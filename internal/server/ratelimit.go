package server

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/model"
)

// rlClock abstracts time so the rate limiter's refill is deterministic in tests.
type rlClock interface {
	Now() time.Time
}

// realClock is the production rlClock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// ipBucket is a per-client-IP token bucket. Tokens refill at rps up to burst.
type ipBucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is a concurrency-safe, per-client-IP token-bucket rate limiter.
// It is dependency-free (stdlib only) so the security-sensitive rate limit
// surface has no third-party code in the critical path.
type rateLimiter struct {
	rps   float64
	burst int
	clock rlClock

	mu      sync.Mutex
	buckets map[string]*ipBucket

	stop     chan struct{}
	stopOnce sync.Once
}

// newRateLimiter builds a per-IP token-bucket limiter refilling at rps
// requests/second with a burst cap. Start must be called to run the janitor;
// Stop releases it.
func newRateLimiter(rps float64, burst int, clock rlClock) *rateLimiter {
	if clock == nil {
		clock = realClock{}
	}
	return &rateLimiter{
		rps:     rps,
		burst:   burst,
		clock:   clock,
		buckets: make(map[string]*ipBucket),
		stop:    make(chan struct{}),
	}
}

// allow consumes one token for ip. It returns (true, 0) when the request is
// admitted and (false, retryAfter) when it is rate-limited, where retryAfter is
// the time until the next token becomes available.
func (rl *rateLimiter) allow(ip string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.clock.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		b = &ipBucket{tokens: float64(rl.burst), last: now}
		rl.buckets[ip] = b
	}

	// Refill: add tokens accrued since the last access, capped at burst.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.rps
		if b.tokens > float64(rl.burst) {
			b.tokens = float64(rl.burst)
		}
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	// Not enough tokens: compute how long until one accrues.
	needed := 1 - b.tokens
	retry := time.Duration(needed / rl.rps * float64(time.Second))
	if retry <= 0 {
		retry = time.Millisecond
	}
	return false, retry
}

// sweep removes idle buckets whose last access is older than idleTTL, bounding
// memory growth from a rotating set of client IPs.
func (rl *rateLimiter) sweep(idleTTL time.Duration) {
	cutoff := rl.clock.Now().Add(-idleTTL)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, b := range rl.buckets {
		if b.last.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
}

// Start launches a background goroutine that periodically removes idle buckets
// so a flood of unique IPs cannot grow memory unbounded. Stop cancels it.
func (rl *rateLimiter) Start(interval, idleTTL time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-rl.stop:
				return
			case <-ticker.C:
				rl.sweep(idleTTL)
			}
		}
	}()
}

// Stop signals the janitor goroutine to exit. Safe to call multiple times and
// from concurrent goroutines: the previous check-then-close pattern could let
// two callers both observe an open channel and double-close it (a panic).
func (rl *rateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.stop) })
}

// clientIP extracts the client IP from RemoteAddr (host:port), handling IPv6
// bracket notation. It does not trust forwarding headers — Keyhole is
// intentionally a single-hop service, and trusting X-Forwarded-For would let a
// client spoof its IP to evade the limit.
func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // already a bare host or unparseable
	}
	return host
}

// rateLimitMiddleware enforces a per-client-IP rate limit. When the limit is
// exceeded it returns 429 with a Retry-After header (seconds, rounded up) and a
// JSON error envelope. collectors, when non-nil, records the limited request so
// it shows up in the requests_total counter.
func rateLimitMiddleware(rl *rateLimiter, collectors *metrics.Collectors) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r.RemoteAddr)
			ok, retry := rl.allow(ip)
			if ok {
				next.ServeHTTP(w, r)
				return
			}
			// Round up to the next whole second so the client waits long enough.
			secs := int(retry.Seconds())
			if retry > time.Duration(secs)*time.Second {
				secs++
			}
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeEnvelopeError(w, model.CodeRateLimited, "rate limit exceeded")
			if collectors != nil {
				collectors.RecordRequest("unknown", http.StatusTooManyRequests)
			}
		})
	}
}
