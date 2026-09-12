package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/amscotti/keyhole/internal/model"
)

// fakeClock is an injectable clock for deterministic rate-limiter tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func TestRateLimiterAllowsWithinBurst(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	rl := newRateLimiter(10, 3, clk) // 10 rps, burst 3
	for i := 0; i < 3; i++ {
		ok, _ := rl.allow("1.2.3.4")
		if !ok {
			t.Fatalf("request %d: expected allowed within burst", i+1)
		}
	}
}

func TestRateLimiterBlocksAboveBurst(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	rl := newRateLimiter(10, 2, clk) // 10 rps, burst 2
	rl.allow("1.2.3.4")
	rl.allow("1.2.3.4")
	ok, retry := rl.allow("1.2.3.4")
	if ok {
		t.Fatal("third request should be blocked")
	}
	if retry <= 0 {
		t.Fatalf("retry-after should be positive, got %v", retry)
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	rl := newRateLimiter(2, 2, clk) // 2 rps, burst 2
	rl.allow("ip")                  // tokens: 1
	rl.allow("ip")                  // tokens: 0
	ok, _ := rl.allow("ip")
	if ok {
		t.Fatal("third request should be blocked before refill")
	}
	// Advance 1 second → 2 tokens refill (capped at burst=2).
	clk.Advance(time.Second)
	ok, _ = rl.allow("ip")
	if !ok {
		t.Fatal("request after refill should be allowed")
	}
}

func TestRateLimiterRetryAfterCorrect(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	rl := newRateLimiter(2, 1, clk) // 2 rps → 1 token / 0.5s
	rl.allow("ip")                  // tokens: 0
	_, retry := rl.allow("ip")
	// Need 1 token at 2 rps = 0.5 seconds.
	want := 500 * time.Millisecond
	if retry != want {
		t.Fatalf("retry-after = %v, want %v", retry, want)
	}
}

func TestRateLimiterIsolatesByIP(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	rl := newRateLimiter(1, 1, clk)
	rl.allow("1.1.1.1") // exhaust 1.1.1.1
	ok, _ := rl.allow("1.1.1.1")
	if ok {
		t.Fatal("1.1.1.1 should be blocked after exhausting burst")
	}
	ok, _ = rl.allow("2.2.2.2")
	if !ok {
		t.Fatal("2.2.2.2 should be allowed (separate bucket)")
	}
}

// TestRateLimiterConcurrent exercises the limiter under -race: many goroutines
// hammering allow on the same IP. Correctness (no data race, no negative
// tokens) is the point, not the exact pass/block count.
func TestRateLimiterConcurrent(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(1000, 50, realClock{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = rl.allow("10.0.0.1")
			}
		}()
	}
	wg.Wait()
}

func TestRateLimitMiddlewareAllowsUnderLimit(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	rl := newRateLimiter(10, 5, clk)
	mw := rateLimitMiddleware(rl, nil)
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fetch", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("handler should be called when under the limit")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRateLimitMiddlewareReturns429WithRetryAfter(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	rl := newRateLimiter(1, 1, clk)
	mw := rateLimitMiddleware(rl, nil)
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	// First request exhausts the single-token burst.
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/fetch", nil)
	req1.RemoteAddr = "1.2.3.4:5678"
	h.ServeHTTP(rec1, req1)
	if !called {
		t.Fatal("first request should be allowed")
	}

	// Second request is rate-limited.
	called = false
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/fetch", nil)
	req2.RemoteAddr = "1.2.3.4:9999"
	h.ServeHTTP(rec2, req2)
	if called {
		t.Fatal("handler should NOT be called when rate-limited")
	}
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec2.Code)
	}
	if ra := rec2.Header().Get("Retry-After"); ra == "" {
		t.Fatal("Retry-After header should be set on 429")
	} else if _, err := strconv.Atoi(ra); err != nil {
		t.Fatalf("Retry-After should be an integer (seconds), got %q", ra)
	}
	var body model.ErrorResponse
	if err := json.NewDecoder(rec2.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error.Code != model.CodeRateLimited {
		t.Fatalf("error code = %q, want %q", body.Error.Code, model.CodeRateLimited)
	}
}

func TestRateLimitMiddlewareRecordsLimitedRequest(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	rl := newRateLimiter(1, 1, clk)
	mw := rateLimitMiddleware(rl, nil)
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fetch", nil)
	req.RemoteAddr = "5.5.5.5:1"
	h.ServeHTTP(rec, req) // allowed

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/fetch", nil)
	req2.RemoteAddr = "5.5.5.5:2"
	h.ServeHTTP(rec2, req2) // limited

	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec2.Code)
	}
}

func TestClientIPStripsPort(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"1.2.3.4:5678":  "1.2.3.4",
		"[::1]:1234":    "::1",
		"192.168.1.1:0": "192.168.1.1",
	}
	for input, want := range cases {
		got := clientIP(input)
		if got != want {
			t.Errorf("clientIP(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestRateLimiterStopConcurrentSafe pins the idempotency contract under
// concurrency: the old check-then-close pattern could double-close and panic.
func TestRateLimiterStopConcurrentSafe(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(1, 1, nil)
	rl.Start(time.Minute, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl.Stop()
		}()
	}
	wg.Wait()

	// Stop before Start-equivalent path (no janitor): also must not panic.
	rl2 := newRateLimiter(1, 1, nil)
	rl2.Stop()
	rl2.Stop()
}
