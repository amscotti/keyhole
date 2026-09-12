package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/model"
)

// ctxKey is an unexported type so context keys from this package cannot collide
// with keys from other packages.
type ctxKey int

const requestIDKey ctxKey = iota

// requestIDFromContext returns the request ID stored in ctx, or "" if absent.
func requestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// requestIDMiddleware ensures every request has an X-Request-Id. If the client
// provides one it is reused; otherwise a fresh random ID is generated. The ID
// is stored in the request context and echoed in the response header so a
// client can correlate a response with log lines.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// newRequestID generates a short random hex ID. If the system source fails,
// fall back to a time-derived ID rather than returning all zeros (which would
// make every such request collide and defeat log correlation).
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// recoveryMiddleware catches panics in downstream handlers, logs the stack
// trace, and returns a 500 so a single bad request never crashes the goroutine
// or leaves the connection hanging.
func recoveryMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The context is passed explicitly (rather than read back via
			// r.Context() at panic time) per the contextcheck gate: request
			// contexts must flow as parameters, never via capture.
			defer func(ctx context.Context) {
				if rec := recover(); rec != nil {
					logger.Error("panic recovered",
						zap.Any("panic", rec),
						zap.String("request_id", requestIDFromContext(ctx)),
						zap.String("stack", string(debug.Stack())),
					)
					writeEnvelopeError(w, model.CodeInternal, "internal server error")
				}
			}(r.Context())
			next.ServeHTTP(w, r)
		})
	}
}

// apiKeyMiddleware gates requests on an X-API-Key header. When key is empty the
// middleware is a pass-through (no auth required). When set, requests without a
// matching key receive 401 and are recorded in the requests_total counter so
// they are not undercounted. Comparison is constant-time to avoid a timing
// oracle on the shared secret.
func apiKeyMiddleware(key string, collectors *metrics.Collectors) func(http.Handler) http.Handler {
	if key == "" {
		return identityMiddleware
	}
	// Hash both sides before the constant-time compare: ConstantTimeCompare
	// returns immediately on a length mismatch, which would leak the key
	// length through timing. Fixed-size digests always compare in full.
	want := sha256.Sum256([]byte(key))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := sha256.Sum256([]byte(r.Header.Get("X-API-Key")))
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				writeEnvelopeError(w, model.CodeUnauthorized, "missing or invalid API key")
				if collectors != nil {
					collectors.RecordRequest("unknown", http.StatusUnauthorized)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Protect wraps h with the same ingress controls used by REST /fetch: optional
// API-key gate and optional per-IP rate limit. The returned stop function tears
// down the rate-limiter janitor (a no-op when rate limiting is disabled).
// Callers should defer stop() for process-lifetime servers and t.Cleanup(stop)
// in tests.
//
// Middleware order (first = outermost):
//
//		requestID → logging → recovery → apiKey → rateLimit → handler
//
//	  - requestID outermost so every subsequent log line (including the panic
//	    log) carries the correlation ID;
//	  - logging outside recovery so a recovered panic still produces an access
//	    log line with status 500 (recovery writes through the status capture);
//	  - apiKey before rateLimit so unauthenticated requests cannot burn the
//	    shared per-IP token bucket (wrong-key floods must not starve legit
//	    clients behind the same NAT).
func Protect(h http.Handler, apiKey string, rateRPS float64, rateBurst int, collectors *metrics.Collectors, logger *zap.Logger) (http.Handler, func()) {
	if logger == nil {
		logger = zap.NewNop()
	}
	mws := []func(http.Handler) http.Handler{
		requestIDMiddleware,
		loggingMiddleware(logger),
		recoveryMiddleware(logger),
		apiKeyMiddleware(apiKey, collectors),
	}
	stop := func() {}
	if rateRPS > 0 {
		rl := newRateLimiter(rateRPS, rateBurst, nil)
		rl.Start(time.Minute, 10*time.Minute)
		stop = rl.Stop
		mws = append(mws, rateLimitMiddleware(rl, collectors))
	}
	return chain(h, mws...), stop
}

// identityMiddleware is a no-op middleware used when API key auth is disabled.
func identityMiddleware(next http.Handler) http.Handler { return next }

// statusCapture wraps http.ResponseWriter to capture the response status code
// for access logging. WriteHeader is called at most once; subsequent calls are
// ignored (the underlying writer already sent the header).
type statusCapture struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (sc *statusCapture) WriteHeader(code int) {
	if sc.wroteHeader {
		return
	}
	sc.status = code
	sc.wroteHeader = true
	sc.ResponseWriter.WriteHeader(code)
}

func (sc *statusCapture) Write(b []byte) (int, error) {
	if !sc.wroteHeader {
		sc.status = http.StatusOK
		sc.wroteHeader = true
	}
	return sc.ResponseWriter.Write(b)
}

// Flush implements http.Flusher by delegating to the wrapped writer. Without
// it, wrapping a handler in the access-log middleware would strip the Flusher
// interface, and MCP Streamable HTTP (which asserts w.(http.Flusher) to decide
// whether it can stream) would silently degrade to non-streaming — rejecting
// GET /mcp with 405 instead of opening the SSE channel.
func (sc *statusCapture) Flush() {
	if f, ok := sc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped writer to http.ResponseController (SetWriteDeadline
// et al.) and any other code that unwraps response writers.
func (sc *statusCapture) Unwrap() http.ResponseWriter { return sc.ResponseWriter }

// loggingMiddleware records an access log line for every request, including the
// request ID, method, path, response status, and duration. Sensitive headers
// are never logged — the logging package's redaction helpers handle that.
func loggingMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sc := &statusCapture{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sc, r)
			logger.Info("request",
				zap.String("request_id", requestIDFromContext(r.Context())),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", sc.status),
				zap.Duration("duration", time.Since(start)),
				zap.String("remote", r.RemoteAddr),
			)
		})
	}
}

// chain wraps handler with the given middlewares, applying them in order so the
// first entry is the outermost (runs first on the way in, last on the way out).
func chain(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
