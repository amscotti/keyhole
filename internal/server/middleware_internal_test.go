package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestStatusCapturePreservesFlusher pins that the access-log wrapper exposes
// http.Flusher (and Unwrap): MCP Streamable HTTP detects streaming by asserting
// the interface, and without it GET /mcp degrades to 405 and SSE is lost.
func TestStatusCapturePreservesFlusher(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder() // implements http.Flusher
	sc := &statusCapture{ResponseWriter: rec, status: http.StatusOK}

	var httpWriter http.ResponseWriter = sc
	if _, ok := httpWriter.(http.Flusher); !ok {
		t.Fatal("statusCapture must implement http.Flusher")
	}
	sc.WriteHeader(http.StatusOK)
	sc.Flush()
	if !rec.Flushed {
		t.Fatal("Flush must delegate to the wrapped writer")
	}
	if sc.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("Unwrap must return the wrapped writer")
	}
}

func TestRecoveryMiddlewareCatchesPanic(t *testing.T) {
	t.Parallel()
	logger := zap.NewNop()

	panicHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	})
	recovered := chain(panicHandler, recoveryMiddleware(logger))

	rec := httptest.NewRecorder()
	recovered.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestRecoveryLogsRequestIDAndStack(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(stringWriter{&buf}),
		zapcore.DebugLevel,
	)
	logger := zap.New(core)

	panicHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("kaboom")
	})
	recovered := chain(
		panicHandler,
		requestIDMiddleware,
		recoveryMiddleware(logger),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "rid-recovery-test")
	recovered.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	logOut := buf.String()
	if !strings.Contains(logOut, "rid-recovery-test") {
		t.Errorf("expected request_id in log output:\n%s", logOut)
	}
	if !strings.Contains(logOut, "panic recovered") {
		t.Errorf("expected 'panic recovered' in log:\n%s", logOut)
	}
}

func TestRequestIDMiddlewareGeneratesID(t *testing.T) {
	t.Parallel()
	var capturedID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = requestIDFromContext(r.Context())
	})
	wrapped := requestIDMiddleware(handler)

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if capturedID == "" {
		t.Error("expected a generated request ID")
	}
	if got := rec.Header().Get("X-Request-Id"); got != capturedID {
		t.Errorf("response X-Request-Id = %q, want %q", got, capturedID)
	}
}

func TestRequestIDMiddlewareReusesClientID(t *testing.T) {
	t.Parallel()
	var capturedID string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedID = requestIDFromContext(r.Context())
	})
	wrapped := requestIDMiddleware(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "client-provided-id")
	wrapped.ServeHTTP(rec, req)

	if capturedID != "client-provided-id" {
		t.Errorf("captured ID = %q, want client-provided-id", capturedID)
	}
	if got := rec.Header().Get("X-Request-Id"); got != "client-provided-id" {
		t.Errorf("response X-Request-Id = %q", got)
	}
}

// stringWriter adapts a *strings.Builder to the io.Writer interface for zap.
type stringWriter struct{ b *strings.Builder }

func (sw stringWriter) Write(p []byte) (int, error) { return sw.b.Write(p) }

// TestProtectPanicProducesAccessLogAnd500 pins the middleware order: logging
// wraps recovery, so a handler panic must still yield an access-log line with
// status 500 (previously the panic bypassed the logger entirely and 5xx-rate
// alerting was blind to panics).
func TestProtectPanicProducesAccessLogAnd500(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(stringWriter{&buf}),
		zapcore.DebugLevel,
	)
	logger := zap.New(core)

	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	})
	h, stop := Protect(handler, "", 0, 0, nil, logger)
	defer stop()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/fetch", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	out := buf.String()
	if !strings.Contains(out, `"msg":"request"`) {
		t.Fatalf("no access-log line emitted for panicked request:\n%s", out)
	}
	if !strings.Contains(out, `"status":500`) {
		t.Fatalf("access-log line missing status 500:\n%s", out)
	}
	if !strings.Contains(out, "panic recovered") {
		t.Fatalf("expected 'panic recovered' in log:\n%s", out)
	}
}

// TestProtectWrongKeyDoesNotBurnRateLimitTokens pins apiKey-before-rateLimit:
// unauthenticated requests must not consume the shared per-IP bucket, so a
// wrong-key flood cannot starve legitimate clients (previously every 401 cost
// a token).
func TestProtectWrongKeyDoesNotBurnRateLimitTokens(t *testing.T) {
	t.Parallel()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(zap.NewNop(), w, http.StatusOK, map[string]string{"ok": "true"})
	})
	// rps=1, burst=2: two authenticated requests exhaust the bucket.
	h, stop := Protect(handler, "secret", 1, 2, nil, zap.NewNop())
	defer stop()

	do := func(key string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/fetch", nil)
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		req.RemoteAddr = "10.0.0.1:1234"
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Flood with wrong keys — must all be 401 and consume nothing.
	for i := 0; i < 10; i++ {
		if code := do("wrong"); code != http.StatusUnauthorized {
			t.Fatalf("wrong key status = %d, want 401", code)
		}
	}
	// The authenticated bucket is untouched: both burst tokens remain.
	if code := do("secret"); code != http.StatusOK {
		t.Fatalf("first good request status = %d, want 200 (tokens burned by 401s)", code)
	}
	if code := do("secret"); code != http.StatusOK {
		t.Fatalf("second good request status = %d, want 200 (tokens burned by 401s)", code)
	}
	// Third exceeds burst → 429.
	if code := do("secret"); code != http.StatusTooManyRequests {
		t.Fatalf("third request status = %d, want 429", code)
	}
}
