package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/server"
)

func newTestMux(t *testing.T, ready func() bool) *http.ServeMux {
	t.Helper()
	mux, stop := server.New(server.Options{
		Logger:         zap.NewNop(),
		MetricsEnabled: true,
		MetricsPath:    "/metrics",
		Ready:          ready,
		Registry:       prometheus.NewRegistry(),
	})
	t.Cleanup(stop)
	return mux
}

func decode(t *testing.T, body io.Reader) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return m
}

func TestHealthzReturns200JSON(t *testing.T) {
	t.Parallel()
	mux := newTestMux(t, func() bool { return true })

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if got := decode(t, rec.Body)["status"]; got != "ok" {
		t.Errorf("body status = %q, want ok", got)
	}
}

func TestReadyzReturns200WhenReady(t *testing.T) {
	t.Parallel()
	mux := newTestMux(t, func() bool { return true })

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := decode(t, rec.Body)["status"]; got != "ready" {
		t.Errorf("body status = %q, want ready", got)
	}
}

func TestReadyzReturns503WhenNotReady(t *testing.T) {
	t.Parallel()
	mux := newTestMux(t, func() bool { return false })

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestMetricsServed(t *testing.T) {
	t.Parallel()
	mux := newTestMux(t, func() bool { return true })

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHealthzNotFoundWhenNotRegistered(t *testing.T) {
	t.Parallel()
	// A path that was never registered must 404, proving the mux is selective.
	mux := newTestMux(t, func() bool { return true })
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
