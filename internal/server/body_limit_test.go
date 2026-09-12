package server_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/fetch"
	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/model"
	"github.com/amscotti/keyhole/internal/rules"
	"github.com/amscotti/keyhole/internal/server"
	"github.com/amscotti/keyhole/internal/transform"
)

func TestFetchRejectsOversizedJSONBody(t *testing.T) {
	t.Parallel()
	engine, err := rules.NewEngine(nil, "allow")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	fetcher := fetch.New(config.NetworkConfig{
		Timeout: "5s", MaxSize: 1024, AllowPrivate: true,
	}, engine, nil, zap.NewNop())
	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     &config.Config{},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transform.NewRegistry(),
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)

	// Body larger than maxFetchRequestBody (1 MiB).
	huge := bytes.Repeat([]byte("a"), (1<<20)+100)
	// Still needs to look like JSON start so we don't short-circuit elsewhere.
	body := append([]byte(`{"url":"`), huge...)
	body = append(body, []byte(`"}`)...)

	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), model.CodeBadRequest) &&
		!strings.Contains(rec.Body.String(), "too large") {
		t.Fatalf("expected too-large/bad_request body, got %s", rec.Body.String())
	}
}

func TestProtectAPIKeyGatesHandler(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	h, stop := server.Protect(inner, "secret", 0, 0, metrics.NewCollectors(), zap.NewNop())
	t.Cleanup(stop)

	// Missing key.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing key status = %d, want 401", rec.Code)
	}

	// Wrong key.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("X-API-Key", "wrong")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key status = %d, want 401", rec.Code)
	}

	// Correct key.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("X-API-Key", "secret")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("good key status = %d, want 200", rec.Code)
	}
}
