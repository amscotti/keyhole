package mcpserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// limitBody must let normal requests through untouched.
func TestLimitBodyPassesSmallBody(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("downstream read: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if string(body) != "hello" {
			t.Errorf("got %q, want %q", body, "hello")
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, MCPHTTPEndpoint, strings.NewReader("hello"))
	rec := httptest.NewRecorder()
	limitBody(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
}

// limitBody must fail fast on bodies over maxMCPRequestBody instead of letting
// the MCP transport buffer them unbounded.
func TestLimitBodyRejectsOversizedBody(t *testing.T) {
	t.Parallel()
	var readErr error
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	})
	big := strings.Repeat("x", maxMCPRequestBody+1024)
	req := httptest.NewRequest(http.MethodPost, MCPHTTPEndpoint, strings.NewReader(big))
	rec := httptest.NewRecorder()
	limitBody(next).ServeHTTP(rec, req)
	if readErr == nil {
		t.Fatal("expected downstream read to fail on oversized body")
	}
}
