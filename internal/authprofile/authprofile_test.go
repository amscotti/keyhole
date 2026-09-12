package authprofile_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/amscotti/keyhole/internal/authprofile"
	"github.com/amscotti/keyhole/internal/config"
)

func newCaptureLogger() (*zap.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&buf),
		zapcore.DebugLevel,
	))
	return logger, &buf
}

func TestApplySetsHeadersFromProfile(t *testing.T) {
	t.Parallel()
	reg := authprofile.New([]config.AuthProfile{
		{Name: "github", Headers: map[string]string{"Authorization": "token abc", "X-Custom": "val"}},
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api", nil)

	if err := reg.Apply(req, "github", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "token abc" {
		t.Errorf("Authorization = %q, want %q", got, "token abc")
	}
	if got := req.Header.Get("X-Custom"); got != "val" {
		t.Errorf("X-Custom = %q, want %q", got, "val")
	}
}

func TestGetReturnsProfile(t *testing.T) {
	t.Parallel()
	reg := authprofile.New([]config.AuthProfile{
		{Name: "github", Headers: map[string]string{"Authorization": "token abc"}},
	})
	p, ok := reg.Get("github")
	if !ok {
		t.Fatal("expected github profile")
	}
	if p.Headers["Authorization"] != "token abc" {
		t.Fatalf("headers = %v", p.Headers)
	}
	if _, ok := reg.Get("missing"); ok {
		t.Fatal("expected missing profile to be absent")
	}
}

func TestApplyEmptyProfileIsNoop(t *testing.T) {
	t.Parallel()
	reg := authprofile.New(nil)
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

	if err := reg.Apply(req, "", nil); err != nil {
		t.Fatalf("empty profile name should be a no-op, got: %v", err)
	}
	if len(req.Header) != 0 {
		t.Errorf("expected no headers set, got %v", req.Header)
	}
}

func TestApplyUnknownProfileReturnsError(t *testing.T) {
	t.Parallel()
	reg := authprofile.New(nil)
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

	err := reg.Apply(req, "nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should name the missing profile, got: %v", err)
	}
}

func TestApplyDoesNotOverwriteExistingHeader(t *testing.T) {
	t.Parallel()
	reg := authprofile.New([]config.AuthProfile{
		{Name: "p", Headers: map[string]string{"Authorization": "token xyz"}},
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	req.Header.Set("Authorization", "Bearer existing")

	if err := reg.Apply(req, "p", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Auth profile headers are additive; they should not replace headers the
	// caller set explicitly.
	if got := req.Header.Get("Authorization"); got != "Bearer existing" {
		t.Errorf("Authorization = %q, want %q (caller header preserved)", got, "Bearer existing")
	}
}

func TestStripRemovesProfileHeadersOnly(t *testing.T) {
	t.Parallel()
	reg := authprofile.New([]config.AuthProfile{
		{Name: "a", Headers: map[string]string{"Authorization": "token a", "X-Api-Key": "ka"}},
		{Name: "b", Headers: map[string]string{"X-Api-Key": "kb", "Cookie": "session=b"}},
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	req.Header.Set("Authorization", "Bearer inherited")
	req.Header.Set("X-Api-Key", "inherited")
	req.Header.Set("Cookie", "inherited=1")
	req.Header.Set("Accept", "text/html")

	reg.Strip(req)

	for _, h := range []string{"Authorization", "X-Api-Key", "Cookie"} {
		if got := req.Header.Get(h); got != "" {
			t.Errorf("%s = %q after Strip, want empty", h, got)
		}
	}
	if got := req.Header.Get("Accept"); got != "text/html" {
		t.Errorf("Accept = %q, want untouched non-profile header", got)
	}

	// A nil registry or request must not panic.
	var nilReg *authprofile.Registry
	nilReg.Strip(req)
}

func TestSanitizeURLDropsCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"https://user:pass@example.com/path?token=secret#frag", "https://example.com/path"},
		{"https://example.com/a/b", "https://example.com/a/b"},
		{"not a url", ""},
		{"", ""},
	}
	for _, tc := range tests {
		if got := authprofile.SanitizeURL(tc.in); got != tc.want {
			t.Errorf("SanitizeURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestApplyLogsProfileNameButNotHeaderValue is the security-critical test: the
// "auth profile applied" log line must mention the profile name and URL but
// must never contain the header value. A secret in a header must not leak into
// the log.
func TestApplyLogsProfileNameButNotHeaderValue(t *testing.T) {
	t.Parallel()
	logger, buf := newCaptureLogger()
	reg := authprofile.New([]config.AuthProfile{
		{Name: "github", Headers: map[string]string{"Authorization": "super-secret-token-abc123"}},
	})
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api", nil)

	if err := reg.Apply(req, "github", logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "github") {
		t.Errorf("log should mention profile name 'github':\n%s", out)
	}
	if !strings.Contains(out, "https://example.com/api") {
		t.Errorf("log should mention the URL:\n%s", out)
	}
	if strings.Contains(out, "super-secret-token-abc123") {
		t.Errorf("header value leaked into log:\n%s", out)
	}
}

// TestApplyLogsSanitizedURL pins that credentials carried in the URL itself —
// userinfo or query parameters — never reach the log line.
func TestApplyLogsSanitizedURL(t *testing.T) {
	t.Parallel()
	logger, buf := newCaptureLogger()
	reg := authprofile.New([]config.AuthProfile{
		{Name: "github", Headers: map[string]string{"Authorization": "token x"}},
	})
	req := httptest.NewRequest(http.MethodGet, "https://alice:hunter2@example.com/api?token=query-secret", nil)

	if err := reg.Apply(req, "github", logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "hunter2") || strings.Contains(out, "query-secret") {
		t.Errorf("URL credentials leaked into log:\n%s", out)
	}
	if !strings.Contains(out, "https://example.com/api") {
		t.Errorf("log should carry the sanitized URL:\n%s", out)
	}
}
