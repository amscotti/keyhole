package e2e_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestE2E_HealthAndReady(t *testing.T) {
	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	cfg := restConfig(listen, "", "")
	path := writeConfig(t, cfg)
	srv := startREST(t, path, listen)

	status, body := getJSON(t, srv.BaseURL+"/healthz", "")
	if status != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", status)
	}
	if body["status"] != "ok" {
		t.Fatalf("healthz body = %v", body)
	}

	status, body = getJSON(t, srv.BaseURL+"/readyz", "")
	if status != http.StatusOK {
		t.Fatalf("readyz status = %d, want 200", status)
	}
	if body["status"] != "ready" {
		t.Fatalf("readyz body = %v", body)
	}

	// Metrics endpoint is enabled in restConfig (Prometheus text, not JSON).
	resp, err := http.Get(srv.BaseURL + "/metrics")
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d", resp.StatusCode)
	}
}

func TestE2E_FetchRawAndMarkdown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><body><h1>E2E Title</h1><p>Hello e2e</p></body></html>")
	}))
	t.Cleanup(upstream.Close)

	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	host := hostPort(upstream.URL)
	cfg := restConfig(listen, "", host)
	path := writeConfig(t, cfg)
	srv := startREST(t, path, listen)

	// raw
	status, env := postFetchJSON(t, srv.BaseURL, "", map[string]any{
		"url":       upstream.URL + "/page",
		"transform": "raw",
	})
	if status != http.StatusOK {
		t.Fatalf("raw status = %d body=%v logs=%s", status, env, srv.logBuf.String())
	}
	if env["ok"] != true {
		t.Fatalf("raw ok = %v", env["ok"])
	}
	content, _ := env["content"].(string)
	if !strings.Contains(content, "E2E Title") {
		t.Fatalf("raw content missing title: %q", content)
	}

	// markdown
	status, env = postFetchJSON(t, srv.BaseURL, "", map[string]any{
		"url":       upstream.URL + "/page",
		"transform": "markdown",
	})
	if status != http.StatusOK {
		t.Fatalf("markdown status = %d body=%v", status, env)
	}
	content, _ = env["content"].(string)
	if !strings.Contains(content, "E2E Title") && !strings.Contains(content, "Hello e2e") {
		t.Fatalf("markdown content unexpected: %q", content)
	}
	if env["transform"] != "markdown" {
		t.Fatalf("transform = %v, want markdown", env["transform"])
	}
}

func TestE2E_PolicyDeny(t *testing.T) {
	// Upstream exists but is not in the allowlist.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secret")
	}))
	t.Cleanup(upstream.Close)

	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	// No rules — default deny.
	cfg := restConfig(listen, "", "")
	path := writeConfig(t, cfg)
	srv := startREST(t, path, listen)

	status, env := postFetchJSON(t, srv.BaseURL, "", map[string]any{
		"url":       upstream.URL + "/secret",
		"transform": "raw",
	})
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", status, env)
	}
	errObj, _ := env["error"].(map[string]any)
	if errObj == nil || errObj["code"] != "denied" {
		t.Fatalf("expected denied error, got %v", env)
	}
}

func TestE2E_APIKeyRequired(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	t.Cleanup(upstream.Close)

	const apiKey = "e2e-secret-key"
	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	host := hostPort(upstream.URL)
	cfg := restConfig(listen, apiKey, host)
	path := writeConfig(t, cfg)
	srv := startREST(t, path, listen)

	// Missing key → 401
	status, env := postFetchJSON(t, srv.BaseURL, "", map[string]any{
		"url":       upstream.URL + "/",
		"transform": "raw",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("missing key status = %d, want 401; body=%v", status, env)
	}

	// Wrong key → 401
	status, env = postFetchJSON(t, srv.BaseURL, "wrong", map[string]any{
		"url":       upstream.URL + "/",
		"transform": "raw",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong key status = %d, want 401; body=%v", status, env)
	}

	// Correct key → 200
	status, env = postFetchJSON(t, srv.BaseURL, apiKey, map[string]any{
		"url":       upstream.URL + "/",
		"transform": "raw",
	})
	if status != http.StatusOK {
		t.Fatalf("good key status = %d, want 200; body=%v logs=%s", status, env, srv.logBuf.String())
	}
	if env["ok"] != true {
		t.Fatalf("envelope not ok: %v", env)
	}
}

func TestE2E_RedirectDeniedHopNeverContacted(t *testing.T) {
	// Upstream: /start → 302 /secret (denied by a more-specific deny rule).
	var secretHits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/secret", http.StatusFound)
		case "/secret":
			secretHits++
			_, _ = io.WriteString(w, "should-not-reach")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	host := hostPort(upstream.URL)

	// Custom config: allow /start, deny /secret, default deny.
	cfg := `default_policy = "deny"
[server]
listen = "` + listen + `"
[logging]
level = "error"
format = "json"
output = "stdout"
[metrics]
enabled = false
[network]
timeout = "5s"
max_size = 1048576
allow_private = true
[cache]
enabled = false
[mcp]
enabled = false
[output]
max_chars = 10000
[youtube]
transcript_language = "en"
[office]
pandoc_path = "pandoc"
timeout = "10s"

[[rules]]
match = "http://` + host + `/start"
allow = true
transforms = ["raw"]

[[rules]]
match = "http://` + host + `/secret"
allow = false
`
	path := writeConfig(t, cfg)
	srv := startREST(t, path, listen)

	status, env := postFetchJSON(t, srv.BaseURL, "", map[string]any{
		"url":       upstream.URL + "/start",
		"transform": "raw",
	})
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v logs=%s", status, env, srv.logBuf.String())
	}
	if secretHits != 0 {
		t.Fatalf("denied hop contacted %d times", secretHits)
	}
}

// TestE2E_FetchTruncation pins max_chars to an exact rune count. A looser
// "content is at most 2x the limit" assertion would let a byte-vs-rune
// truncation bug through: the source mixes ASCII and multi-byte runes, so a
// byte-offset cut that is not exactly the requested rune count is caught by
// the prefix comparison.
func TestE2E_FetchTruncation(t *testing.T) {
	source := strings.Repeat("aé漢", 5000) // 15000 runes, 25000 bytes
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, source)
	}))
	t.Cleanup(upstream.Close)

	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	cfg := restConfig(listen, "", hostPort(upstream.URL))
	path := writeConfig(t, cfg)
	srv := startREST(t, path, listen)

	const maxChars = 1234
	status, env := postFetchJSON(t, srv.BaseURL, "", map[string]any{
		"url":       upstream.URL + "/long",
		"transform": "raw",
		"max_chars": maxChars,
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%v logs=%s", status, env, srv.logBuf.String())
	}
	content, _ := env["content"].(string)
	if got := utf8.RuneCountInString(content); got != maxChars {
		t.Fatalf("content runes = %d, want exactly %d", got, maxChars)
	}
	if env["truncated"] != true {
		t.Fatalf("truncated = %v, want true", env["truncated"])
	}
	// The result is the source's first maxChars runes — never a mid-codepoint
	// cut and never a different (e.g. 2x) limit.
	want := string([]rune(source)[:maxChars])
	if content != want {
		t.Fatalf("content does not equal the first %d runes of the source", maxChars)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
