package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/amscotti/keyhole/internal/authprofile"
	"github.com/amscotti/keyhole/internal/cache"
	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/fetch"
	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/model"
	"github.com/amscotti/keyhole/internal/rules"
	"github.com/amscotti/keyhole/internal/server"
	"github.com/amscotti/keyhole/internal/transform"
)

// --- test helpers ---------------------------------------------------------

// fetchTestEnv bundles the dependencies needed to test the /fetch endpoint. The
// httptest.Server is the upstream that /fetch will retrieve from.
type fetchTestEnv struct {
	mux       *http.ServeMux
	upstream  *httptest.Server
	collectrs *metrics.Collectors
	registry  *prometheus.Registry
	cache     *cache.Cache
}

func newFetchTestEnv(t *testing.T, upstreamHandler http.HandlerFunc, cfg config.Config) *fetchTestEnv {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	base := strings.TrimPrefix(upstream.URL, "http://")

	// Build an engine that allows the upstream host.
	allowRule := config.Rule{
		Match:      "http://" + base + "/**",
		Allow:      boolPtr(true),
		Transforms: []string{"raw", "markdown", "article"},
	}
	engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}

	netCfg := config.NetworkConfig{
		Timeout:      "5s",
		MaxSize:      1024 * 1024,
		MaxRedirects: 10,
		UserAgent:    "keyhole-test",
		AllowPrivate: true,
	}
	fetcher := fetch.New(netCfg, engine, nil, zap.NewNop())

	transforms := transform.NewRegistry()

	reg := prometheus.NewRegistry()
	collectors := metrics.NewCollectors()
	collectors.MustRegister(reg)

	ttl, _ := time.ParseDuration("10m")
	c := cache.New(cache.Options{Enabled: true, TTL: ttl, MaxEntries: 100})

	mux, stop := server.New(server.Options{
		Logger:         zap.NewNop(),
		MetricsEnabled: true,
		MetricsPath:    "/metrics",
		Ready:          func() bool { return true },
		Registry:       reg,
		Config:         &cfg,
		Fetcher:        fetcher,
		Engine:         engine,
		Transforms:     transforms,
		Cache:          c,
		Collectors:     collectors,
	})
	t.Cleanup(stop)

	return &fetchTestEnv{
		mux:       mux,
		upstream:  upstream,
		collectrs: collectors,
		registry:  reg,
		cache:     c,
	}
}

func boolPtr(b bool) *bool { return &b }

func doFetch(mux *http.ServeMux, method, path string, body any) (*httptest.ResponseRecorder, model.Envelope, model.ErrorResponse) {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var env model.Envelope
	var errResp model.ErrorResponse
	if rec.Body.Len() > 0 {
		// Try to decode as success envelope first; if ok is false it's an error.
		raw := rec.Body.Bytes()
		_ = json.Unmarshal(raw, &env)
		_ = json.Unmarshal(raw, &errResp)
	}
	return rec, env, errResp
}

// --- basic fetch tests ----------------------------------------------------

func TestFetchPostReturnsMarkdownEnvelope(t *testing.T) {
	t.Parallel()
	htmlBody := `<html><body><h1>Hello</h1><p>World</p></body></html>`
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, htmlBody)
	}, config.Config{Output: config.OutputConfig{MaxChars: 100000}})

	rec, envResp, errResp := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       env.upstream.URL,
		"transform": "markdown",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !errResp.OK && errResp.Error.Code != "" {
		t.Fatalf("unexpected error: %+v", errResp)
	}
	if !envResp.OK {
		t.Fatal("expected ok:true")
	}
	if envResp.Transform != "markdown" {
		t.Errorf("transform = %q, want markdown", envResp.Transform)
	}
	if !strings.Contains(envResp.Content, "Hello") {
		t.Errorf("content missing expected text: %q", envResp.Content)
	}
	if envResp.ContentType != "text/markdown; charset=utf-8" {
		t.Errorf("content_type = %q", envResp.ContentType)
	}
}

func TestFetchPostReturnsRawEnvelope(t *testing.T) {
	t.Parallel()
	htmlBody := `<html><body>Raw content</body></html>`
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, htmlBody)
	}, config.Config{})

	rec, envResp, _ := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       env.upstream.URL,
		"transform": "raw",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if envResp.Content != htmlBody {
		t.Errorf("raw content = %q, want %q", envResp.Content, htmlBody)
	}
}

func TestFetchGetVariant(t *testing.T) {
	t.Parallel()
	htmlBody := `<html><body><h1>Get Test</h1></body></html>`
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, htmlBody)
	}, config.Config{})

	rec, envResp, _ := doFetch(env.mux, http.MethodGet,
		"/fetch?url="+env.upstream.URL+"&transform=raw", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !envResp.OK {
		t.Fatal("expected ok:true")
	}
	if !strings.Contains(envResp.Content, "Get Test") {
		t.Errorf("content = %q", envResp.Content)
	}
}

// --- error cases ----------------------------------------------------------

func TestFetchDeniedURLReturns403(t *testing.T) {
	t.Parallel()
	// Upstream server exists but the engine won't allow the URL because it's
	// not in the allowlist — we create a custom env with a deny-everything
	// engine by hitting a URL that doesn't match the allow rule.
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, config.Config{})

	rec, _, errResp := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://denied.example.com/secret",
		"transform": "raw",
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if errResp.Error.Code != model.CodeDenied {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeDenied)
	}
}

func TestFetchUnknownTransformReturns400(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, config.Config{})

	rec, _, errResp := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       env.upstream.URL,
		"transform": "nonexistent",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if errResp.Error.Code != model.CodeUnsupported {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeUnsupported)
	}
}

func TestFetchUnknownAuthProfileReturns400(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer upstream.Close()

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowRule := config.Rule{Match: "http://" + base + "/**", Allow: boolPtr(true)}
	engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}

	// A registry with a known profile — but the request will name an unknown one.
	profiles := authprofile.New([]config.AuthProfile{
		{Name: "known", Headers: map[string]string{"X-Test": "val"}},
	})

	fetcher := fetch.New(netCfg, engine, profiles, zap.NewNop())

	// Client-selected profiles require allow_client_auth_profile = true.
	cfg := &config.Config{}
	cfg.Server.AllowClientAuthProfile = true

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     cfg,
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transform.NewRegistry(),
		Profiles:   profiles,
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)

	// Request with an unknown auth_profile → should be bad_request (400),
	// not denied (403).
	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":          upstream.URL,
		"transform":    "raw",
		"auth_profile": "does-not-exist",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (bad_request)", rec.Code)
	}
	if errResp.Error.Code != model.CodeBadRequest {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeBadRequest)
	}
}

func TestFetchClientAuthProfileRefusedByDefault(t *testing.T) {
	t.Parallel()
	var sawAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("X-Test")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer upstream.Close()

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowRule := config.Rule{Match: "http://" + base + "/**", Allow: boolPtr(true)}
	engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	profiles := authprofile.New([]config.AuthProfile{
		{Name: "known", Headers: map[string]string{"X-Test": "secret"}},
	})
	fetcher := fetch.New(netCfg, engine, profiles, zap.NewNop())

	// Default: allow_client_auth_profile = false — a client-selected profile
	// is refused with a clear 400, not silently dropped, so a caller never
	// mistakes an anonymous fetch for an authenticated one.
	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     &config.Config{},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transform.NewRegistry(),
		Profiles:   profiles,
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)

	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":          upstream.URL,
		"transform":    "raw",
		"auth_profile": "known",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if errResp.Error.Code != model.CodeBadRequest {
		t.Fatalf("error code = %q, want %q", errResp.Error.Code, model.CodeBadRequest)
	}
	if sawAuth != "" {
		t.Fatalf("client auth_profile was applied (X-Test=%q); default must refuse it", sawAuth)
	}
}

// TestFetchRuleAuthProfileWinsOverClientSelection pins precedence: even with
// [server] allow_client_auth_profile = true, a rule-attached profile is the
// identity the upstream sees. Client selection may fill in an identity only
// when the matched rule attaches none — it must never swap the rule's
// credentials for a caller-chosen one (a wrong-identity response would look
// exactly like a right-identity one).
func TestFetchRuleAuthProfileWinsOverClientSelection(t *testing.T) {
	t.Parallel()

	var sawAuth atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.Store(r.Header.Get("X-Test"))
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	t.Cleanup(upstream.Close)

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowRule := config.Rule{
		Match:       "http://" + base + "/**",
		Allow:       boolPtr(true),
		AuthProfile: "rule-prof",
	}
	engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	profiles := authprofile.New([]config.AuthProfile{
		{Name: "rule-prof", Headers: map[string]string{"X-Test": "rule-secret"}},
		{Name: "client-prof", Headers: map[string]string{"X-Test": "client-secret"}},
	})
	fetcher := fetch.New(netCfg, engine, profiles, zap.NewNop())

	cfg := &config.Config{}
	cfg.Server.AllowClientAuthProfile = true

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     cfg,
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transform.NewRegistry(),
		Profiles:   profiles,
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)

	// The caller names the rule's own profile; the request must proceed as the
	// rule identity, never as a client-chosen one.
	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":          upstream.URL,
		"transform":    "raw",
		"auth_profile": "rule-prof",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if errResp.Error.Code != "" {
		t.Fatalf("unexpected error: %+v", errResp)
	}
	if got := sawAuth.Load(); got != "rule-secret" {
		t.Fatalf("upstream X-Test = %v, want the rule profile's header (rule-secret)", got)
	}
}

// TestFetchClientAuthProfileMismatchRejected pins the fail-closed identity
// rule: a caller asking for a profile the matched rule does not attach gets
// bad_request instead of a response fetched under the rule's identity. A
// silently-dropped request would look like success while using credentials the
// caller never chose.
func TestFetchClientAuthProfileMismatchRejected(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	t.Cleanup(upstream.Close)

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowRule := config.Rule{
		Match:       "http://" + base + "/**",
		Allow:       boolPtr(true),
		AuthProfile: "rule-prof",
	}
	engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	profiles := authprofile.New([]config.AuthProfile{
		{Name: "rule-prof", Headers: map[string]string{"X-Test": "rule-secret"}},
		{Name: "client-prof", Headers: map[string]string{"X-Test": "client-secret"}},
	})
	fetcher := fetch.New(netCfg, engine, profiles, zap.NewNop())

	cfg := &config.Config{}
	cfg.Server.AllowClientAuthProfile = true

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     cfg,
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transform.NewRegistry(),
		Profiles:   profiles,
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)

	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":          upstream.URL,
		"transform":    "raw",
		"auth_profile": "client-prof",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (bad_request); body = %s", rec.Code, rec.Body.String())
	}
	if errResp.Error.Code != model.CodeBadRequest {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeBadRequest)
	}
	if !strings.Contains(errResp.Error.Message, "not available") {
		t.Errorf("message should explain the requested profile is not available, got %q", errResp.Error.Message)
	}
	if hits.Load() != 0 {
		t.Errorf("upstream hit %d times; a mismatched identity must be refused before fetching", hits.Load())
	}
}

func TestFetchNonHTMLWithMarkdownReturns400(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"key":"value"}`)
	}, config.Config{})

	rec, _, errResp := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       env.upstream.URL,
		"transform": "markdown",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if errResp.Error.Code != model.CodeUnsupported {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeUnsupported)
	}
}

func TestFetchMissingURLReturns400(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, config.Config{})

	rec, _, errResp := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"transform": "raw",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if errResp.Error.Code != model.CodeBadRequest {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeBadRequest)
	}
}

func TestFetchUnreachableReturns502(t *testing.T) {
	t.Parallel()
	// A port that's almost certainly closed.
	rec, _, errResp := doFetch(setupUnreachableEnv(t), http.MethodPost, "/fetch", map[string]string{
		"url":       "http://127.0.0.1:1/",
		"transform": "raw",
	})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if errResp.Error.Code != model.CodeUnreachable {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeUnreachable)
	}
}

func setupUnreachableEnv(t *testing.T) *http.ServeMux {
	t.Helper()
	// Build an engine that allows everything so the fetch is attempted.
	engine, err := rules.NewEngine(nil, "allow")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{
		Timeout:      "2s",
		MaxSize:      1024 * 1024,
		MaxRedirects: 10,
		UserAgent:    "keyhole-test",
		AllowPrivate: true,
	}
	fetcher := fetch.New(netCfg, engine, nil, zap.NewNop())
	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     &config.Config{},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transform.NewRegistry(),
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)
	return mux
}

// --- truncation tests -----------------------------------------------------

func TestFetchTruncatesOversizedContent(t *testing.T) {
	t.Parallel()
	longText := strings.Repeat("A", 5000)
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>"+longText+"</body></html>")
	}, config.Config{Output: config.OutputConfig{MaxChars: 100}})

	rec, envResp, _ := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       env.upstream.URL,
		"transform": "raw",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !envResp.Truncated {
		t.Error("expected truncated:true")
	}
	// Raw returns the upstream body verbatim; truncation must cut to exactly
	// max_chars runes — a "somewhere under 2x" bound would let the response
	// exceed the limit callers size their context window against.
	if got := len([]rune(envResp.Content)); got != 100 {
		t.Errorf("content = %d runes, want exactly max_chars=100", got)
	}
}

func TestFetchMaxCharsOverride(t *testing.T) {
	t.Parallel()
	longText := strings.Repeat("B", 5000)
	// Config default is 100000, but the request asks for 50.
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>"+longText+"</body></html>")
	}, config.Config{Output: config.OutputConfig{MaxChars: 100000}})

	rec, envResp, _ := doFetch(env.mux, http.MethodPost, "/fetch", map[string]any{
		"url":       env.upstream.URL,
		"transform": "raw",
		"max_chars": 50,
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !envResp.Truncated {
		t.Error("expected truncated:true with max_chars override")
	}
	if got := len([]rune(envResp.Content)); got != 50 {
		t.Errorf("content = %d runes, want exactly max_chars=50", got)
	}
}

func TestFetchInvalidMaxCharsGETReturns400(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, config.Config{})

	rec, _, errResp := doFetch(env.mux, http.MethodGet,
		"/fetch?url="+env.upstream.URL+"&transform=raw&max_chars=abc", nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if errResp.Error.Code != model.CodeBadRequest {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeBadRequest)
	}
}

// --- request ID -----------------------------------------------------------

func TestFetchRequestIDEchoed(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}, config.Config{})

	req := httptest.NewRequest(http.MethodPost, "/fetch", strings.NewReader(
		`{"url":"`+env.upstream.URL+`","transform":"raw"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "test-id-123")
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-Id"); got != "test-id-123" {
		t.Errorf("X-Request-Id = %q, want test-id-123", got)
	}
}

func TestFetchRequestIDGeneratedWhenAbsent(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}, config.Config{})

	req := httptest.NewRequest(http.MethodPost, "/fetch", strings.NewReader(
		`{"url":"`+env.upstream.URL+`","transform":"raw"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)

	if id := rec.Header().Get("X-Request-Id"); id == "" {
		t.Error("expected a generated X-Request-Id in the response")
	}
}

// --- API key --------------------------------------------------------------

func TestFetchAPIKeyRequired(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer upstream.Close()

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowRule := config.Rule{Match: "http://" + base + "/**", Allow: boolPtr(true)}
	engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	fetcher := fetch.New(netCfg, engine, nil, zap.NewNop())

	cfg := &config.Config{Server: config.ServerConfig{APIKey: "secret-key"}}

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     cfg,
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transform.NewRegistry(),
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)

	// Without the key → 401.
	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       upstream.URL,
		"transform": "raw",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if errResp.Error.Code != "unauthorized" {
		t.Errorf("code = %q, want unauthorized", errResp.Error.Code)
	}

	// With the key → 200.
	req := httptest.NewRequest(http.MethodPost, "/fetch", strings.NewReader(
		`{"url":"`+upstream.URL+`","transform":"raw"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "secret-key")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status with key = %d, want 200", rec2.Code)
	}
}

func TestFetchAPIKeyRejectionCountedInMetrics(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowRule := config.Rule{Match: "http://" + base + "/**", Allow: boolPtr(true)}
	engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	fetcher := fetch.New(netCfg, engine, nil, zap.NewNop())

	reg := prometheus.NewRegistry()
	collectors := metrics.NewCollectors()
	collectors.MustRegister(reg)

	cfg := &config.Config{Server: config.ServerConfig{APIKey: "secret-key"}}
	mux, stop := server.New(server.Options{
		Logger:         zap.NewNop(),
		MetricsEnabled: true,
		MetricsPath:    "/metrics",
		Registry:       reg,
		Config:         cfg,
		Fetcher:        fetcher,
		Engine:         engine,
		Transforms:     transform.NewRegistry(),
		Collectors:     collectors,
	})
	t.Cleanup(stop)

	// Send a request without the key → 401.
	_, _, _ = doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       upstream.URL,
		"transform": "raw",
	})

	// Scrape /metrics — requests_total must have a 4xx entry.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `keyhole_requests_total{status="4xx"`) {
		t.Errorf("expected requests_total{status=\"4xx\"} in metrics after 401:\n%s", body)
	}
}

// --- metrics --------------------------------------------------------------

func TestFetchMetricsRecorded(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body><h1>Metric Test</h1></body></html>")
	}, config.Config{})

	// Make a request.
	_, _, _ = doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       env.upstream.URL,
		"transform": "markdown",
	})

	// Make a denied request.
	_, _, _ = doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://denied.example.com/",
		"transform": "raw",
	})

	// Verify metrics appear in /metrics output.
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "keyhole_requests_total") {
		t.Error("metrics output missing keyhole_requests_total")
	}
	if !strings.Contains(body, "keyhole_policy_denials_total") {
		t.Error("metrics output missing keyhole_policy_denials_total")
	}
}

func TestFetchMetricsTransformLabelSanitized(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, config.Config{})

	// Send a denied request with a garbage transform string. Because policy
	// is checked before the transform, the request is denied, but RecordRequest
	// is still called with the raw client string.
	const garbage = "garbage-label-DO-NOT-LEAK-9k2m"
	_, _, _ = doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://denied.example.com/",
		"transform": garbage,
	})

	// Scrape /metrics and verify the garbage string does not appear as a label.
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if strings.Contains(body, garbage) {
		t.Errorf("metrics output leaked unbounded transform label %q:\n%s", garbage, body)
	}
}

// --- cache ----------------------------------------------------------------

func TestFetchCacheHitOnSecondRequest(t *testing.T) {
	t.Parallel()
	var fetchCount int
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>Cached content</body></html>")
	}, config.Config{})

	// First request — cache miss.
	_, _, _ = doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       env.upstream.URL,
		"transform": "raw",
	})
	if fetchCount != 1 {
		t.Fatalf("expected 1 upstream fetch, got %d", fetchCount)
	}

	// Second identical request — should be a cache hit.
	_, envResp, _ := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       env.upstream.URL,
		"transform": "raw",
	})
	if fetchCount != 1 {
		t.Fatalf("expected 1 upstream fetch (cache hit), got %d", fetchCount)
	}
	if !envResp.OK {
		t.Error("expected ok:true from cache")
	}

	// Verify the cache-hit counter was incremented in /metrics (Phase 3 DoD).
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "keyhole_cache_hits_total 1") {
		t.Errorf("expected keyhole_cache_hits_total 1 in metrics:\n%s", rec.Body.String())
	}
}

// --- capture logger helper (reused from fetch_test pattern) ----------------

func newCaptureLogger() (*zap.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&buf),
		zapcore.DebugLevel,
	))
	return logger, &buf
}

func TestFetchRequestIDInLogs(t *testing.T) {
	t.Parallel()
	// Build a server with a capture logger so we can inspect log output.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	defer upstream.Close()

	logger, buf := newCaptureLogger()

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowRule := config.Rule{Match: "http://" + base + "/**", Allow: boolPtr(true)}
	engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	fetcher := fetch.New(netCfg, engine, nil, logger)

	mux, stop := server.New(server.Options{
		Logger:     logger,
		Config:     &config.Config{},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transform.NewRegistry(),
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)

	req := httptest.NewRequest(http.MethodPost, "/fetch", strings.NewReader(
		`{"url":"`+upstream.URL+`","transform":"raw"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "log-trace-id-42")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	logOut := buf.String()
	if !strings.Contains(logOut, "log-trace-id-42") {
		t.Errorf("expected request_id 'log-trace-id-42' in log output:\n%s", logOut)
	}
	if !strings.Contains(logOut, `"msg":"request"`) {
		t.Errorf("expected access log 'request' message in output:\n%s", logOut)
	}
}

// Ensure context import is used (for potential future test additions).
var _ = context.Background

// Ensure authprofile import is used (for potential future test additions).
var _ = authprofile.New

// --- YouTube direct-transform path ----------------------------------------

// serverFakeYouTubeClient is a minimal fake for the server-level YouTube test.
type serverFakeYouTubeClient struct {
	called bool
}

func (f *serverFakeYouTubeClient) GetVideo(_ context.Context, videoID string) (transform.VideoInfo, []string, error) {
	f.called = true
	return transform.VideoInfo{
		ID:       videoID,
		Title:    "Server Test Video",
		Author:   "Tester",
		Duration: 2 * time.Minute,
		Views:    42,
	}, []string{"en"}, nil
}

func (f *serverFakeYouTubeClient) GetTranscript(_ context.Context, _, _ string) ([]transform.CaptionLine, error) {
	return []transform.CaptionLine{
		{Text: "transcript line one", StartMs: 1000},
		{Text: "transcript line two", StartMs: 5000},
	}, nil
}

// TestFetchYouTubeUsesDirectPath verifies that a YouTube URL with transform
// "youtube" is served via the DirectTransform path: the generic HTTP fetcher is
// NOT invoked (no upstream call) and the YouTube client provides the content.
func TestFetchYouTubeUsesDirectPath(t *testing.T) {
	t.Parallel()

	// An upstream that would fail the test if hit (the YouTube path must not
	// fetch the watch page).
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamHits++
	}))
	t.Cleanup(upstream.Close)

	allowTrue := true
	ytRule := config.Rule{
		Match:      "https://www.youtube.com/watch?v=*",
		Allow:      &allowTrue,
		Transforms: []string{"youtube"},
	}
	engine, err := rules.NewEngine([]config.Rule{ytRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	fetcher := fetch.New(netCfg, engine, nil, zap.NewNop())

	fake := &serverFakeYouTubeClient{}
	transforms := transform.NewRegistry()
	transforms.Register(transform.NewYouTube(fake, transform.YouTubeOptions{
		TranscriptLanguage: "en",
		IncludeTimestamps:  true,
	}))

	reg := prometheus.NewRegistry()
	collectors := metrics.NewCollectors()
	collectors.MustRegister(reg)

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     &config.Config{Output: config.OutputConfig{MaxChars: 100000}},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transforms,
		Collectors: collectors,
	})
	t.Cleanup(stop)

	rec, envResp, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		"transform": "youtube",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !errResp.OK && errResp.Error.Code != "" {
		t.Fatalf("unexpected error: %+v", errResp)
	}
	if !envResp.OK {
		t.Fatal("expected ok:true")
	}
	if envResp.Transform != "youtube" {
		t.Errorf("transform = %q, want youtube", envResp.Transform)
	}
	if envResp.Metadata["title"] != "Server Test Video" {
		t.Errorf("metadata title = %q", envResp.Metadata["title"])
	}
	if !strings.Contains(envResp.Content, "transcript line one") {
		t.Errorf("expected transcript content, got %q", envResp.Content)
	}
	if !strings.Contains(envResp.Content, "[00:01] transcript line one") {
		t.Errorf("expected timestamp prefix, got %q", envResp.Content)
	}
	if upstreamHits != 0 {
		t.Errorf("upstream should NOT be hit by the YouTube direct path, got %d hits", upstreamHits)
	}
}

// TestFetchYouTubeMarkdownUnsupported verifies that requesting markdown on a
// YouTube URL returns unsupported pointing at the youtube transform.
func TestFetchYouTubeMarkdownUnsupported(t *testing.T) {
	t.Parallel()

	allowTrue := true
	ytRule := config.Rule{
		Match:      "https://www.youtube.com/**",
		Allow:      &allowTrue,
		Transforms: []string{"markdown", "youtube"},
	}
	engine, err := rules.NewEngine([]config.Rule{ytRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	fetcher := fetch.New(netCfg, engine, nil, zap.NewNop())

	transforms := transform.NewRegistry()
	transforms.Register(transform.NewYouTube(&serverFakeYouTubeClient{}, transform.YouTubeOptions{}))

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     &config.Config{},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transforms,
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)

	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		"transform": "markdown",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if errResp.Error.Code != model.CodeUnsupported {
		t.Errorf("code = %q, want %q", errResp.Error.Code, model.CodeUnsupported)
	}
	if !strings.Contains(errResp.Error.Message, "youtube") {
		t.Errorf("message should point at youtube transform, got %q", errResp.Error.Message)
	}
}

// newYouTubeServerEnv builds a /fetch server with an explicit rules set and a
// fake YouTube client, for the canonical-target policy tests.
func newYouTubeServerEnv(t *testing.T, rs []config.Rule, defaultPolicy string) (*http.ServeMux, *serverFakeYouTubeClient) {
	t.Helper()
	engine, err := rules.NewEngine(rs, defaultPolicy)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	fetcher := fetch.New(netCfg, engine, nil, zap.NewNop())

	fake := &serverFakeYouTubeClient{}
	transforms := transform.NewRegistry()
	transforms.Register(transform.NewYouTube(fake, transform.YouTubeOptions{
		TranscriptLanguage: "en",
	}))

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     &config.Config{Output: config.OutputConfig{MaxChars: 100000}},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transforms,
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)
	return mux, fake
}

// TestFetchYouTubeDenyOnCanonicalTarget verifies that a YouTube URL allowed on
// its short-link form (youtu.be) — but whose canonical fetch target
// (www.youtube.com) is explicitly denied — is refused. Policy must be
// re-evaluated on the URL the transform actually dials, so a deny rule on the
// fetch destination blocks the request (PLAN.md:53: "a deny rule anywhere in
// the chain blocks").
func TestFetchYouTubeDenyOnCanonicalTarget(t *testing.T) {
	t.Parallel()

	rs := []config.Rule{
		{Match: "https://youtu.be/**", Allow: boolPtr(true), Transforms: []string{"youtube"}},
		{Match: "https://www.youtube.com/**", Allow: boolPtr(false)},
	}
	mux, fake := newYouTubeServerEnv(t, rs, "deny")

	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://youtu.be/dQw4w9WgXcQ",
		"transform": "youtube",
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (denied canonical target); body = %s", rec.Code, rec.Body.String())
	}
	if errResp.Error.Code != model.CodeDenied {
		t.Errorf("code = %q, want %q", errResp.Error.Code, model.CodeDenied)
	}
	if fake.called {
		t.Error("YouTube client must NOT be called when the canonical fetch target is denied")
	}
}

// TestFetchYouTubeCanonicalTargetTransformAllowlist pins that the canonical
// target's rule is re-checked for the transform allowlist too, not just
// allow/deny. A youtu.be URL whose rule permits "youtube" but whose canonical
// www.youtube.com rule permits only "raw" must be refused: otherwise the alias
// form would bypass the canonical rule's allowlist.
func TestFetchYouTubeCanonicalTargetTransformAllowlist(t *testing.T) {
	t.Parallel()

	rs := []config.Rule{
		{Match: "https://youtu.be/**", Allow: boolPtr(true), Transforms: []string{"youtube"}},
		{Match: "https://www.youtube.com/**", Allow: boolPtr(true), Transforms: []string{"raw"}},
	}
	mux, fake := newYouTubeServerEnv(t, rs, "deny")

	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://youtu.be/dQw4w9WgXcQ",
		"transform": "youtube",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (canonical rule does not allow youtube); body = %s", rec.Code, rec.Body.String())
	}
	if errResp.Error.Code != model.CodeUnsupported {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeUnsupported)
	}
	if fake.called {
		t.Error("YouTube client must NOT be called when the canonical target's rule forbids the transform")
	}
}

// TestFetchYouTubeFinalURLIsCanonical verifies that final_url reports the
// canonical watch URL that was actually fetched, not the raw request URL — the
// provenance promise (PLAN.md:9: "final URL after redirects").
func TestFetchYouTubeFinalURLIsCanonical(t *testing.T) {
	t.Parallel()

	rs := []config.Rule{
		{Match: "https://youtu.be/**", Allow: boolPtr(true), Transforms: []string{"youtube"}},
		{Match: "https://www.youtube.com/**", Allow: boolPtr(true), Transforms: []string{"youtube"}},
	}
	mux, _ := newYouTubeServerEnv(t, rs, "deny")

	rec, envResp, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://youtu.be/dQw4w9WgXcQ",
		"transform": "youtube",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !errResp.OK && errResp.Error.Code != "" {
		t.Fatalf("unexpected error: %+v", errResp)
	}
	const want = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
	if envResp.FinalURL != want {
		t.Errorf("final_url = %q, want %q", envResp.FinalURL, want)
	}
}

// --- Phase 8: rate limiting through the full mux ---------------------------

// TestRateLimitThroughMux proves the /fetch route enforces the configured
// per-client-IP rate limit end-to-end: burst requests succeed, the next gets
// 429 with a Retry-After header.
func TestRateLimitThroughMux(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeUpstreamBody(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowRule := config.Rule{Match: "http://" + base + "/**", Allow: boolPtr(true), Transforms: []string{"raw"}}
	engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}

	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, MaxRedirects: 10, AllowPrivate: true}
	fetcher := fetch.New(netCfg, engine, nil, zap.NewNop())
	transforms := transform.NewRegistry()
	reg := prometheus.NewRegistry()
	collectors := metrics.NewCollectors()
	collectors.MustRegister(reg)

	// Rate limit: 1 rps, burst 2 — allows 2 requests then 429s the third.
	cfg := config.Config{
		Server: config.ServerConfig{
			Rate: config.RateConfig{RPS: 1, Burst: 2},
		},
	}
	mux, stop := server.New(server.Options{
		Logger:         zap.NewNop(),
		MetricsEnabled: false,
		Ready:          func() bool { return true },
		Registry:       reg,
		Config:         &cfg,
		Fetcher:        fetcher,
		Engine:         engine,
		Transforms:     transforms,
		Collectors:     collectors,
	})
	t.Cleanup(stop)

	url := upstream.URL + "/"
	// First two requests (within burst) should succeed.
	for i := 0; i < 2; i++ {
		rec, _, _ := doFetch(mux, http.MethodPost, "/fetch", map[string]string{"url": url, "transform": "raw"})
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (within burst)", i+1, rec.Code)
		}
	}

	// Third request exceeds burst → 429 + Retry-After.
	req := httptest.NewRequest(http.MethodPost, "/fetch", jsonString(t, map[string]string{"url": url, "transform": "raw"}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header missing on 429")
	}
}

func writeUpstreamBody(w http.ResponseWriter, s string) {
	_, _ = io.WriteString(w, s)
}

func jsonString(t *testing.T, v any) io.Reader {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bytes.NewReader(data)
}

// TestFetchDirectTransformRejectsAuthProfile pins the fail-closed behavior for
// rules that attach an auth_profile to a DirectTransform (e.g. youtube): the
// direct client cannot apply profile headers, so the request must fail loudly
// instead of silently fetching without the credentials the rule promised.
func TestFetchDirectTransformRejectsAuthProfile(t *testing.T) {
	t.Parallel()

	allowTrue := true
	ytRule := config.Rule{
		Match:       "https://www.youtube.com/watch?v=*",
		Allow:       &allowTrue,
		Transforms:  []string{"youtube"},
		AuthProfile: "sso",
	}
	engine, err := rules.NewEngine([]config.Rule{ytRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	profiles := authprofile.New([]config.AuthProfile{
		{Name: "sso", Headers: map[string]string{"Authorization": "Bearer x"}},
	})
	fetcher := fetch.New(config.NetworkConfig{Timeout: "5s", MaxSize: 1024, AllowPrivate: true}, engine, profiles, zap.NewNop())

	fake := &serverFakeYouTubeClient{}
	transforms := transform.NewRegistry()
	transforms.Register(transform.NewYouTube(fake, transform.YouTubeOptions{TranscriptLanguage: "en"}))

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     &config.Config{Output: config.OutputConfig{MaxChars: 1000}},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transforms,
		Profiles:   profiles,
	})
	t.Cleanup(stop)

	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		"transform": "youtube",
	})

	if rec.Code == http.StatusOK {
		t.Fatal("rule-attached auth_profile on a direct transform must not succeed")
	}
	if errResp.Error.Code != "unsupported" {
		t.Fatalf("error code = %q, want unsupported; body=%s", errResp.Error.Code, rec.Body.String())
	}
	if fake.called {
		t.Fatal("the direct (YouTube) client must not be invoked when the profile cannot be applied")
	}
}

// TestFetchRedirectEnforcesFinalRuleTransforms pins the cross-rule transform
// check: an allow rule permitting markdown on the original URL whose redirect
// lands on a rule allowing only raw must NOT have markdown applied to the
// final content.
func TestFetchRedirectEnforcesFinalRuleTransforms(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html><body><p>arrived</p></body></html>")
		}
	}))
	t.Cleanup(upstream.Close)

	host := strings.TrimPrefix(upstream.URL, "http://")
	allow := true
	engine, err := rules.NewEngine([]config.Rule{
		{Match: "http://" + host + "/start", Allow: &allow, Transforms: []string{"raw", "markdown"}},
		{Match: "http://" + host + "/end", Allow: &allow, Transforms: []string{"raw"}},
	}, "deny")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	fetcher := fetch.New(config.NetworkConfig{
		Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true, MaxRedirects: 5,
	}, engine, nil, zap.NewNop())
	transforms := transform.NewRegistry()

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     &config.Config{Output: config.OutputConfig{MaxChars: 100000}},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transforms,
	})
	t.Cleanup(stop)

	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       upstream.URL + "/start",
		"transform": "markdown",
	})
	if rec.Code == http.StatusOK {
		t.Fatal("markdown through a final rule allowing only raw must not succeed")
	}
	if errResp.Error.Code != "unsupported" {
		t.Fatalf("error code = %q, want unsupported; body=%s", errResp.Error.Code, rec.Body.String())
	}

	// raw is allowed by both rules and must still succeed.
	rec, envResp, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       upstream.URL + "/start",
		"transform": "raw",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("raw status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !envResp.OK || errResp.Error.Code != "" {
		t.Fatalf("raw should succeed: %+v", errResp)
	}
}

// TestFetchTransformNotAllowedByOriginalRule pins that the matched rule's
// transform allowlist gates the request before any upstream contact: a rule
// that permits only "raw" must reject a markdown request. Without this check,
// an allowlisted URL would silently gain every transform the registry knows.
func TestFetchTransformNotAllowedByOriginalRule(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body><h1>Secret</h1></body></html>")
	}))
	t.Cleanup(upstream.Close)

	host := strings.TrimPrefix(upstream.URL, "http://")
	allow := true
	engine, err := rules.NewEngine([]config.Rule{
		{Match: "http://" + host + "/**", Allow: &allow, Transforms: []string{"raw"}},
	}, "deny")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	fetcher := fetch.New(config.NetworkConfig{
		Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true, MaxRedirects: 5,
	}, engine, nil, zap.NewNop())

	mux, stop := server.New(server.Options{
		Logger:     zap.NewNop(),
		Config:     &config.Config{Output: config.OutputConfig{MaxChars: 100000}},
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transform.NewRegistry(),
		Collectors: metrics.NewCollectors(),
	})
	t.Cleanup(stop)

	rec, _, errResp := doFetch(mux, http.MethodPost, "/fetch", map[string]string{
		"url":       upstream.URL + "/page",
		"transform": "markdown",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if errResp.Error.Code != model.CodeUnsupported {
		t.Errorf("error code = %q, want %q", errResp.Error.Code, model.CodeUnsupported)
	}
	if !strings.Contains(errResp.Error.Message, "not allowed") {
		t.Errorf("message should name the allowlist rejection, got %q", errResp.Error.Message)
	}
	if hits.Load() != 0 {
		t.Errorf("upstream hit %d times; the allowlist must reject before fetching", hits.Load())
	}
}

// TestFetchCacheHitRestampsRequestURL pins the provenance contract on cache
// hits: the cache key is the normalized URL (case-insensitive host), so two
// spellings share an entry — the second requester must see THEIR original
// spelling in envelope.url, not the first requester's.
func TestFetchCacheHitRestampsRequestURL(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t,
		func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "cached body") },
		config.Config{Output: config.OutputConfig{MaxChars: 100000}})

	host := strings.TrimPrefix(env.upstream.URL, "http://")
	upper := "http://" + strings.ToUpper(host) + "/"
	lower := env.upstream.URL + "/"

	// Prime the cache with the upper-case spelling.
	rec, resp, errResp := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       upper,
		"transform": "raw",
	})
	if rec.Code != http.StatusOK || !resp.OK {
		t.Fatalf("prime fetch failed: status=%d body=%s err=%+v", rec.Code, rec.Body.String(), errResp)
	}
	if resp.URL != upper {
		t.Fatalf("prime: envelope url = %q, want the requested spelling", resp.URL)
	}

	// Same normalized URL, different spelling → cache hit; url must be
	// re-stamped to the current request.
	rec, resp, errResp = doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       lower,
		"transform": "raw",
	})
	if rec.Code != http.StatusOK || !resp.OK {
		t.Fatalf("cached fetch failed: status=%d body=%s err=%+v", rec.Code, rec.Body.String(), errResp)
	}
	if resp.URL != lower {
		t.Fatalf("cache hit: envelope url = %q, want the current request spelling %q", resp.URL, lower)
	}
}

// TestFetchCacheControlNoStore pins the intermediary-defense header: /fetch
// success bodies and envelope errors must never be stored by shared caches —
// they are internal documents and policy-bearing rejections.
func TestFetchCacheControlNoStore(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t,
		func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "body") },
		config.Config{Output: config.OutputConfig{MaxChars: 100000}})

	rec, _, _ := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       env.upstream.URL + "/",
		"transform": "raw",
	})
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("success Cache-Control = %q, want no-store", cc)
	}

	// Policy denial → envelope error path.
	rec, _, _ = doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
		"url":       "https://denied.invalid/x",
		"transform": "raw",
	})
	if rec.Code == http.StatusOK {
		t.Fatal("expected denial")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("error Cache-Control = %q, want no-store", cc)
	}

	// Health endpoint stays cacheable (no no-store directive forced).
	healthRec := httptest.NewRecorder()
	env.mux.ServeHTTP(healthRec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if cc := healthRec.Header().Get("Cache-Control"); cc == "no-store" {
		t.Fatal("/healthz should not carry no-store")
	}
}

// --- request-parsing edge cases -------------------------------------------

// TestHeadFetchReturnsEnvelopeStatus pins that HEAD /fetch is routed like GET
// (Go's ServeMux maps HEAD to GET patterns) and does not fall through to a
// zero-value request that errors "url is required".
func TestHeadFetchReturnsEnvelopeStatus(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}, config.Config{})

	rec, _, errResp := doFetch(env.mux, http.MethodHead, "/fetch?url="+env.upstream.URL, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD /fetch status = %d, want 200 (error %+v)", rec.Code, errResp)
	}
}

// TestPostFetchRejectsUnknownField pins strict body decoding: a typo must be
// rejected, not silently ignored so the request runs with a surprising default.
func TestPostFetchRejectsUnknownField(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, config.Config{})

	rec, _, errResp := doFetch(env.mux, http.MethodPost, "/fetch", map[string]any{
		"url":       env.upstream.URL,
		"max_char":  10, // typo: should be max_chars
		"transform": "raw",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if errResp.Error.Code != model.CodeBadRequest {
		t.Fatalf("code = %q, want bad_request", errResp.Error.Code)
	}
}

// TestPostFetchRejectsTrailingJSON pins that junk after the JSON object is an
// error rather than silently ignored.
func TestPostFetchRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, config.Config{})

	body := `{"url":"` + env.upstream.URL + `","transform":"raw"} {"extra":true}`
	req := httptest.NewRequest(http.MethodPost, "/fetch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestGetFetchPreservesLiteralPlus pins that a '+' in the url query parameter
// reaches policy and the upstream as a literal '+', not as a space (net/url's
// form decoding would rewrite it).
func TestGetFetchPreservesLiteralPlus(t *testing.T) {
	t.Parallel()
	var gotPath atomic.Value
	env := newFetchTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}, config.Config{})

	// Raw '+' in the outer query string (not percent-encoded).
	target := env.upstream.URL + "/a+b"
	rec, _, errResp := doFetch(env.mux, http.MethodGet, "/fetch?url="+target, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (error %+v)", rec.Code, errResp)
	}
	if got := gotPath.Load(); got != "/a+b" {
		t.Fatalf("upstream path = %v, want /a+b (literal plus preserved)", got)
	}
}

func TestGetFetchMaxCharsNonIntegerRejected(t *testing.T) {
	t.Parallel()
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, config.Config{})

	rec, _, errResp := doFetch(env.mux, http.MethodGet, "/fetch?url="+env.upstream.URL+"&max_chars=abc", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if errResp.Error.Code != model.CodeBadRequest {
		t.Fatalf("code = %q, want bad_request", errResp.Error.Code)
	}
}

// TestFetchConcurrentMissesSingleflight pins the cache-stampede guard: N
// concurrent requests for one cold URL must produce exactly one upstream fetch,
// with every caller receiving the same successful envelope.
func TestFetchConcurrentMissesSingleflight(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	release := make(chan struct{})
	var releaseOnce sync.Once
	env := newFetchTestEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		<-release
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>shared</body></html>")
	}, config.Config{})

	const n = 25
	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, _, _ := doFetch(env.mux, http.MethodPost, "/fetch", map[string]string{
				"url":       env.upstream.URL,
				"transform": "raw",
			})
			if rec.Code != http.StatusOK {
				failures.Add(1)
			}
		}()
	}
	// Give the callers time to pile up on the in-flight call, then let the
	// leader's upstream response complete.
	time.Sleep(75 * time.Millisecond)
	releaseOnce.Do(func() { close(release) })
	wg.Wait()

	if got := failures.Load(); got != 0 {
		t.Fatalf("%d/%d concurrent fetches failed", got, n)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1 (single-flight)", got)
	}
}
