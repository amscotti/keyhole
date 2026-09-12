package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/model"
	"github.com/amscotti/keyhole/internal/server"
)

func TestBuildDeps_WiresEngineFetcherTransforms(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>hi</body></html>")
	}))
	t.Cleanup(upstream.Close)

	base := strings.TrimPrefix(upstream.URL, "http://")
	cfg := loadSnippet(t, fmt.Sprintf(`
default_policy = "deny"
[network]
timeout = "5s"
max_size = 1048576
max_redirects = 5
user_agent = "deps-test"
allow_private = true
[cache]
enabled = true
ttl = "1m"
max_entries = 10
[youtube]
transcript_language = "en"
max_chars = 1000
[office]
pandoc_path = "pandoc"
timeout = "5s"
[[rules]]
match = "http://%s/**"
allow = true
transforms = ["raw", "markdown", "youtube", "office"]
`, base))

	deps, err := buildDeps(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("buildDeps: %v", err)
	}
	if deps.Cache != nil {
		t.Cleanup(deps.Cache.Stop)
	}
	if deps.Engine == nil || deps.Fetcher == nil || deps.Transforms == nil {
		t.Fatal("expected engine, fetcher, transforms")
	}
	for _, name := range []string{"raw", "markdown", "article", "youtube", "office"} {
		if _, ok := deps.Transforms.Get(name); !ok {
			t.Errorf("missing transform %q", name)
		}
	}

	svc := &server.Service{Collectors: metrics.NewCollectors(), Logger: zap.NewNop()}
	svc.StoreDeps(deps)
	env, ferr := svc.Fetch(context.Background(), server.FetchRequest{
		URL:       upstream.URL + "/",
		Transform: "raw",
	})
	if ferr != nil {
		t.Fatalf("Fetch: %v", ferr)
	}
	if !env.OK || !strings.Contains(env.Content, "hi") {
		t.Fatalf("envelope unexpected: %+v", env)
	}
}

func TestRuntimeState_ApplySwapsPolicy(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>x</body></html>")
	}))
	t.Cleanup(upstream.Close)
	base := strings.TrimPrefix(upstream.URL, "http://")

	svc := &server.Service{Collectors: metrics.NewCollectors(), Logger: zap.NewNop()}
	rt := &runtimeState{svc: svc, logger: zap.NewNop()}
	t.Cleanup(rt.stop)

	allowCfg := loadSnippet(t, fmt.Sprintf(`
default_policy = "deny"
[network]
timeout = "5s"
max_size = 1048576
allow_private = true
[cache]
enabled = false
ttl = "1m"
[office]
pandoc_path = "pandoc"
timeout = "5s"
[[rules]]
match = "http://%s/**"
allow = true
transforms = ["raw", "markdown"]
`, base))
	if err := rt.apply(allowCfg); err != nil {
		t.Fatalf("apply allow: %v", err)
	}
	_, ferr := svc.Fetch(context.Background(), server.FetchRequest{
		URL: upstream.URL + "/", Transform: "raw",
	})
	if ferr != nil {
		t.Fatalf("fetch under allow: %v", ferr)
	}

	denyCfg := loadSnippet(t, `
default_policy = "deny"
[network]
timeout = "5s"
max_size = 1048576
allow_private = true
[cache]
enabled = false
ttl = "1m"
[office]
pandoc_path = "pandoc"
timeout = "5s"
`)
	if err := rt.apply(denyCfg); err != nil {
		t.Fatalf("apply deny: %v", err)
	}
	_, ferr = svc.Fetch(context.Background(), server.FetchRequest{
		URL: upstream.URL + "/", Transform: "raw",
	})
	if ferr == nil {
		t.Fatal("expected denial after apply deny-all")
	}
	if ferr.Code != model.CodeDenied {
		t.Fatalf("code = %q, want denied", ferr.Code)
	}
}

func TestRuntimeState_StopCacheIdempotent(t *testing.T) {
	t.Parallel()
	svc := &server.Service{Collectors: metrics.NewCollectors(), Logger: zap.NewNop()}
	rt := &runtimeState{svc: svc, logger: zap.NewNop()}
	cfg := loadSnippet(t, `
default_policy = "deny"
[network]
timeout = "5s"
max_size = 1048576
[cache]
enabled = true
ttl = "1m"
max_entries = 5
[office]
pandoc_path = "pandoc"
timeout = "5s"
`)
	if err := rt.apply(cfg); err != nil {
		t.Fatalf("apply: %v", err)
	}
	rt.stop()
	rt.stop()
}

func loadSnippet(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}
