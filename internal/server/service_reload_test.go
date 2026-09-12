package server_test

import (
	"context"
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

// TestServiceStoreDepsHotSwap verifies that StoreDeps makes a new policy engine
// visible on the next Fetch call — the hot-reload wiring contract.
func TestServiceStoreDepsHotSwap(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>ok</body></html>")
	}))
	t.Cleanup(upstream.Close)

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowAll, err := rules.NewEngine([]config.Rule{
		{Match: "http://" + base + "/**", Allow: boolPtr(true)},
	}, "deny")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	denyAll, err := rules.NewEngine(nil, "deny")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	netCfg := config.NetworkConfig{Timeout: "5s", MaxSize: 1024 * 1024, AllowPrivate: true}
	fetcherAllow := fetch.New(netCfg, allowAll, nil, zap.NewNop())
	fetcherDeny := fetch.New(netCfg, denyAll, nil, zap.NewNop())
	reg := transform.NewRegistry()
	cfg := &config.Config{}

	svc := &server.Service{
		Collectors: metrics.NewCollectors(),
		Logger:     zap.NewNop(),
	}
	svc.StoreDeps(&server.Deps{
		Fetcher:    fetcherAllow,
		Engine:     allowAll,
		Transforms: reg,
		Cfg:        cfg,
	})

	env, ferr := svc.Fetch(context.Background(), server.FetchRequest{
		URL:       upstream.URL,
		Transform: "raw",
	})
	if ferr != nil {
		t.Fatalf("first fetch: %v", ferr)
	}
	if !env.OK {
		t.Fatal("first fetch expected ok")
	}

	// Hot-swap to deny-all: the next request must be refused.
	svc.StoreDeps(&server.Deps{
		Fetcher:    fetcherDeny,
		Engine:     denyAll,
		Transforms: reg,
		Cfg:        cfg,
	})
	_, ferr = svc.Fetch(context.Background(), server.FetchRequest{
		URL:       upstream.URL,
		Transform: "raw",
	})
	if ferr == nil {
		t.Fatal("expected denial after StoreDeps deny-all")
	}
	if ferr.Code != model.CodeDenied {
		t.Fatalf("code = %q, want denied", ferr.Code)
	}
}
