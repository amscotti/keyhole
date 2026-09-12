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
	"github.com/amscotti/keyhole/internal/rules"
	"github.com/amscotti/keyhole/internal/server"
	"github.com/amscotti/keyhole/internal/transform"
)

// ctxProbeKey carries the marker value proving the request context reached
// the transform.
type ctxProbeKey struct{}

// ctxProbeTransform is a ContextTransform registered as "raw" that records
// which entry point the server used and which context it passed.
type ctxProbeTransform struct {
	applyCalled bool
	gotValue    any
}

func (p *ctxProbeTransform) Name() string { return "raw" }

func (p *ctxProbeTransform) Apply(body []byte, contentType, _ string) (*transform.Result, error) {
	p.applyCalled = true
	return &transform.Result{Content: string(body), OutputType: contentType}, nil
}

func (p *ctxProbeTransform) ApplyContext(ctx context.Context, body []byte, contentType, _ string) (*transform.Result, error) {
	p.gotValue = ctx.Value(ctxProbeKey{})
	return &transform.Result{Content: string(body), OutputType: contentType}, nil
}

// TestServicePrefersApplyContext verifies the server passes the request
// context to context-aware transforms on the fetch→apply path: Apply must
// NOT be called, and the marker value in the request context must arrive
// intact. Without the dispatch, client disconnect could never abort Office
// conversions.
func TestServicePrefersApplyContext(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>hi</body></html>")
	}))
	t.Cleanup(upstream.Close)

	base := strings.TrimPrefix(upstream.URL, "http://")
	engine, err := rules.NewEngine([]config.Rule{
		{Match: "http://" + base + "/**", Allow: boolPtr(true)},
	}, "deny")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	netCfg := config.NetworkConfig{
		Timeout:      "5s",
		MaxSize:      1024 * 1024,
		MaxRedirects: 10,
		UserAgent:    "keyhole-test",
		AllowPrivate: true,
	}
	fetcher := fetch.New(netCfg, engine, nil, zap.NewNop())

	reg := transform.NewRegistry()
	probe := &ctxProbeTransform{}
	reg.Register(probe) // replaces "raw" for this test

	svc := &server.Service{
		Collectors: metrics.NewCollectors(),
		Logger:     zap.NewNop(),
	}
	svc.StoreDeps(&server.Deps{
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: reg,
		Cfg:        &config.Config{},
	})

	ctx := context.WithValue(context.Background(), ctxProbeKey{}, "probe-123")
	env, ferr := svc.Fetch(ctx, server.FetchRequest{URL: upstream.URL, Transform: "raw"})
	if ferr != nil {
		t.Fatalf("fetch: %v", ferr)
	}
	if !env.OK {
		t.Fatal("expected ok envelope")
	}
	if probe.applyCalled {
		t.Fatal("server called Apply; want ApplyContext for ContextTransform")
	}
	if probe.gotValue != "probe-123" {
		t.Fatalf("transform saw ctx value %v; request context was not propagated", probe.gotValue)
	}
}
