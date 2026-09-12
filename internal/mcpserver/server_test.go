package mcpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/fetch"
	"github.com/amscotti/keyhole/internal/mcpserver"
	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/model"
	"github.com/amscotti/keyhole/internal/rules"
	"github.com/amscotti/keyhole/internal/server"
	"github.com/amscotti/keyhole/internal/transform"
)

// --- test helpers ---------------------------------------------------------

// testEnv bundles the shared dependencies and the upstream httptest server
// used by the MCP tests. Both REST and MCP paths are built from the same deps
// so parity can be verified directly.
type testEnv struct {
	svc         *server.Service
	upstream    *httptest.Server
	upstreamURL string
}

// newTestEnv creates an upstream that serves a simple HTML page, and builds a
// shared Service with a deny-by-default policy that allows only the upstream
// host. denyHost sets up a second host that is explicitly denied.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>Hello</h1><p>World</p></body></html>"))
	}))
	t.Cleanup(upstream.Close)

	base := strings.TrimPrefix(upstream.URL, "http://")

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
	collectors := metrics.NewCollectors()

	svc := &server.Service{
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transforms,
		Cfg:        &config.Config{},
		Collectors: collectors,
		Logger:     zap.NewNop(),
	}

	return &testEnv{
		svc:         svc,
		upstream:    upstream,
		upstreamURL: upstream.URL + "/page",
	}
}

// newDeniedEnv creates a test environment with a separate denied host.
func newDeniedEnv(t *testing.T) (*testEnv, string) {
	t.Helper()
	env := newTestEnv(t)

	deniedUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	t.Cleanup(deniedUpstream.Close)
	return env, deniedUpstream.URL + "/secret"
}

// mcpClient builds an MCP server from svc, connects an in-process client, and
// initializes the session. The cleanup is registered with t.Cleanup.
func mcpClient(t *testing.T, svc *server.Service) *client.Client {
	t.Helper()

	s := mcpserver.New(svc, zap.NewNop())

	c, err := client.NewInProcessClient(s)
	if err != nil {
		t.Fatalf("create in-process client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("start client: %v", err)
	}

	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "keyhole-test",
		Version: "1.0.0",
	}
	if _, err := c.Initialize(ctx, initReq); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	return c
}

func boolPtr(b bool) *bool { return &b }

// --- tools/list tests -----------------------------------------------------

func TestToolsList_ShowsFetchTool(t *testing.T) {
	env := newTestEnv(t)
	c := mcpClient(t, env.svc)

	result, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if len(result.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(result.Tools))
	}

	tool := result.Tools[0]
	if tool.Name != "fetch" {
		t.Errorf("tool name: got %q, want %q", tool.Name, "fetch")
	}
	if tool.Description == "" {
		t.Error("tool description is empty — models read it to understand the tool")
	}
	// The description must mention key behaviors so a model knows what to expect.
	desc := strings.ToLower(tool.Description)
	for _, want := range []string{"truncat", "denied", "policy"} {
		if !strings.Contains(desc, want) {
			t.Errorf("tool description should mention %q (models need to know), got: %s", want, tool.Description)
		}
	}

	// Verify the input schema has the expected properties.
	schema := tool.InputSchema
	if schema.Properties == nil {
		t.Fatal("input schema has no properties")
	}

	// url must be required.
	urlProp, ok := schema.Properties["url"]
	if !ok {
		t.Fatal("schema missing 'url' property")
	}
	if !hasString(urlProp, "type", "string") {
		t.Errorf("url property type: got %v, want %q", urlProp, "string")
	}
	foundURLRequired := false
	for _, req := range schema.Required {
		if req == "url" {
			foundURLRequired = true
		}
	}
	if !foundURLRequired {
		t.Error("'url' is not in the required properties list")
	}

	// transform must be an enum.
	transformProp, ok := schema.Properties["transform"]
	if !ok {
		t.Fatal("schema missing 'transform' property")
	}
	if !hasEnum(transformProp) {
		t.Error("'transform' should be an enum")
	}

	// max_chars must be integer.
	maxCharsProp, ok := schema.Properties["max_chars"]
	if !ok {
		t.Fatal("schema missing 'max_chars' property")
	}
	if !hasString(maxCharsProp, "type", "integer") {
		t.Errorf("max_chars property type: got %v, want %q", maxCharsProp, "integer")
	}

	// auth_profile must be string.
	authProp, ok := schema.Properties["auth_profile"]
	if !ok {
		t.Fatal("schema missing 'auth_profile' property")
	}
	if !hasString(authProp, "type", "string") {
		t.Errorf("auth_profile property type: got %v, want %q", authProp, "string")
	}
}

// --- tools/call tests -----------------------------------------------------

func TestCallTool_PermittedURL_ReturnsContent(t *testing.T) {
	env := newTestEnv(t)
	c := mcpClient(t, env.svc)

	req := mcp.CallToolRequest{}
	req.Params.Name = "fetch"
	req.Params.Arguments = map[string]any{
		"url":       env.upstreamURL,
		"transform": "raw",
	}

	result, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	// The text content should contain the upstream HTML.
	text := toolResultText(result)
	if !strings.Contains(text, "<h1>Hello</h1>") {
		t.Errorf("expected HTML content, got: %s", text)
	}

	// Structured content should carry the full envelope.
	env2 := parseStructuredEnvelope(t, result)
	if !env2.OK {
		t.Error("envelope OK should be true")
	}
	if env2.Transform != "raw" {
		t.Errorf("envelope transform: got %q, want %q", env2.Transform, "raw")
	}
}

func TestCallTool_DeniedURL_ReturnsErrorModelCanRead(t *testing.T) {
	env, deniedURL := newDeniedEnv(t)
	c := mcpClient(t, env.svc)

	req := mcp.CallToolRequest{}
	req.Params.Name = "fetch"
	req.Params.Arguments = map[string]any{
		"url":       deniedURL,
		"transform": "raw",
	}

	result, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool returned transport error (should be tool error): %v", err)
	}

	// Per MCP convention, policy denial surfaces as IsError in the result, not
	// as a Go error — so the model can see and react to it.
	if !result.IsError {
		t.Fatal("expected IsError=true for denied URL, got false")
	}

	text := toolResultText(result)
	if !strings.Contains(strings.ToLower(text), "denied") {
		t.Errorf("error message should mention 'denied' so the model can react, got: %s", text)
	}
}

func TestCallTool_MissingURL_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	c := mcpClient(t, env.svc)

	req := mcp.CallToolRequest{}
	req.Params.Name = "fetch"
	req.Params.Arguments = map[string]any{
		"transform": "raw",
	}

	result, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError for missing url")
	}

	text := toolResultText(result)
	if !strings.Contains(strings.ToLower(text), `"url"`) && !strings.Contains(strings.ToLower(text), "url") {
		t.Errorf("error should mention 'url', got: %s", text)
	}
}

// TestCallTool_ErrorTextCarriesCode pins the model-facing error format:
// "denied" keeps its friendly prefix, and any other fetch code falls through
// to its raw code name ("too_large: ...") so a model can still branch on the
// machine-readable signal instead of losing it in prose.
func TestCallTool_ErrorTextCarriesCode(t *testing.T) {
	t.Parallel()

	// Default branch: a tiny max_size turns an oversized upstream body into
	// the too_large code, which has no special formatting.
	t.Run("default branch prefixes the code", func(t *testing.T) {
		t.Parallel()

		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>" + strings.Repeat("x", 256) + "</body></html>"))
		}))
		t.Cleanup(upstream.Close)

		host := strings.TrimPrefix(upstream.URL, "http://")
		allowRule := config.Rule{
			Match:      "http://" + host + "/**",
			Allow:      boolPtr(true),
			Transforms: []string{"raw"},
		}
		engine, err := rules.NewEngine([]config.Rule{allowRule}, "deny")
		if err != nil {
			t.Fatalf("build engine: %v", err)
		}
		fetcher := fetch.New(config.NetworkConfig{
			Timeout: "5s", MaxSize: 32, MaxRedirects: 5, UserAgent: "keyhole-test", AllowPrivate: true,
		}, engine, nil, zap.NewNop())
		svc := &server.Service{
			Fetcher:    fetcher,
			Engine:     engine,
			Transforms: transform.NewRegistry(),
			Cfg:        &config.Config{},
			Collectors: metrics.NewCollectors(),
			Logger:     zap.NewNop(),
		}
		c := mcpClient(t, svc)

		req := mcp.CallToolRequest{}
		req.Params.Name = "fetch"
		req.Params.Arguments = map[string]any{
			"url":       upstream.URL,
			"transform": "raw",
		}
		result, err := c.CallTool(context.Background(), req)
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !result.IsError {
			t.Fatal("expected IsError=true for an oversized body")
		}
		text := toolResultText(result)
		if !strings.HasPrefix(text, model.CodeTooLarge+": ") {
			t.Errorf("error text = %q, want prefix %q", text, model.CodeTooLarge+": ")
		}
		if !strings.Contains(text, "max_size") {
			t.Errorf("error text should carry the fetch message, got %q", text)
		}
	})

	t.Run("denied keeps its prefix", func(t *testing.T) {
		t.Parallel()

		env, deniedURL := newDeniedEnv(t)
		c := mcpClient(t, env.svc)

		req := mcp.CallToolRequest{}
		req.Params.Name = "fetch"
		req.Params.Arguments = map[string]any{
			"url":       deniedURL,
			"transform": "raw",
		}
		result, err := c.CallTool(context.Background(), req)
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !result.IsError {
			t.Fatal("expected IsError=true for denied URL")
		}
		if text := toolResultText(result); !strings.HasPrefix(text, model.CodeDenied+": ") {
			t.Errorf("error text = %q, want prefix %q", text, model.CodeDenied+": ")
		}
	})
}

// TestCallTool_MissingURLCountedAsBadRequest pins that a malformed MCP call is
// visible in keyhole_requests_total with a 4xx status: an MCP-only deployment
// must be able to alert on bad-call volume, mirroring REST parse failures.
func TestCallTool_MissingURLCountedAsBadRequest(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	c := mcpClient(t, env.svc)

	req := mcp.CallToolRequest{}
	req.Params.Name = "fetch"
	req.Params.Arguments = map[string]any{"transform": "raw"}
	if _, err := c.CallTool(context.Background(), req); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	got := testutil.ToFloat64(env.svc.Collectors.Requests.WithLabelValues("unknown", "4xx"))
	if got != 1 {
		t.Fatalf(`keyhole_requests_total{transform="unknown",status="4xx"} = %v, want 1`, got)
	}
}

func TestCallTool_MarkdownTransform(t *testing.T) {
	env := newTestEnv(t)
	c := mcpClient(t, env.svc)

	req := mcp.CallToolRequest{}
	req.Params.Name = "fetch"
	req.Params.Arguments = map[string]any{
		"url":       env.upstreamURL,
		"transform": "markdown",
	}

	result, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", toolResultText(result))
	}

	// Markdown of <h1>Hello</h1> should produce "# Hello".
	text := toolResultText(result)
	if !strings.Contains(text, "Hello") {
		t.Errorf("expected markdown content with 'Hello', got: %s", text)
	}
}

// --- Streamable HTTP transport tests --------------------------------------

// httpMCPClient mounts the MCP Streamable HTTP handler on an httptest server
// and connects a real HTTP client. The endpoint path is /mcp (the default).
func httpMCPClient(t *testing.T, svc *server.Service) (*client.Client, string) {
	t.Helper()

	handler := mcpserver.NewStreamableHTTPHandler(svc, zap.NewNop())
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	endpoint := ts.URL + mcpserver.MCPHTTPEndpoint
	c, err := client.NewStreamableHttpClient(endpoint)
	if err != nil {
		t.Fatalf("create streamable http client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("start client: %v", err)
	}
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "keyhole-test-http", Version: "1.0.0"}
	if _, err := c.Initialize(ctx, initReq); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	return c, endpoint
}

func TestStreamableHTTP_ListToolsShowsFetch(t *testing.T) {
	env := newTestEnv(t)
	c, _ := httpMCPClient(t, env.svc)

	result, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(result.Tools) != 1 || result.Tools[0].Name != "fetch" {
		t.Fatalf("expected one 'fetch' tool, got %+v", result.Tools)
	}
}

func TestStreamableHTTP_PermittedAndDeniedParity(t *testing.T) {
	env, deniedURL := newDeniedEnv(t)
	c, _ := httpMCPClient(t, env.svc)

	// Permitted URL returns content (the same envelope as REST/stdio).
	callReq := mcp.CallToolRequest{}
	callReq.Params.Name = "fetch"
	callReq.Params.Arguments = map[string]any{
		"url":       env.upstreamURL,
		"transform": "raw",
	}
	res, err := c.CallTool(context.Background(), callReq)
	if err != nil {
		t.Fatalf("CallTool permitted: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success over HTTP, got: %s", toolResultText(res))
	}
	if !strings.Contains(toolResultText(res), "<h1>Hello</h1>") {
		t.Errorf("expected upstream HTML, got: %s", toolResultText(res))
	}
	envOK := parseStructuredEnvelope(t, res)
	if !envOK.OK {
		t.Error("HTTP envelope OK should be true")
	}

	// Denied URL returns a tool error the model can read.
	denyReq := mcp.CallToolRequest{}
	denyReq.Params.Name = "fetch"
	denyReq.Params.Arguments = map[string]any{
		"url":       deniedURL,
		"transform": "raw",
	}
	dres, err := c.CallTool(context.Background(), denyReq)
	if err != nil {
		t.Fatalf("CallTool denied: %v", err)
	}
	if !dres.IsError {
		t.Fatal("expected IsError=true for denied URL over HTTP")
	}
	if !strings.Contains(strings.ToLower(toolResultText(dres)), "denied") {
		t.Errorf("denied message should mention 'denied', got: %s", toolResultText(dres))
	}
}

// --- REST/MCP parity test -------------------------------------------------

func TestParity_RESTAndMCP_SamePolicyAndContent(t *testing.T) {
	// The DoD requires: "The same config that allows a URL over REST allows it
	// over MCP, and vice versa — one test proves parity." Both transports call
	// the exact same Service.Fetch pipeline, so the envelopes must match.
	env := newTestEnv(t)

	// 1. REST path: call Service.Fetch directly (the REST handler delegates
	// here with no HTTP-specific transformation of the result).
	restEnv, restErr := env.svc.Fetch(context.Background(), server.FetchRequest{
		URL:       env.upstreamURL,
		Transform: "raw",
	})
	if restErr != nil {
		t.Fatalf("REST path: %v", restErr)
	}

	// 2. MCP path: call through the MCP tool handler.
	c := mcpClient(t, env.svc)
	req := mcp.CallToolRequest{}
	req.Params.Name = "fetch"
	req.Params.Arguments = map[string]any{
		"url":       env.upstreamURL,
		"transform": "raw",
	}
	result, err := c.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("MCP CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("MCP path returned error: %s", toolResultText(result))
	}
	mcpEnv := parseStructuredEnvelope(t, result)

	// 3. Assert parity: the content, transform, and OK flag must match.
	if mcpEnv.OK != restEnv.OK {
		t.Errorf("OK mismatch: REST=%v MCP=%v", restEnv.OK, mcpEnv.OK)
	}
	if mcpEnv.Content != restEnv.Content {
		t.Errorf("content mismatch:\nREST=%q\nMCP =%q", restEnv.Content, mcpEnv.Content)
	}
	if mcpEnv.Transform != restEnv.Transform {
		t.Errorf("transform mismatch: REST=%q MCP=%q", restEnv.Transform, mcpEnv.Transform)
	}
	if mcpEnv.NormalizedURL != restEnv.NormalizedURL {
		t.Errorf("normalized_url mismatch: REST=%q MCP=%q", restEnv.NormalizedURL, mcpEnv.NormalizedURL)
	}

	// 4. Parity on denial: a denied URL must be denied on both paths.
	_, deniedURL := newDeniedEnv(t)
	restDenyEnv, restDenyErr := env.svc.Fetch(context.Background(), server.FetchRequest{
		URL:       deniedURL,
		Transform: "raw",
	})
	if restDenyErr == nil {
		t.Fatal("REST should deny the denied URL")
	}
	if restDenyErr.Code != model.CodeDenied {
		t.Errorf("REST denial code: got %q, want %q", restDenyErr.Code, model.CodeDenied)
	}
	if restDenyEnv.OK {
		t.Error("denied envelope should not be OK")
	}

	mcpDenyReq := mcp.CallToolRequest{}
	mcpDenyReq.Params.Name = "fetch"
	mcpDenyReq.Params.Arguments = map[string]any{
		"url":       deniedURL,
		"transform": "raw",
	}
	mcpDenyResult, err := c.CallTool(context.Background(), mcpDenyReq)
	if err != nil {
		t.Fatalf("MCP denied CallTool: %v", err)
	}
	if !mcpDenyResult.IsError {
		t.Error("MCP should deny the denied URL (IsError expected)")
	}
}

// --- parity via REST mux --------------------------------------------------

func TestParity_RESTHTTPAndMCP(t *testing.T) {
	// End-to-end parity: build both the REST mux (server.New) and the MCP
	// server with the same engine/fetcher/transforms, then assert the fetched
	// content is identical over both transports.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><h1>Parity</h1></body></html>"))
	}))
	t.Cleanup(upstream.Close)

	base := strings.TrimPrefix(upstream.URL, "http://")
	allowRule := config.Rule{
		Match:      "http://" + base + "/**",
		Allow:      boolPtr(true),
		Transforms: []string{"raw", "markdown"},
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
	collectors := metrics.NewCollectors()
	reg := prometheus.NewRegistry()
	collectors.MustRegister(reg)
	cfg := &config.Config{}

	// REST mux.
	mux, stop := server.New(server.Options{
		Logger:         zap.NewNop(),
		MetricsEnabled: false,
		Ready:          func() bool { return true },
		Registry:       reg,
		Config:         cfg,
		Fetcher:        fetcher,
		Engine:         engine,
		Transforms:     transforms,
		Collectors:     collectors,
	})
	t.Cleanup(stop)

	// MCP server.
	svc := &server.Service{
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transforms,
		Cfg:        cfg,
		Collectors: collectors,
		Logger:     zap.NewNop(),
	}
	mcpSrv := mcpserver.New(svc, zap.NewNop())

	targetURL := upstream.URL + "/test"

	// REST request.
	restReq := httptest.NewRequest(http.MethodPost, "/fetch", strings.NewReader(
		`{"url":"`+targetURL+`","transform":"raw"}`))
	restReq.Header.Set("Content-Type", "application/json")
	restRec := httptest.NewRecorder()
	mux.ServeHTTP(restRec, restReq)
	if restRec.Code != 200 {
		t.Fatalf("REST status: got %d, want 200", restRec.Code)
	}
	var restEnv model.Envelope
	if err := json.Unmarshal(restRec.Body.Bytes(), &restEnv); err != nil {
		t.Fatalf("unmarshal REST envelope: %v", err)
	}

	// MCP request.
	mcpClient, err := client.NewInProcessClient(mcpSrv)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() { _ = mcpClient.Close() })

	ctx := context.Background()
	if err := mcpClient.Start(ctx); err != nil {
		t.Fatalf("start client: %v", err)
	}
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "test", Version: "1.0.0"}
	if _, err := mcpClient.Initialize(ctx, initReq); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	callReq := mcp.CallToolRequest{}
	callReq.Params.Name = "fetch"
	callReq.Params.Arguments = map[string]any{
		"url":       targetURL,
		"transform": "raw",
	}
	mcpResult, err := mcpClient.CallTool(ctx, callReq)
	if err != nil {
		t.Fatalf("MCP CallTool: %v", err)
	}
	if mcpResult.IsError {
		t.Fatalf("MCP returned error: %s", toolResultText(mcpResult))
	}
	mcpEnv := parseStructuredEnvelope(t, mcpResult)

	// Assert content parity.
	if restEnv.Content != mcpEnv.Content {
		t.Errorf("content mismatch:\nREST=%q\nMCP =%q", restEnv.Content, mcpEnv.Content)
	}
}

// --- helpers --------------------------------------------------------------

// hasString checks that a JSON schema property (map[string]any) has the given
// string key-value pair (e.g. {"type": "string"}).
func hasString(prop any, key, want string) bool {
	m, ok := prop.(map[string]any)
	if !ok {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	s, ok := v.(string)
	return ok && s == want
}

// hasEnum checks that a JSON schema property has a non-empty "enum" array.
func hasEnum(prop any) bool {
	m, ok := prop.(map[string]any)
	if !ok {
		return false
	}
	v, ok := m["enum"]
	if !ok {
		return false
	}
	arr, ok := v.([]any)
	return ok && len(arr) > 0
}

// toolResultText extracts the first text content block from a CallToolResult.
func toolResultText(result *mcp.CallToolResult) string {
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

// parseStructuredEnvelope unmarshals the StructuredContent of a CallToolResult
// into a model.Envelope. Falls back to parsing the text content if structured
// content is absent.
func parseStructuredEnvelope(t *testing.T, result *mcp.CallToolResult) model.Envelope {
	t.Helper()

	if result.StructuredContent != nil {
		raw, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatalf("marshal structured content: %v", err)
		}
		var env model.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("unmarshal structured content: %v", err)
		}
		return env
	}

	// Fallback: parse the text content as JSON.
	var env model.Envelope
	if err := json.Unmarshal([]byte(toolResultText(result)), &env); err != nil {
		t.Fatalf("unmarshal text content as envelope: %v", err)
	}
	return env
}
