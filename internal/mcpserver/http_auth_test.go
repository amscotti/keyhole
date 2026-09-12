package mcpserver_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/amscotti/keyhole/internal/mcpserver"
	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/server"
)

// TestStreamableHTTP_ProtectAPIKey proves the MCP HTTP handler, when wrapped
// with server.Protect the way ServeStreamableHTTP does, rejects missing keys
// and admits correct ones. This covers the production auth path without
// starting a full blocking server.
func TestStreamableHTTP_ProtectAPIKey(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)
	raw := mcpserver.NewStreamableHTTPHandler(env.svc, zap.NewNop())
	h, stop := server.Protect(raw, "secret", 0, 0, metrics.NewCollectors(), zap.NewNop())
	t.Cleanup(stop)

	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)

	// Missing key. Do not drain the body: a GET to the MCP endpoint with an
	// admitted key opens a long-lived SSE stream, so only the status/headers
	// are relevant and the body is closed immediately.
	resp, err := http.Get(ts.URL + mcpserver.MCPHTTPEndpoint)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing key status = %d, want 401", resp.StatusCode)
	}

	// Good key: admitted (not 401). With the status-capture wrapper correctly
	// exposing http.Flusher, this returns 200 text/event-stream rather than
	// 405 "Streaming unsupported".
	req, _ := http.NewRequest(http.MethodGet, ts.URL+mcpserver.MCPHTTPEndpoint, nil)
	req.Header.Set("X-API-Key", "secret")
	req.Header.Set("Accept", "text/event-stream")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET with key: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatal("expected admission with correct API key")
	}
	if resp.StatusCode == http.StatusMethodNotAllowed {
		t.Fatalf("GET with key = %d %q; the access-log wrapper must preserve http.Flusher so Streamable HTTP can stream",
			resp.StatusCode, resp.Status)
	}
}

// TestCallTool_DeniedErrorPrefix ensures policy denials are returned as tool
// errors whose text starts with "denied:" so models can branch on free text.
func TestCallTool_DeniedErrorPrefix(t *testing.T) {
	env, deniedURL := newDeniedEnv(t)
	c := mcpClient(t, env.svc)

	req := mcp.CallToolRequest{}
	req.Params.Name = "fetch"
	req.Params.Arguments = map[string]any{
		"url":       deniedURL,
		"transform": "raw",
	}
	result, err := c.CallTool(t.Context(), req)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected tool error for denied URL")
	}
	text := toolResultText(result)
	if !strings.HasPrefix(text, "denied:") {
		t.Fatalf("error text = %q, want denied: prefix", text)
	}
}
