package e2e_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestE2E_MCPHTTP_APIKeyGate verifies that Streamable HTTP MCP applies the same
// X-API-Key ingress control as REST — missing/wrong keys get 401; a correct
// key is admitted past the gate (MCP protocol may still return 4xx for a bare
// GET, which is fine).
func TestE2E_MCPHTTP_APIKeyGate(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>mcp</body></html>")
	}))
	t.Cleanup(upstream.Close)

	const apiKey = "mcp-e2e-key"
	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	host := hostPort(upstream.URL)
	cfg := mcpHTTPConfig(listen, apiKey, host)
	path := writeConfig(t, cfg)
	srv := startMCPHTTP(t, path, listen)

	endpoint := srv.BaseURL + "/mcp"
	client := &http.Client{Timeout: 5 * time.Second}

	// Missing key.
	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatalf("GET without key: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing key status = %d, want 401 (logs=%s)", resp.StatusCode, srv.logBuf.String())
	}

	// Wrong key.
	req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	req.Header.Set("X-API-Key", "nope")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET wrong key: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong key status = %d, want 401", resp.StatusCode)
	}

	// Correct key — must not be 401. Bare GET may be 400/405/406 from the MCP
	// transport; anything other than 401 proves the gate accepted the key.
	req, _ = http.NewRequest(http.MethodGet, endpoint, nil)
	req.Header.Set("X-API-Key", apiKey)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET with key: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("good key still 401; body=%s logs=%s", body, srv.logBuf.String())
	}
}

// TestE2E_MCPHTTP_NoAPIKeyOpen admits unauthenticated MCP when api_key is empty
// (local-agent style). The endpoint must respond without 401.
func TestE2E_MCPHTTP_NoAPIKeyOpen(t *testing.T) {
	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	cfg := mcpHTTPConfig(listen, "", "")
	path := writeConfig(t, cfg)
	srv := startMCPHTTP(t, path, listen)

	resp, err := http.Get(srv.BaseURL + "/mcp")
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("empty api_key should not require auth; got 401 logs=%s", srv.logBuf.String())
	}
}

// TestE2E_MCPHTTP_ToolCall drives initialize -> tools/list -> tools/call
// through the real binary over Streamable HTTP with the X-API-Key gate in
// front, asserting the shared fetch envelope comes back. It also pins the
// http.Flusher fix: GET /mcp with Accept: text/event-stream and a valid key
// must open the SSE listening stream (200), not degrade to 405 because the
// access-log middleware's response wrapper dropped the Flusher interface.
func TestE2E_MCPHTTP_ToolCall(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><body><h1>HTTP Title</h1><p>Hello http</p></body></html>")
	}))
	t.Cleanup(upstream.Close)

	const apiKey = "mcp-e2e-key"
	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	cfg := mcpHTTPConfig(listen, apiKey, hostPort(upstream.URL))
	path := writeConfig(t, cfg)
	srv := startMCPHTTP(t, path, listen)

	sess := newMCPHTTPSession(t, srv.BaseURL, apiKey)

	initResult := sess.call("initialize", mcpInitializeParams())
	serverInfo, _ := initResult["serverInfo"].(map[string]any)
	if serverInfo["name"] != "keyhole" {
		t.Fatalf("serverInfo = %v, want name keyhole", serverInfo)
	}
	sess.notify("notifications/initialized")

	listResult := sess.call("tools/list", map[string]any{})
	tools, _ := listResult["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools = %v, want exactly the fetch tool", listResult["tools"])
	}
	if tool, _ := tools[0].(map[string]any); tool["name"] != "fetch" {
		t.Fatalf("tool = %v, want fetch", tools[0])
	}

	callResult := sess.call("tools/call", mcpFetchArgs(upstream.URL+"/page", "raw"))
	assertFetchEnvelope(t, callResult, "HTTP Title")

	// SSE listening stream. The handler keeps the connection open, so close as
	// soon as the status line arrives; the client disconnect cancels the
	// handler context and lets graceful shutdown proceed.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sess.endpoint, nil)
	if err != nil {
		t.Fatalf("new GET: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("GET /mcp status = %d, want 200 (did the middleware wrapper lose http.Flusher?); body=%s logs=%s",
			resp.StatusCode, body, srv.logBuf.String())
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		_ = resp.Body.Close()
		t.Fatalf("GET /mcp content-type = %q, want text/event-stream", ct)
	}
	_ = resp.Body.Close()
}

// TestE2E_MCPHTTP_ConfigOnly pins the documented "MCP replaces REST"
// activation: [mcp] enabled = true + transport = "http" starts MCP without any
// --mcp flag, and the same process serves no REST surface — /fetch and
// /healthz are absent from the MCP-only listener.
func TestE2E_MCPHTTP_ConfigOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><body><h1>Config Title</h1></body></html>")
	}))
	t.Cleanup(upstream.Close)

	port := freePort(t)
	listen := "127.0.0.1:" + itoa(port)
	cfg := mcpHTTPConfig(listen, "", hostPort(upstream.URL))
	path := writeConfig(t, cfg)
	// No --mcp argument: the config alone must activate the transport.
	srv := startMCPHTTPFromConfig(t, path, listen)

	sess := newMCPHTTPSession(t, srv.BaseURL, "")
	if initResult := sess.call("initialize", mcpInitializeParams()); initResult["serverInfo"] == nil {
		t.Fatalf("initialize result missing serverInfo: %v", initResult)
	}
	sess.notify("notifications/initialized")

	listResult := sess.call("tools/list", map[string]any{})
	tools, _ := listResult["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools = %v, want exactly the fetch tool", listResult["tools"])
	}

	callResult := sess.call("tools/call", mcpFetchArgs(upstream.URL+"/page", "raw"))
	assertFetchEnvelope(t, callResult, "Config Title")

	// REST is not mounted alongside MCP: the mux only knows /mcp, so the REST
	// surface answers 404/405 rather than serving /fetch.
	client := &http.Client{Timeout: 5 * time.Second}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, err := http.NewRequest(method, srv.BaseURL+"/fetch", nil)
		if err != nil {
			t.Fatalf("new %s /fetch: %v", method, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s /fetch: %v", method, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s /fetch status = %d, want MCP-only 404/405; logs=%s", method, resp.StatusCode, srv.logBuf.String())
		}
	}
}
