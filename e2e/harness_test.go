// Package e2e runs end-to-end tests against a real keyhole binary.
//
// Tests build the binary once (TestMain), start subprocesses with generated
// configs, and exercise REST + MCP Streamable HTTP over the loopback network.
// Upstream content is served by httptest in-process so no external network is
// required (unit-test style isolation with a real process boundary).
package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// keyholeBin is the absolute path to the binary built by TestMain.
var keyholeBin string

// startupDeadline bounds how long startProc waits for the server to become
// healthy. Default 30s: freshly-built binaries can incur multi-second (worst
// case tens of seconds) first-exec code-signature validation on macOS
// endpoint-security setups, and the binary is built into a fresh temp path on
// every `go test` run. Override with KEYHOLE_E2E_STARTUP_DEADLINE (seconds).
var startupDeadline = 30 * time.Second

func TestMain(m *testing.M) {
	if v := os.Getenv("KEYHOLE_E2E_STARTUP_DEADLINE"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			startupDeadline = time.Duration(secs) * time.Second
		}
	}
	root := repoRoot()
	dir, err := os.MkdirTemp("", "keyhole-e2e-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: mkdir: %v\n", err)
		os.Exit(1)
	}
	keyholeBin = filepath.Join(dir, "keyhole")
	cmd := exec.Command("go", "build", "-o", keyholeBin, "./cmd/keyhole")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: build keyhole: %v\n%s\n", err, out)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	// Warm the binary: execute it once before any test so one-time OS-level
	// validation of the freshly built file (code signature / endpoint-security
	// scanning) lands here, with a generous timeout, instead of inside each
	// test's startup window.
	warm := exec.Command(keyholeBin, "--help")
	warm.Stdout = nil
	warm.Stderr = nil
	if err := warm.Run(); err != nil {
		// Non-fatal: any real defect will surface with diagnostics in the
		// tests themselves; --help merely exits non-zero via flag parsing.
		fmt.Fprintf(os.Stderr, "e2e: warmup exec: %v\n", err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// repoRoot returns the absolute path to the module root (parent of e2e/).
func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("e2e: runtime.Caller failed")
	}
	// file is .../e2e/harness_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

// freePort binds 127.0.0.1:0, returns the port, and closes the listener.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// writeConfig writes content into t.TempDir and returns the path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// serverProc is a running keyhole subprocess.
type serverProc struct {
	BaseURL string // e.g. http://127.0.0.1:12345
	cmd     *exec.Cmd
	logBuf  *bytes.Buffer
	// exited receives the child's Wait result exactly once; the goroutine is
	// started by startProc so both early-exit detection and stop() share it.
	exited chan error
}

// startREST launches keyhole in REST mode with the given config path and waits
// until /healthz returns 200 (or times out).
func startREST(t *testing.T, configPath string, listen string) *serverProc {
	t.Helper()
	return startProc(t, configPath, listen, false, false)
}

// startMCPHTTP launches keyhole with --mcp (Streamable HTTP). listen is the
// [mcp] listen address already embedded in the config; health is checked on
// that address via a non-MCP path... MCP has no /healthz, so we wait until
// the port accepts TCP and (optionally) returns any HTTP response.
func startMCPHTTP(t *testing.T, configPath string, listen string) *serverProc {
	t.Helper()
	return startProc(t, configPath, listen, true, true)
}

// startMCPHTTPFromConfig launches the MCP Streamable HTTP transport without
// --mcp, relying on `[mcp] enabled = true` in the config. This is the
// documented config-only activation path ("MCP replaces REST"), so readiness
// is the listen-port probe rather than the REST /healthz poll.
func startMCPHTTPFromConfig(t *testing.T, configPath string, listen string) *serverProc {
	t.Helper()
	return startProc(t, configPath, listen, false, true)
}

// startProc launches keyhole with mcpFlag prepended when set, then waits for
// readiness: mcpWait probes the MCP listen port (MCP has no /healthz), a false
// value polls REST /healthz.
func startProc(t *testing.T, configPath, listen string, mcpFlag, mcpWait bool) *serverProc {
	t.Helper()
	args := []string{"--config", configPath}
	if mcpFlag {
		args = append([]string{"--mcp"}, args...)
	}
	var logBuf bytes.Buffer
	cmd := exec.Command(keyholeBin, args...)
	cmd.Stdout = &logBuf
	cmd.Stderr = &logBuf
	// Ensure dummy env for example-style profiles is not required; tests use
	// configs without ${ENV} references.
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start keyhole: %v", err)
	}
	proc := &serverProc{
		BaseURL: "http://" + listen,
		cmd:     cmd,
		logBuf:  &logBuf,
		exited:  make(chan error, 1),
	}
	// exited fires when the child terminates; ProcessState is only populated
	// by Wait, so a dedicated goroutine is required for early-exit detection.
	go func() { proc.exited <- cmd.Wait() }()
	t.Cleanup(func() {
		proc.stop(t)
	})

	deadline := time.Now().Add(startupDeadline)
	if mcpWait {
		// Wait until the listen port accepts connections.
		addr := strings.TrimPrefix(listen, "http://")
		if !strings.Contains(addr, ":") {
			addr = listen
		}
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return proc
			}
			select {
			case err := <-proc.exited:
				t.Fatalf("keyhole exited early (err=%v):\n%s", err, logBuf.String())
			default:
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for MCP listen %s:\n%s", listen, logBuf.String())
	}

	// REST: poll /healthz.
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for time.Now().Before(deadline) {
		resp, err := client.Get(proc.BaseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return proc
			}
		}
		select {
		case err := <-proc.exited:
			t.Fatalf("keyhole exited early (err=%v):\n%s", err, logBuf.String())
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for /healthz on %s:\n%s", proc.BaseURL, logBuf.String())
	return proc
}

func (p *serverProc) stop(t *testing.T) {
	t.Helper()
	if p.cmd.Process == nil {
		return
	}
	// Prefer graceful SIGTERM so "shutdown complete" path is exercised. A
	// clean SIGINT exit yields Wait() == nil (exit code 0); anything else is
	// a regression in the shutdown contract.
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-p.exited:
		if err != nil {
			t.Errorf("keyhole unclean exit after SIGINT: %v\nlogs:\n%s", err, p.logBuf.String())
		}
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
		t.Errorf("keyhole did not exit within 10s of SIGINT; forced kill\nlogs:\n%s", p.logBuf.String())
	}
}

// restConfig builds a minimal deny-by-default config that allows the given
// upstream host pattern (e.g. "127.0.0.1:1234") for raw/markdown/article.
func restConfig(listen, apiKey, upstreamHost string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "default_policy = \"deny\"\n")
	fmt.Fprintf(&b, "[server]\nlisten = %q\n", listen)
	if apiKey != "" {
		fmt.Fprintf(&b, "api_key = %q\n", apiKey)
	}
	fmt.Fprintf(&b, "reload = false\n")
	fmt.Fprintf(&b, "allow_client_auth_profile = false\n")
	fmt.Fprintf(&b, "[server.rate]\nrps = 0\nburst = 0\n")
	fmt.Fprintf(&b, "[logging]\nlevel = \"error\"\nformat = \"json\"\noutput = \"stdout\"\n")
	fmt.Fprintf(&b, "[metrics]\nenabled = true\npath = \"/metrics\"\n")
	fmt.Fprintf(&b, "[network]\ntimeout = \"5s\"\nmax_size = 1048576\nmax_redirects = 5\n")
	fmt.Fprintf(&b, "user_agent = \"keyhole-e2e\"\nallow_private = true\nrespect_robots = false\npin_dns = false\n")
	fmt.Fprintf(&b, "[cache]\nenabled = false\n")
	fmt.Fprintf(&b, "[mcp]\nenabled = false\n")
	fmt.Fprintf(&b, "[output]\nmax_chars = 100000\n")
	fmt.Fprintf(&b, "[youtube]\ntranscript_language = \"en\"\ninclude_timestamps = false\nmax_chars = 50000\n")
	fmt.Fprintf(&b, "[office]\npandoc_path = \"pandoc\"\ntimeout = \"10s\"\n")
	if upstreamHost != "" {
		fmt.Fprintf(&b, "\n[[rules]]\n")
		fmt.Fprintf(&b, "match = \"http://%s/**\"\n", upstreamHost)
		fmt.Fprintf(&b, "allow = true\n")
		fmt.Fprintf(&b, "transforms = [\"raw\", \"markdown\", \"article\"]\n")
	}
	return b.String()
}

// mcpHTTPConfig is like restConfig but enables MCP Streamable HTTP on listen.
func mcpHTTPConfig(listen, apiKey, upstreamHost string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "default_policy = \"deny\"\n")
	fmt.Fprintf(&b, "[server]\nlisten = \":0\"\n") // unused in --mcp mode
	if apiKey != "" {
		fmt.Fprintf(&b, "api_key = %q\n", apiKey)
	}
	fmt.Fprintf(&b, "reload = false\n")
	fmt.Fprintf(&b, "[logging]\nlevel = \"error\"\nformat = \"json\"\noutput = \"stdout\"\n")
	fmt.Fprintf(&b, "[metrics]\nenabled = false\n")
	fmt.Fprintf(&b, "[network]\ntimeout = \"5s\"\nmax_size = 1048576\nallow_private = true\n")
	fmt.Fprintf(&b, "[cache]\nenabled = false\n")
	fmt.Fprintf(&b, "[mcp]\nenabled = true\ntransport = \"http\"\nlisten = %q\n", listen)
	fmt.Fprintf(&b, "[output]\nmax_chars = 100000\n")
	fmt.Fprintf(&b, "[youtube]\ntranscript_language = \"en\"\nmax_chars = 50000\n")
	fmt.Fprintf(&b, "[office]\npandoc_path = \"pandoc\"\ntimeout = \"10s\"\n")
	if upstreamHost != "" {
		fmt.Fprintf(&b, "\n[[rules]]\n")
		fmt.Fprintf(&b, "match = \"http://%s/**\"\n", upstreamHost)
		fmt.Fprintf(&b, "allow = true\n")
		fmt.Fprintf(&b, "transforms = [\"raw\", \"markdown\"]\n")
	}
	return b.String()
}

// hostPort strips the scheme from an httptest URL, returning host:port.
func hostPort(rawURL string) string {
	u := strings.TrimPrefix(rawURL, "http://")
	u = strings.TrimPrefix(u, "https://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

// postFetchJSON posts a JSON body to /fetch and returns status + decoded map.
func postFetchJSON(t *testing.T, baseURL, apiKey string, body any) (int, map[string]any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/fetch", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /fetch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var m map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal %q: %v", raw, err)
		}
	}
	return resp.StatusCode, m
}

// getJSON issues a GET and decodes a JSON object body.
func getJSON(t *testing.T, url, apiKey string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	return resp.StatusCode, m
}

// mcpHTTPSession is a minimal raw JSON-RPC client for the Streamable HTTP
// transport. It exists (rather than importing a generated client) so the e2e
// suite asserts the wire contract the binary actually serves: session header
// handling, both response encodings, and the final tool envelope.
type mcpHTTPSession struct {
	t        *testing.T
	client   *http.Client
	endpoint string
	apiKey   string
	session  string
	nextID   int
}

func newMCPHTTPSession(t *testing.T, baseURL, apiKey string) *mcpHTTPSession {
	t.Helper()
	return &mcpHTTPSession{
		t:        t,
		client:   &http.Client{Timeout: 10 * time.Second},
		endpoint: baseURL + "/mcp",
		apiKey:   apiKey,
	}
}

// post sends one JSON-RPC message and returns status, headers, and raw body.
func (s *mcpHTTPSession) post(payload map[string]any) (int, http.Header, []byte) {
	s.t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		s.t.Fatalf("marshal JSON-RPC: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, s.endpoint, bytes.NewReader(data))
	if err != nil {
		s.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The MCP spec requires clients to accept both response encodings.
	req.Header.Set("Accept", "application/json, text/event-stream")
	if s.apiKey != "" {
		req.Header.Set("X-API-Key", s.apiKey)
	}
	if s.session != "" {
		req.Header.Set("Mcp-Session-Id", s.session)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.t.Fatalf("POST %s: %v", s.endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// The transport issues the session ID on the initialize response and
	// requires it back on every subsequent request.
	if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
		s.session = id
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, resp.Header, raw
}

// call sends a JSON-RPC request and returns its decoded result object.
func (s *mcpHTTPSession) call(method string, params any) map[string]any {
	s.t.Helper()
	s.nextID++
	payload := map[string]any{"jsonrpc": "2.0", "id": s.nextID, "method": method}
	if params != nil {
		payload["params"] = params
	}
	status, header, raw := s.post(payload)
	if status != http.StatusOK {
		s.t.Fatalf("%s status = %d body=%s", method, status, raw)
	}
	msg := decodeMCPBody(s.t, header.Get("Content-Type"), raw)
	if rpcErr, ok := msg["error"]; ok {
		s.t.Fatalf("%s JSON-RPC error: %v", method, rpcErr)
	}
	result, _ := msg["result"].(map[string]any)
	if result == nil {
		s.t.Fatalf("%s result missing: %s", method, raw)
	}
	return result
}

// notify sends a JSON-RPC notification (no id); the transport answers 202.
func (s *mcpHTTPSession) notify(method string) {
	s.t.Helper()
	status, _, raw := s.post(map[string]any{"jsonrpc": "2.0", "method": method})
	if status != http.StatusAccepted {
		s.t.Fatalf("%s notification status = %d body=%s", method, status, raw)
	}
}

// decodeMCPBody parses a Streamable HTTP response body in either allowed
// encoding: a bare JSON object, or one/more SSE events whose data lines carry
// the JSON-RPC message.
func decodeMCPBody(t *testing.T, contentType string, raw []byte) map[string]any {
	t.Helper()
	if strings.HasPrefix(contentType, "text/event-stream") {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			var msg map[string]any
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if err := json.Unmarshal([]byte(data), &msg); err != nil {
				t.Fatalf("decode SSE data %q: %v", data, err)
			}
			return msg
		}
		t.Fatalf("no SSE data event in body %q", raw)
	}
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("decode JSON response %q: %v", raw, err)
	}
	return msg
}

// mcpInitializeParams is the params object a client sends for initialize.
func mcpInitializeParams() map[string]any {
	return map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "keyhole-e2e", "version": "1.0.0"},
	}
}

// mcpFetchArgs builds tools/call params for the fetch tool.
func mcpFetchArgs(url, transform string) map[string]any {
	return map[string]any{
		"name": "fetch",
		"arguments": map[string]any{
			"url":       url,
			"transform": transform,
		},
	}
}

// assertFetchEnvelope extracts structuredContent from a tools/call result and
// fails unless it is a successful fetch envelope whose content contains want.
func assertFetchEnvelope(t *testing.T, result map[string]any, want string) {
	t.Helper()
	if isErr, _ := result["isError"].(bool); isErr {
		t.Fatalf("tools/call isError=true: %v", result)
	}
	envelope, _ := result["structuredContent"].(map[string]any)
	if envelope == nil {
		t.Fatalf("structuredContent missing: %v", result)
	}
	if envelope["ok"] != true {
		t.Fatalf("envelope ok = %v, want true", envelope["ok"])
	}
	content, _ := envelope["content"].(string)
	if !strings.Contains(content, want) {
		t.Fatalf("envelope content %q missing %q", content, want)
	}
}
