package e2e_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// stdioRPCDeadline bounds waiting for one JSON-RPC response on stdout.
const stdioRPCDeadline = 15 * time.Second

// mcpStdioConfig mirrors restConfig but logs at info level: with the stdio
// transport the logger's default stdout must be redirected to stderr, and a
// quiet logger would make that contract untestable. [mcp] is activated by the
// --mcp flag, so transport stays at its stdio default.
func mcpStdioConfig(upstreamHost string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "default_policy = \"deny\"\n")
	fmt.Fprintf(&b, "[server]\nlisten = \":0\"\n") // unused in stdio mode
	fmt.Fprintf(&b, "reload = false\n")
	fmt.Fprintf(&b, "[logging]\nlevel = \"info\"\nformat = \"json\"\noutput = \"stdout\"\n")
	fmt.Fprintf(&b, "[metrics]\nenabled = false\n")
	fmt.Fprintf(&b, "[network]\ntimeout = \"5s\"\nmax_size = 1048576\nmax_redirects = 5\n")
	fmt.Fprintf(&b, "user_agent = \"keyhole-e2e\"\nallow_private = true\nrespect_robots = false\npin_dns = false\n")
	fmt.Fprintf(&b, "[cache]\nenabled = false\n")
	fmt.Fprintf(&b, "[mcp]\nenabled = false\n")
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

// syncBuffer is a bytes.Buffer safe for the exec copy goroutine and the test
// goroutine to use concurrently. serverProc can read its buffer only after
// Wait, but the stdio test reports stderr from failure paths while the child
// may still be running.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// stdioProc is a running keyhole --mcp stdio subprocess. stdout is consumed
// line-by-line into lines; one line is one newline-delimited JSON-RPC message
// per the MCP stdio framing.
type stdioProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan stdioLine
	stderr *syncBuffer
	// stopped guards the single Wait: a test may stop explicitly to assert on
	// stderr, then t.Cleanup stops again (idempotent).
	stopped bool
}

type stdioLine struct {
	raw string
	err error
}

// startStdio launches keyhole with --mcp (stdio transport) and returns the
// process handle. The binary is the one built once by TestMain.
func startStdio(t *testing.T, configPath string) *stdioProc {
	t.Helper()
	cmd := exec.Command(keyholeBin, "--mcp", "--config", configPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start keyhole --mcp: %v", err)
	}
	p := &stdioProc{
		cmd:    cmd,
		stdin:  stdin,
		lines:  make(chan stdioLine, 256),
		stderr: stderr,
	}
	// Reader goroutine: scan stdout into the channel, then close it so readers
	// can distinguish "no more output" (process exited) from a stalled read.
	go func() {
		defer close(p.lines)
		sc := bufio.NewScanner(stdout)
		// A tools/call response is a full fetch envelope; allow well past the
		// scanner's 64 KiB default so a large but valid response is not
		// misreported as a framing failure.
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			p.lines <- stdioLine{raw: sc.Text()}
		}
		if err := sc.Err(); err != nil {
			p.lines <- stdioLine{err: err}
		}
	}()
	t.Cleanup(func() { p.stop(t) })
	return p
}

// send writes one JSON-RPC request, newline-terminated.
func (p *stdioProc) send(t *testing.T, id int, method string, params any) {
	t.Helper()
	msg := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	p.write(t, method, msg)
}

// notify writes one JSON-RPC notification (no id).
func (p *stdioProc) notify(t *testing.T, method string) {
	t.Helper()
	p.write(t, method, map[string]any{"jsonrpc": "2.0", "method": method})
}

func (p *stdioProc) write(t *testing.T, method string, msg map[string]any) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal %s: %v", method, err)
	}
	if _, err := p.stdin.Write(append(data, '\n')); err != nil {
		t.Fatalf("write %s: %v\nstderr:\n%s", method, err, p.stderr.String())
	}
}

// readResponse consumes validated JSON-RPC lines until the response with the
// given id arrives, returning its result object. Every line read is checked by
// parseJSONRPC, so a stray log line on stdout fails at the line that carries
// it — the core stdio framing contract.
func (p *stdioProc) readResponse(t *testing.T, id int) map[string]any {
	t.Helper()
	deadline := time.After(stdioRPCDeadline)
	for {
		select {
		case ln, ok := <-p.lines:
			if !ok {
				t.Fatalf("keyhole closed stdout before response id=%d\nstderr:\n%s", id, p.stderr.String())
			}
			if ln.err != nil {
				t.Fatalf("read stdout before response id=%d: %v\nstderr:\n%s", id, ln.err, p.stderr.String())
			}
			if strings.TrimSpace(ln.raw) == "" {
				continue
			}
			msg, err := parseJSONRPC(ln.raw)
			if err != nil {
				t.Fatalf("stdout is not pure JSON-RPC: %v\nstderr:\n%s", err, p.stderr.String())
			}
			gotID, _ := msg["id"].(float64)
			if int(gotID) != id {
				continue
			}
			if rpcErr, ok := msg["error"]; ok {
				t.Fatalf("JSON-RPC error for id=%d: %v", id, rpcErr)
			}
			result, _ := msg["result"].(map[string]any)
			if result == nil {
				t.Fatalf("response id=%d missing result: %s", id, ln.raw)
			}
			return result
		case <-deadline:
			_ = p.cmd.Process.Kill()
			t.Fatalf("timeout waiting for JSON-RPC response id=%d\nstderr:\n%s", id, p.stderr.String())
		}
	}
}

// parseJSONRPC asserts a stdout line is a JSON-RPC 2.0 object and returns it.
func parseJSONRPC(line string) (map[string]any, error) {
	var msg map[string]any
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return nil, fmt.Errorf("not JSON (%q): %w", line, err)
	}
	if msg["jsonrpc"] != "2.0" {
		return nil, fmt.Errorf("missing jsonrpc 2.0 (%q)", line)
	}
	return msg, nil
}

// stop closes stdin (ending the MCP session) and drains stdout to EOF so every
// remaining line is validated and the child is reaped. A watchdog kills a hung
// child so a regression cannot wedge the suite. Safe to call more than once.
func (p *stdioProc) stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	if p.cmd.Process == nil {
		return
	}
	_ = p.stdin.Close()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ln, ok := <-p.lines:
			if !ok {
				if err := p.cmd.Wait(); err != nil {
					t.Errorf("keyhole stdio unclean exit: %v\nstderr:\n%s", err, p.stderr.String())
				}
				return
			}
			if ln.err != nil {
				t.Errorf("reading stdout: %v", ln.err)
				continue
			}
			if strings.TrimSpace(ln.raw) == "" {
				continue
			}
			if _, err := parseJSONRPC(ln.raw); err != nil {
				t.Errorf("stdout is not pure JSON-RPC: %v", err)
			}
		case <-timeout:
			_ = p.cmd.Process.Kill()
			t.Errorf("keyhole did not exit within 10s of stdin close; forced kill\nstderr:\n%s", p.stderr.String())
			// Keep draining: the scanner reaches EOF/error once the process
			// dies and the channel closes.
			timeout = nil
		}
	}
}

// TestE2E_MCPStdio drives the real binary over the stdio transport:
// initialize -> tools/list -> fetch tools/call, strictly newline-delimited
// JSON-RPC. It pins three contracts: stdout carries nothing but JSON-RPC
// (even though the config logs to stdout), the tool returns the shared fetch
// envelope, and the process exits cleanly when stdin closes.
func TestE2E_MCPStdio(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html><body><h1>Stdio Title</h1><p>Hello stdio</p></body></html>")
	}))
	t.Cleanup(upstream.Close)

	cfg := mcpStdioConfig(hostPort(upstream.URL))
	path := writeConfig(t, cfg)
	proc := startStdio(t, path)

	// initialize
	proc.send(t, 1, "initialize", mcpInitializeParams())
	initResult := proc.readResponse(t, 1)
	serverInfo, _ := initResult["serverInfo"].(map[string]any)
	if serverInfo["name"] != "keyhole" {
		t.Fatalf("serverInfo = %v, want name keyhole", serverInfo)
	}
	proc.notify(t, "notifications/initialized")

	// tools/list
	proc.send(t, 2, "tools/list", map[string]any{})
	listResult := proc.readResponse(t, 2)
	tools, _ := listResult["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools = %v, want exactly the fetch tool", listResult["tools"])
	}
	tool, _ := tools[0].(map[string]any)
	if tool["name"] != "fetch" {
		t.Fatalf("tool name = %v, want fetch", tool["name"])
	}

	// tools/call
	proc.send(t, 3, "tools/call", mcpFetchArgs(upstream.URL+"/page", "raw"))
	callResult := proc.readResponse(t, 3)
	assertFetchEnvelope(t, callResult, "Stdio Title")
	// Text fallback: clients that predate structuredContent read the content
	// off content[0].text.
	contentList, _ := callResult["content"].([]any)
	if len(contentList) == 0 {
		t.Fatalf("tools/call content missing: %v", callResult)
	}
	first, _ := contentList[0].(map[string]any)
	if text, _ := first["text"].(string); !strings.Contains(text, "Stdio Title") {
		t.Fatalf("text fallback %q missing fetched content", text)
	}

	// Closing stdin ends the session. stop() drains and validates every
	// remaining stdout line before reaping, then stderr proves the info-level
	// startup log was redirected away from the protocol channel.
	proc.stop(t)
	if !strings.Contains(proc.stderr.String(), "keyhole starting") {
		t.Fatalf("expected startup log on stderr, got:\n%s", proc.stderr.String())
	}
}
