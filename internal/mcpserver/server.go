// Package mcpserver exposes Keyhole's fetch service as an MCP tool so that AI
// agents (Claude Desktop, Hermes, custom clients) can call it directly over the
// Model Context Protocol.
//
// MCP is a transport, not a separate product: the tool handler delegates to the
// same shared Service.Fetch pipeline that the REST handler uses, so policy
// (allow/deny rules), transforms, caching, and SSRF protection are identical
// across REST and MCP. A policy denial surfaces as a tool error the model can
// read and react to.
//
// Two transports are supported, selected by [mcp] transport:
//   - "stdio" (default): JSON-RPC over stdin/stdout, for local agents.
//   - "http": MCP Streamable HTTP, served at the /mcp endpoint, for remote or
//     long-lived clients. Enabled by [mcp] transport = "http" with [mcp] listen.
//     Streamable HTTP reuses the same API-key and rate-limit ingress as REST
//     /fetch so enabling remote MCP does not bypass transport auth.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/amscotti/keyhole/internal/authprofile"
	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/model"
	"github.com/amscotti/keyhole/internal/server"
)

// fetchToolDescription is the tool description as seen by the LLM. It is written
// for a model audience: what the tool does, that content may be truncated, and
// that policy applies (some URLs may be denied).
const fetchToolDescription = `Fetch a URL and return its content shaped for an LLM context window.

Returns clean content instead of raw HTML:
- "raw": the response body verbatim.
- "markdown": the full page converted to Markdown.
- "article": reader-mode extraction (main text, stripped of navigation and ads) as Markdown.
- "youtube": video metadata and transcript for YouTube URLs.
- "office": converts .docx/.pptx/.xlsx to Markdown via pandoc.

The response is a JSON envelope with the content, provenance (original and final URLs),
content type, and a "truncated" flag that is true when the content was cut to fit a
max_chars limit. Policy is enforced: some URLs may be denied by the server's configuration.
When a fetch is denied the result is an error message describing why.`

// ServerName is the MCP server name advertised during the initialize handshake.
const ServerName = "keyhole"

// ServerVersion is the MCP server version advertised during the initialize handshake.
const ServerVersion = "0.1.0"

// New builds an MCP server exposing a single "fetch" tool backed by svc. The
// returned *mcpserver.MCPServer can be served over stdio or HTTP. A nil logger
// is normalized to a no-op logger (mirroring server.New) so the denial path —
// which logs — cannot panic on callers that omit it.
func New(svc *server.Service, logger *zap.Logger) *mcpserver.MCPServer {
	if logger == nil {
		logger = zap.NewNop()
	}
	s := mcpserver.NewMCPServer(ServerName, ServerVersion,
		mcpserver.WithToolCapabilities(false),
	)

	tool := mcp.NewTool("fetch",
		mcp.WithDescription(fetchToolDescription),
		// The tool only reads from the network and never mutates local state.
		// Clients use the annotations to decide whether to prompt; without
		// them a fetch can look destructive.
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("url",
			mcp.Required(),
			mcp.Description("The URL to fetch."),
		),
		mcp.WithString("transform",
			mcp.Description("How to process the fetched content. Defaults to \"raw\"."),
			mcp.Enum("raw", "markdown", "article", "youtube", "office"),
		),
		mcp.WithInteger("max_chars",
			mcp.Description("Maximum number of characters (runes) in the returned content. "+
				"When exceeded the content is truncated and \"truncated\" is set to true in the envelope. "+
				"If omitted, the server default applies."),
		),
		mcp.WithString("auth_profile",
			mcp.Description("Optional named auth profile to apply (sends headers like Authorization). "+
				"Only available when the server enables client-selected profiles and the matched rule "+
				"does not attach a different profile; otherwise the request fails with an error rather "+
				"than silently fetching without the requested credentials."),
		),
	)

	s.AddTool(tool, makeFetchHandler(svc, logger))

	return s
}

// makeFetchHandler returns the MCP tool handler that delegates to the shared
// Service.Fetch pipeline and wraps the result in an MCP CallToolResult.
func makeFetchHandler(svc *server.Service, logger *zap.Logger) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rawURL, err := req.RequireString("url")
		if err != nil {
			// Count malformed calls like REST records its parse failures, so
			// an MCP-only deployment can see bad-call volume on /metrics.
			if svc.Collectors != nil {
				svc.Collectors.RecordRequest("unknown", http.StatusBadRequest)
			}
			return mcp.NewToolResultError(`"url" is required`), nil
		}

		transform := req.GetString("transform", "raw")
		maxChars := req.GetInt("max_chars", 0)
		authProfile := req.GetString("auth_profile", "")

		envelope, ferr := svc.Fetch(ctx, server.FetchRequest{
			URL:         rawURL,
			Transform:   transform,
			MaxChars:    maxChars,
			AuthProfile: authProfile,
		})
		if ferr != nil {
			logger.Debug("mcp fetch denied or failed",
				zap.String("url", authprofile.SanitizeURL(rawURL)),
				zap.String("code", ferr.Code),
				zap.String("message", ferr.Message),
			)
			// MCP traffic counts in keyhole_requests_total too — the README
			// documents the metric as "total fetch requests", and an MCP-only
			// deployment must not be invisible to dashboards.
			if svc.Collectors != nil {
				svc.Collectors.RecordRequest(
					svc.SanitizeTransform(transform),
					model.HTTPStatus(ferr.Code),
				)
			}
			return mcp.NewToolResultError(formatToolError(ferr)), nil
		}

		if svc.Collectors != nil {
			svc.Collectors.RecordRequest(svc.SanitizeTransform(transform), http.StatusOK)
		}

		// Return the envelope as both structured content (for clients that
		// support it) and a text fallback (for backward compatibility). The
		// text is the content itself so an LLM reading the text content gets
		// the useful payload directly.
		text := envelope.Content
		if text == "" {
			text = fmt.Sprintf("(empty content from %s)", envelope.FinalURL)
		}

		return mcp.NewToolResultStructured(envelope, text), nil
	}
}

// formatToolError produces a human-readable error string for the model. It
// prefixes the code so a model can branch on known codes (e.g. "denied") while
// still getting the explanatory message.
func formatToolError(ferr *server.FetchError) string {
	switch ferr.Code {
	case model.CodeDenied:
		return fmt.Sprintf("denied: %s", ferr.Message)
	default:
		return fmt.Sprintf("%s: %s", ferr.Code, ferr.Message)
	}
}

// maxMCPRequestBody bounds POST bodies on the Streamable HTTP transport,
// mirroring the REST /fetch cap (maxFetchRequestBody, 1 MiB). Without it the
// MCP library reads the whole body with io.ReadAll — an unbounded allocation
// vector REST deliberately bounds.
const maxMCPRequestBody = 1 << 20

// limitBody installs an http.MaxBytesReader on every request before the raw
// MCP transport sees it, so oversized bodies fail fast instead of allocating.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxMCPRequestBody)
		next.ServeHTTP(w, r)
	})
}

// ServeStdio creates an MCP server backed by svc and serves it on stdio. It
// blocks until the stdin stream ends or the process is signalled. This is the
// primary entry point for --mcp mode (the default transport).
func ServeStdio(svc *server.Service, logger *zap.Logger) error {
	s := New(svc, logger)
	return mcpserver.ServeStdio(s)
}

// MCPHTTPEndpoint is the URL path the Streamable HTTP transport is mounted on.
const MCPHTTPEndpoint = "/mcp"

// HTTPOptions configures the Streamable HTTP transport, including the same
// ingress controls (API key, rate limit) used by REST /fetch.
type HTTPOptions struct {
	// Addr is the listen address (required), e.g. ":9090".
	Addr string
	// APIKey, when non-empty, requires X-API-Key on every request.
	APIKey string
	// Rate is the optional per-IP token-bucket limit (RPS zero disables).
	Rate config.RateConfig
	// Collectors records rate-limit and auth failures when non-nil.
	Collectors *metrics.Collectors
	// DisableLocalhostProtection turns off the MCP library's DNS-rebinding
	// guard, which rejects requests whose Host header does not match a
	// loopback bind. Only needed when a reverse proxy in front of a loopback
	// listener preserves the original Host; default false keeps the guard on.
	DisableLocalhostProtection bool
}

// NewStreamableHTTPHandler builds the MCP Streamable HTTP transport for svc and
// returns it as an http.Handler mounted at MCPHTTPEndpoint. It is exposed so the
// transport can be mounted behind any http.ServeMux (and exercised with
// httptest). Use ServeStreamableHTTP for the standalone blocking runner.
//
// Streamable HTTP is stateless by default: each tools/call carries everything it
// needs (the handler delegates to Service.Fetch), so no server-side session
// state is required between requests.
//
// The returned handler is the raw MCP transport — callers that need API-key or
// rate-limit protection should wrap it with server.Protect (ServeStreamableHTTP
// does this automatically).
func NewStreamableHTTPHandler(svc *server.Service, logger *zap.Logger, opts ...HTTPOptions) http.Handler {
	s := New(svc, logger)
	serverOpts := []mcpserver.StreamableHTTPOption{
		mcpserver.WithEndpointPath(MCPHTTPEndpoint),
	}
	var o HTTPOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.DisableLocalhostProtection {
		serverOpts = append(serverOpts, mcpserver.WithDisableLocalhostProtection(true))
	}
	return mcpserver.NewStreamableHTTPServer(s, serverOpts...)
}

// httpShutdownTimeout bounds graceful drain of the Streamable HTTP server so a
// stuck connection cannot hang exit. It mirrors the REST server's shutdown
// budget.
const httpShutdownTimeout = 15 * time.Second

// ServeStreamableHTTP creates an MCP server backed by svc and serves it over
// Streamable HTTP at opts.Addr (the /mcp endpoint) until SIGINT/SIGTERM is
// received or the listener fails. It applies the same API-key and rate-limit
// middleware as REST /fetch so remote MCP cannot bypass transport auth.
func ServeStreamableHTTP(svc *server.Service, logger *zap.Logger, opts HTTPOptions) error {
	if logger == nil {
		logger = zap.NewNop()
	}
	raw := limitBody(NewStreamableHTTPHandler(svc, logger, opts))
	handler, stopIngress := server.Protect(
		raw,
		opts.APIKey,
		opts.Rate.RPS,
		opts.Rate.Burst,
		opts.Collectors,
		logger,
	)
	defer stopIngress()

	mux := http.NewServeMux()
	// Mount both the endpoint path and a catch-all under it so the MCP library's
	// path handling still sees /mcp while our middleware wraps every request.
	mux.Handle(MCPHTTPEndpoint, handler)
	mux.Handle(MCPHTTPEndpoint+"/", handler)

	httpSrv := &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// Bound the full request read (headers are covered above; this adds
		// the body) and idle keep-alives. A client trickling a body can no
		// longer hold a connection indefinitely. WriteTimeout is deliberately
		// omitted: SSE GET responses are long-lived streams.
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	// Bind before logging readiness: a busy port must fail without emitting a
	// "listening" line that log-based alerts would read as healthy.
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("mcp http listen: %w", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("keyhole listening",
			zap.String("addr", ln.Addr().String()),
			zap.String("transport", "http"),
			zap.String("endpoint", MCPHTTPEndpoint),
			zap.Bool("api_key", opts.APIKey != ""),
		)
		serveErr <- listenOn(httpSrv, ln)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", zap.String("signal", sig.String()))
	case err := <-serveErr:
		return fmt.Errorf("mcp http server: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		// Long-lived SSE streams cannot finish on their own; a drain timeout
		// means "close what is left", not a fatal error. Force-close so the
		// process exits 0 on a clean signal.
		logger.Warn("graceful shutdown timed out; closing remaining connections", zap.Error(err))
		_ = httpSrv.Close()
	}
	<-serveErr

	logger.Info("shutdown complete")
	return nil
}

// listen runs the server and normalises http.ErrServerClosed (the expected
// return after Shutdown) into nil so callers can distinguish a clean stop from
// a real failure. It mirrors the REST server's listen helper.
func listen(srv *http.Server) error {
	return listenOn(srv, nil)
}

// listenOn serves on an already-bound listener (nil = bind from srv.Addr),
// normalising http.ErrServerClosed to nil.
func listenOn(srv *http.Server, ln net.Listener) error {
	var err error
	if ln != nil {
		err = srv.Serve(ln)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
