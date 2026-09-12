// Command keyhole is the Keyhole service entrypoint. It loads the TOML config,
// builds the logger and HTTP server (or MCP server with --mcp), and shuts down
// cleanly on SIGINT/SIGTERM.
//
// Flags:
//
//	--config <path>   path to the config file (default: config.toml)
//	--mcp             run as an MCP server (stdio or Streamable HTTP per [mcp] config)
//	--version         print the build version and exit
//
// The REST and MCP transports share one fetch pipeline; MCP is a transport,
// not a separate product.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/authprofile"
	"github.com/amscotti/keyhole/internal/cache"
	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/egress"
	"github.com/amscotti/keyhole/internal/fetch"
	"github.com/amscotti/keyhole/internal/logging"
	"github.com/amscotti/keyhole/internal/mcpserver"
	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/rules"
	"github.com/amscotti/keyhole/internal/server"
	"github.com/amscotti/keyhole/internal/transform"
)

// shutdownTimeout bounds graceful drain so a stuck connection cannot hang exit.
const shutdownTimeout = 15 * time.Second

// version is the build version, overridable at build time:
//
//	go build -ldflags "-X main.version=v0.1.0" ./cmd/keyhole
var version = "dev"

func main() {
	configPath := flag.String("config", "config.toml", "path to the TOML config file")
	mcpMode := flag.Bool("mcp", false, "run as an MCP server (stdio or Streamable HTTP per [mcp] config) instead of REST")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("keyhole " + version)
		return
	}

	if err := run(*configPath, *mcpMode); err != nil {
		// Once the zap logger exists it has already logged the detail; before
		// it exists, fall back to the stdlib logger so the cause is visible.
		log.Fatalf("keyhole: %v", err)
	}
}

// run loads the config, builds the shared dependencies, and then starts either
// the REST HTTP server or the MCP server (stdio or Streamable HTTP) depending
// on the --mcp flag and the [mcp] config block.
func run(configPath string, mcpMode bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// The MCP transport is active when either the --mcp flag is set or
	// [mcp] enabled = true (both are documented entry points). The transport
	// selects stdio (default) or Streamable HTTP. Resolved before logger
	// construction: on the stdio transport stdout carries JSON-RPC, so the
	// logger must be moved off stdout.
	mcpActive, transport := resolveMCP(mcpMode, cfg)

	logCfg := cfg.Logging
	configuredOutput := logCfg.Output
	logCfg.Output = resolveLogOutput(logCfg.Output, mcpActive, transport)
	logger, err := logging.New(logCfg)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}
	defer func() {
		_ = logger.Sync()
	}()
	if mcpActive && transport == "stdio" &&
		!strings.EqualFold(configuredOutput, "stderr") &&
		!strings.EqualFold(configuredOutput, "stdout") &&
		configuredOutput != "" {
		// stdout must stay a clean JSON-RPC channel on stdio, so a configured
		// log file is ignored. Say so rather than silently dropping it.
		logger.Warn("logging output overridden to stderr for MCP stdio transport",
			zap.String("configured_output", configuredOutput))
	}

	// Prometheus metrics — a fresh, process-local registry (no global state).
	// Built once for the process lifetime; collectors are not hot-reloaded.
	promReg := prometheus.NewRegistry()
	collectors := metrics.NewCollectors()
	collectors.MustRegister(promReg)

	// Shared Service that both REST and MCP call. Hot-reload swaps its Deps
	// snapshot so the next request sees the new policy end-to-end.
	svc := &server.Service{
		Collectors: collectors,
		Logger:     logger,
	}

	rt := &runtimeState{svc: svc, logger: logger}
	if err := rt.apply(cfg); err != nil {
		return fmt.Errorf("build runtime: %w", err)
	}
	defer rt.stop()

	// Hot-reload is opt-in via [server].reload. When enabled, a Reloader watches
	// the config file and, on every valid change, rebuilds the full dependency
	// graph (engine, fetcher, profiles, transforms, cache) via AfterReload —
	// readers always observe a completely applied policy. An invalid edit is
	// logged and the previous config + deps keep serving. Off by default: a
	// rogue AI with write access to the file must not be able to silently
	// alter policy.
	if cfg.Server.Reload {
		reloader := config.NewReloader(configPath, cfg, logger, func(newCfg *config.Config) error {
			if changed := startupOnlyDiff(cfg, newCfg); len(changed) > 0 {
				return fmt.Errorf(
					"config changes startup-only fields (%s); these are baked into the listener and ingress middleware at boot — restart to apply them",
					strings.Join(changed, ", "))
			}
			return rt.apply(newCfg)
		})
		if err := reloader.Start(); err != nil {
			return fmt.Errorf("start config reloader: %w", err)
		}
		defer reloader.Stop()
		logger.Info("config hot-reload enabled", zap.String("config", configPath))
	}

	if mcpActive {
		if transport == "http" {
			warnIfUnauthenticated(logger, cfg.MCP.Listen, cfg.Server.APIKey)
		}
		return runMCP(cfg, configPath, logger, svc, collectors, transport)
	}

	warnIfUnauthenticated(logger, cfg.Server.Listen, cfg.Server.APIKey)
	return runREST(cfg, configPath, logger, svc, collectors, promReg)
}

// warnIfUnauthenticated logs a prominent warning when the HTTP surface is
// reachable beyond loopback with no API key. Deny-by-default policy keeps a
// fresh install from being dangerous, but the moment an operator adds an allow
// rule (or default_policy = "allow") an unauthenticated listener becomes an
// open fetch proxy.
func warnIfUnauthenticated(logger *zap.Logger, listen, apiKey string) {
	if apiKey != "" {
		return
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return
	}
	logger.Warn("no [server] api_key configured; the HTTP listener is reachable beyond loopback",
		zap.String("listen", listen))
}

// runtimeState owns the live dependency snapshot so hot-reload can release the
// previous cache janitor and idle upstream connections after each swap.
type runtimeState struct {
	svc    *server.Service
	logger *zap.Logger

	mu   sync.Mutex
	deps *server.Deps
}

// apply rebuilds the full dependency snapshot from cfg and installs it on the
// Service. On success the previous snapshot's background resources are released
// after the swap so in-flight requests that still hold the old Deps pointer can
// finish.
func (rt *runtimeState) apply(cfg *config.Config) error {
	deps, err := buildDeps(cfg, rt.logger)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	old := rt.deps
	rt.deps = deps
	rt.mu.Unlock()

	rt.svc.StoreDeps(deps)

	if old != nil {
		if old.Cache != nil && old.Cache != deps.Cache {
			old.Cache.Stop()
		}
		if old.Close != nil {
			// CloseIdleConnections is safe alongside in-flight requests: it
			// only retires pooled idle connections (and their goroutines).
			old.Close()
		}
	}
	return nil
}

func (rt *runtimeState) stop() {
	rt.mu.Lock()
	d := rt.deps
	rt.deps = nil
	rt.mu.Unlock()
	if d == nil {
		return
	}
	if d.Cache != nil {
		d.Cache.Stop()
	}
	if d.Close != nil {
		d.Close()
	}
}

// buildDeps constructs a complete Deps snapshot from cfg: policy engine, auth
// profiles, hardened fetcher, transform registry (with youtube/office options),
// and optional TTL cache. Used at startup and on every successful hot-reload.
//
// INVARIANT: the cache is rebuilt (not reused) on every call. A reload is the
// only path that can change a profile's resolved secrets or [output] max_chars;
// a fresh cache guarantees rotated credentials / new truncation never serve
// stale entries under the old identity.
func buildDeps(cfg *config.Config, logger *zap.Logger) (*server.Deps, error) {
	engine, err := rules.NewEngine(cfg.Rules, cfg.DefaultPolicy)
	if err != nil {
		return nil, fmt.Errorf("build rules engine: %w", err)
	}

	profiles := authprofile.New(cfg.AuthProfiles)
	fetcher := fetch.New(cfg.Network, engine, profiles, logger)

	transforms := transform.NewRegistry()
	// The YouTube DirectTransform bypasses the generic fetcher, so its HTTP
	// client is built by the same egress choke point with the same SSRF
	// policy, timeout, and redirect limit — one egress invariant, no second
	// path. Zero timeout/redirect values fall back to egress defaults, so no
	// local fallback branch is needed here.
	// Caption GETs share the network max_size bound so the DirectTransform path
	// cannot allocate more than the generic fetcher would. The client is kept
	// here so Deps.Close can retire its idle connections on reload.
	youtubeHTTP := egress.NewHTTPClient(egress.Policy{
		AllowPrivate: cfg.Network.AllowPrivate,
		PinDNS:       cfg.Network.PinDNS,
	}, cfg.Network.TimeoutDuration(), cfg.Network.MaxRedirects)
	transforms.Register(transform.NewYouTube(
		transform.NewRealYouTubeClientLimited(
			youtubeHTTP,
			cfg.Network.MaxSize,
		),
		transform.YouTubeOptions{
			TranscriptLanguage: cfg.Youtube.TranscriptLanguage,
			IncludeTimestamps:  cfg.Youtube.IncludeTimestamps,
			MaxChars:           cfg.Youtube.MaxChars,
		},
	))
	transforms.Register(transform.NewOffice(transform.OfficeOptions{
		PandocPath: cfg.Office.PandocPath,
		Timeout:    cfg.Office.TimeoutDuration(),
	}))

	var ttlCache *cache.Cache
	if cfg.Cache.Enabled {
		// Janitor cadence follows the TTL: a TTL shorter than the old
		// hardcoded minute left expired entries squatting in MaxEntries (and
		// prematurely evicting fresh ones) until the next sweep. Floor at 1s.
		janitor := time.Minute
		if half := cfg.Cache.TTLDuration() / 2; half > 0 && half < janitor {
			janitor = half
		}
		if janitor < time.Second {
			janitor = time.Second
		}
		ttlCache = cache.New(cache.Options{
			Enabled:    true,
			TTL:        cfg.Cache.TTLDuration(),
			MaxEntries: cfg.Cache.MaxEntries,
			MaxBytes:   cfg.Cache.MaxBytes,
			Janitor:    janitor,
		})
		ttlCache.Start()
	}

	return &server.Deps{
		Fetcher:    fetcher,
		Engine:     engine,
		Transforms: transforms,
		Cache:      ttlCache,
		Cfg:        cfg,
		Profiles:   profiles,
		// Release pooled upstream connections when this snapshot is retired.
		// Without it, every hot reload strands the old transports and their
		// idle sockets (and readLoop goroutines) for the process lifetime.
		Close: func() {
			fetcher.CloseIdleConnections()
			youtubeHTTP.CloseIdleConnections()
		},
	}, nil
}

// resolveMCP decides whether the MCP transport is active and which transport to
// use, combining the --mcp flag with the [mcp] config block. Either the flag or
// [mcp] enabled = true activates MCP; an empty transport defaults to "stdio".
// This honors the documented `enabled = true` entry point that was previously
// dead config.
func resolveMCP(mcpFlag bool, cfg *config.Config) (active bool, transport string) {
	transport = strings.ToLower(cfg.MCP.Transport)
	if transport == "" {
		transport = "stdio"
	}
	return mcpFlag || cfg.MCP.Enabled, transport
}

// resolveLogOutput returns the effective logging output destination. On the
// stdio MCP transport stdout is reserved for JSON-RPC messages (the MCP spec,
// and what Claude Desktop / Hermes / MCP Inspector expect), so any log output
// — even the default "stdout" — is forced to stderr to keep the protocol
// channel clean. HTTP and REST modes honor the configured output unchanged.
func resolveLogOutput(base string, mcpActive bool, transport string) string {
	if mcpActive && transport == "stdio" {
		return "stderr"
	}
	return base
}

// runMCP starts the MCP server. MCP is a transport, not a separate product: the
// tool handler delegates to the same Service.Fetch pipeline as the REST handler,
// so policy and transforms are identical. The transport is stdio (default) or
// Streamable HTTP when [mcp] transport = "http" (served at [mcp] listen).
func runMCP(
	cfg *config.Config,
	configPath string,
	logger *zap.Logger,
	svc *server.Service,
	collectors *metrics.Collectors,
	transport string,
) error {
	if transport == "http" {
		logger.Info("keyhole starting",
			zap.String("mode", "mcp"),
			zap.String("transport", "http"),
			zap.String("config", configPath))
		return mcpserver.ServeStreamableHTTP(svc, logger, mcpserver.HTTPOptions{
			Addr:                       cfg.MCP.Listen,
			APIKey:                     cfg.Server.APIKey,
			Rate:                       cfg.Server.Rate,
			Collectors:                 collectors,
			DisableLocalhostProtection: cfg.MCP.DisableLocalhostProtection,
		})
	}

	logger.Info("keyhole starting",
		zap.String("mode", "mcp"),
		zap.String("transport", "stdio"),
		zap.String("config", configPath))

	// ServeStdio blocks until stdin closes or SIGINT/SIGTERM is received (the
	// mcp-go library installs its own signal handler). No explicit graceful
	// shutdown is needed: stdio has no in-flight HTTP connections to drain.
	if err := mcpserver.ServeStdio(svc, logger); err != nil {
		return fmt.Errorf("mcp server: %w", err)
	}

	logger.Info("shutdown complete")
	return nil
}

// startupOnlyDiff names the config fields that a hot-reload must NOT change:
// they are consumed once at boot to build the listener, mux, logger, and
// ingress middleware (API key, rate limits), so a reload that edits them would
// log "config reloaded" while silently keeping the old values — precisely the
// silent no-op an operator must never get when rotating a key mid-incident.
// Returns the list of offending field names (empty when the reload is safe).
func startupOnlyDiff(oldCfg, newCfg *config.Config) []string {
	var changed []string
	if oldCfg.Server.Listen != newCfg.Server.Listen {
		changed = append(changed, "[server] listen")
	}
	if oldCfg.Server.APIKey != newCfg.Server.APIKey {
		changed = append(changed, "[server] api_key")
	}
	if oldCfg.Server.Rate != newCfg.Server.Rate {
		changed = append(changed, "[server.rate]")
	}
	if oldCfg.Server.Reload != newCfg.Server.Reload {
		changed = append(changed, "[server] reload")
	}
	if oldCfg.Metrics.Enabled != newCfg.Metrics.Enabled || oldCfg.Metrics.Path != newCfg.Metrics.Path {
		changed = append(changed, "[metrics]")
	}
	if oldCfg.Logging != newCfg.Logging {
		changed = append(changed, "[logging]")
	}
	// [mcp] is diffed per field so a future inert field (description,
	// handshake metadata) does not force a restart. Transport compares
	// case-insensitively: resolveMCP lowercases it, so "STDIO" → "stdio"
	// is a no-op, not a transport change.
	if oldCfg.MCP.Enabled != newCfg.MCP.Enabled {
		changed = append(changed, "[mcp] enabled")
	}
	if !strings.EqualFold(oldCfg.MCP.Transport, newCfg.MCP.Transport) {
		changed = append(changed, "[mcp] transport")
	}
	if oldCfg.MCP.Listen != newCfg.MCP.Listen {
		changed = append(changed, "[mcp] listen")
	}
	if oldCfg.MCP.DisableLocalhostProtection != newCfg.MCP.DisableLocalhostProtection {
		changed = append(changed, "[mcp] disable_localhost_protection")
	}
	return changed
}

// runREST starts the REST HTTP server with the full middleware chain and
// graceful shutdown on SIGINT/SIGTERM.
func runREST(
	cfg *config.Config,
	configPath string,
	logger *zap.Logger,
	svc *server.Service,
	collectors *metrics.Collectors,
	promReg *prometheus.Registry,
) error {
	ready := &atomic.Bool{}

	handler, stopIngress := server.New(server.Options{
		Logger:         logger,
		MetricsPath:    cfg.Metrics.Path,
		MetricsEnabled: cfg.Metrics.Enabled,
		Ready:          ready.Load,
		Registry:       promReg,
		Config:         cfg,
		Service:        svc,
		Collectors:     collectors,
	})
	defer stopIngress()

	httpSrv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// Bound the full request read (headers above; body here) and idle
		// keep-alives so a client trickling a body cannot hold a connection
		// and goroutine indefinitely. WriteTimeout is omitted because a
		// slow upstream fetch can legitimately take longer than any fixed
		// write budget; the body cap plus read timeouts cover the abuse
		// vector.
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		// Bind the listener BEFORE advertising readiness so /readyz reports
		// ready only once traffic can actually be accepted (a bind failure —
		// e.g. port in use — exits without ever flipping the flag).
		ln, err := net.Listen("tcp", cfg.Server.Listen)
		if err != nil {
			ready.Store(false)
			// No "http server:" prefix here: the select below adds it, and
			// double-prefixing made bind errors read as "http server: http
			// server: ...".
			serveErr <- fmt.Errorf("listen: %w", err)
			return
		}
		ready.Store(true)
		logger.Info("keyhole listening",
			zap.String("addr", cfg.Server.Listen),
			zap.String("config", configPath))
		serveErr <- listen(httpSrv, ln)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", zap.String("signal", sig.String()))
	case err := <-serveErr:
		// Bind/listen failed before any signal — surface and exit non-zero.
		return fmt.Errorf("http server: %w", err)
	}

	// Stop advertising readiness, then drain in-flight requests within the
	// timeout. On SIGTERM the process must exit 0 after logging the line below.
	ready.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		// A slow in-flight fetch can outlast the drain budget. That is a
		// best-effort drain, not a startup failure: force-close the rest and
		// still exit 0, or a clean SIGTERM would look like a crash to systemd
		// and container supervisors.
		logger.Warn("graceful shutdown timed out; closing remaining connections", zap.Error(err))
		_ = httpSrv.Close()
	}
	// Inspect the drained result: a crash racing the signal (Serve returning
	// a real error just as SIGTERM arrived) must not exit 0 as if nothing
	// happened. ErrServerClosed is the expected clean-stop value.
	if err := <-serveErr; err != nil {
		logger.Error("graceful shutdown failed", zap.Error(err))
		return fmt.Errorf("shutdown: %w", err)
	}

	logger.Info("shutdown complete")
	return nil
}

// listen runs the server on an already-bound listener and normalises
// http.ErrServerClosed (the expected return after Shutdown) into nil so callers
// can distinguish a clean stop from a real failure.
func listen(srv *http.Server, ln net.Listener) error {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
