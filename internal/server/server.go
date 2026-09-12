// Package server wires the HTTP surface for Keyhole: the operational endpoints
// (/healthz, /readyz, /metrics) and POST/GET /fetch — the visible product —
// behind the full middleware chain (recovery, request-ID, optional API key,
// rate limiting, and request logging). The fetch handler normalizes the URL,
// evaluates policy, fetches (with redirect re-checking via the fetcher),
// applies the requested transform, truncates to max_chars, and wraps the
// result in the JSON envelope defined by internal/model.
package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/authprofile"
	"github.com/amscotti/keyhole/internal/cache"
	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/fetch"
	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/rules"
	"github.com/amscotti/keyhole/internal/transform"
)

// HealthResponse is the JSON body returned by /healthz and /readyz.
type HealthResponse struct {
	Status string `json:"status"`
}

// Options configures the server mux.
type Options struct {
	Logger *zap.Logger
	// MetricsPath is the route for the Prometheus handler (default /metrics).
	MetricsPath string
	// MetricsEnabled gates whether the /metrics route is registered.
	MetricsEnabled bool
	// Ready reports readiness for /readyz. nil means always ready.
	Ready func() bool
	// Registry is the Prometheus registry backing /metrics. nil → a fresh,
	// process-local empty registry (no global/default registry is used).
	Registry *prometheus.Registry

	// --- fetch API ----------------------------------------------------------

	// Config provides the default max_chars, API key, and cache settings.
	Config *config.Config
	// Service, when non-nil, is used for /fetch instead of building one from
	// the individual dependency fields. Production wiring installs a Service
	// that can be hot-reloaded via StoreDeps; tests usually leave this nil and
	// set Fetcher/Engine/Transforms instead.
	Service *Service
	// Fetcher retrieves URLs. Required for /fetch when Service is nil.
	Fetcher *fetch.Fetcher
	// Engine evaluates policy. Required for /fetch when Service is nil.
	Engine *rules.Engine
	// Transforms is the transform registry. Required for /fetch when Service is nil.
	Transforms *transform.Registry
	// Cache is the optional in-memory TTL cache.
	Cache *cache.Cache
	// Collectors holds the Prometheus instruments for request metrics.
	Collectors *metrics.Collectors
	// Profiles validates client-supplied auth_profile names before fetch.
	// When non-nil, an unknown profile name yields bad_request (400) instead of
	// a confusing denied (403) from the fetch layer. When nil, auth-profile
	// validation falls through to the fetcher.
	Profiles *authprofile.Registry
}

// New returns a ServeMux with the operational endpoints and (when the fetch
// dependencies are provided) the /fetch handler registered, all wrapped in the
// middleware chain. The second return value stops background resources started
// by New (the rate-limiter janitor); it is safe to call multiple times and is a
// no-op when nothing needs stopping. Production should defer it; tests should
// register it with t.Cleanup.
//
// When Service is set on Options it is used for /fetch (production wires a
// single Service shared with MCP and hot-reload). Otherwise a Service is built
// from the individual dependency fields (the path unit tests use).
func New(opts Options) (*http.ServeMux, func()) {
	if opts.Ready == nil {
		opts.Ready = func() bool { return true }
	}
	if opts.Registry == nil {
		opts.Registry = prometheus.NewRegistry()
	}
	metricsPath := opts.MetricsPath
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	mux := http.NewServeMux()
	stop := func() {}

	// Health endpoints are not wrapped in middleware — they must respond
	// immediately and without auth.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(logger, w, http.StatusOK, HealthResponse{Status: "ok"})
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !opts.Ready() {
			writeJSON(logger, w, http.StatusServiceUnavailable, HealthResponse{Status: "not ready"})
			return
		}
		writeJSON(logger, w, http.StatusOK, HealthResponse{Status: "ready"})
	})

	if opts.MetricsEnabled {
		mux.Handle("GET "+metricsPath, promhttp.HandlerFor(opts.Registry, promhttp.HandlerOpts{
			Registry: opts.Registry,
		}))
	}

	// Fetch handler — registered when a pre-built Service is provided, or when
	// all required individual dependencies are present.
	var svc *Service
	switch {
	case opts.Service != nil:
		svc = opts.Service
	case opts.Fetcher != nil && opts.Engine != nil && opts.Transforms != nil:
		svc = &Service{
			Fetcher:    opts.Fetcher,
			Engine:     opts.Engine,
			Transforms: opts.Transforms,
			Cache:      opts.Cache,
			Cfg:        opts.Config,
			Collectors: opts.Collectors,
			Profiles:   opts.Profiles,
			Logger:     logger,
		}
	}

	if svc != nil {
		if svc.Collectors == nil {
			svc.Collectors = metrics.NewCollectors()
		}
		if svc.Logger == nil {
			svc.Logger = logger
		}
		// Resolve the config from the Options when the Service did not carry
		// one; discarding opts.Config here would make max_chars and
		// allow_client_auth_profile silently fall back to zero values even
		// though the caller supplied them. A zero-value config remains the
		// last resort (max_chars = 0 means no truncation — the test default).
		if svc.Cfg == nil {
			svc.Cfg = opts.Config
		}
		if svc.Cfg == nil {
			svc.Cfg = &config.Config{}
		}

		fh := &fetchHandler{svc: svc}

		var apiKey string
		var rateRPS float64
		var rateBurst int
		if opts.Config != nil {
			apiKey = opts.Config.Server.APIKey
			rateRPS = opts.Config.Server.Rate.RPS
			rateBurst = opts.Config.Server.Rate.Burst
		}

		var wrapped http.Handler
		wrapped, stop = Protect(fh, apiKey, rateRPS, rateBurst, svc.Collectors, logger)
		mux.Handle("POST /fetch", wrapped)
		mux.Handle("GET /fetch", wrapped)
	}

	return mux, stop
}
