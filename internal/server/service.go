package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/authprofile"
	"github.com/amscotti/keyhole/internal/cache"
	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/fetch"
	"github.com/amscotti/keyhole/internal/metrics"
	"github.com/amscotti/keyhole/internal/model"
	"github.com/amscotti/keyhole/internal/rules"
	"github.com/amscotti/keyhole/internal/transform"
)

// Deps is an immutable snapshot of the fetch pipeline dependencies. Hot-reload
// swaps the entire snapshot atomically via Service.StoreDeps so a request never
// observes a half-applied policy (new engine + old network caps, etc.).
type Deps struct {
	Fetcher    *fetch.Fetcher
	Engine     *rules.Engine
	Transforms *transform.Registry
	Cache      *cache.Cache
	Cfg        *config.Config
	Profiles   *authprofile.Registry
	// Close releases process-lifetime resources held by this snapshot (idle
	// upstream connections). Hot-reload calls it on the retired snapshot so
	// old transports do not accumulate. Optional; nil is a no-op.
	Close func()
}

// FetchError carries a model error code (model.Code*) alongside a human-readable
// message. Both the REST handler and the MCP tool handler map it to their
// transport-specific error form, guaranteeing identical error semantics across
// transports.
type FetchError struct {
	Code    string
	Message string
}

func (e *FetchError) Error() string { return e.Code + ": " + e.Message }

// FetchRequest is the transport-agnostic input for the fetch pipeline.
type FetchRequest struct {
	URL         string
	Transform   string
	MaxChars    int
	AuthProfile string
}

// Service holds the shared fetch pipeline: normalize → evaluate policy → fetch
// (with redirect re-checking) → transform → truncate → envelope. Both the REST
// handler and the MCP tool handler call Service.Fetch so policy and transforms
// are guaranteed identical across transports (MCP is a transport, not a
// separate product).
//
// Direct fields (Fetcher, Engine, …) are the static wiring path used by tests.
// Production installs a hot-reloadable snapshot with StoreDeps; Fetch always
// reads via activeDeps() so a reload is visible on the next request.
type Service struct {
	Fetcher    *fetch.Fetcher
	Engine     *rules.Engine
	Transforms *transform.Registry
	Cache      *cache.Cache
	Cfg        *config.Config
	Collectors *metrics.Collectors
	Profiles   *authprofile.Registry
	Logger     *zap.Logger

	deps atomic.Pointer[Deps]

	// inflight single-flights cache-miss fetches: one caller performs the
	// upstream fetch for a key while concurrent callers for the same key wait
	// for its envelope. Without it, an agent fan-out of N identical requests
	// becomes N upstream fetches (amplification and a cache stampede). The map
	// is only touched when the cache is enabled (useCache).
	inflightMu sync.Mutex
	inflight   map[string]*inflightCall
}

// inflightCall is one in-flight cache-miss fetch shared by concurrent callers.
type inflightCall struct {
	done chan struct{}
	env  model.Envelope
	err  *FetchError
}

// StoreDeps atomically installs a new dependency snapshot for subsequent Fetch
// calls. Safe for concurrent use with Fetch.
func (s *Service) StoreDeps(d *Deps) {
	if d == nil {
		return
	}
	s.deps.Store(d)
}

// activeDeps returns the live snapshot, falling back to the struct fields for
// tests that wire Service without StoreDeps.
func (s *Service) activeDeps() *Deps {
	if d := s.deps.Load(); d != nil {
		return d
	}
	return &Deps{
		Fetcher:    s.Fetcher,
		Engine:     s.Engine,
		Transforms: s.Transforms,
		Cache:      s.Cache,
		Cfg:        s.Cfg,
		Profiles:   s.Profiles,
	}
}

// fetchErr is a shorthand for building a *FetchError.
func fetchErr(code, message string) *FetchError {
	return &FetchError{Code: code, Message: message}
}

// Fetch executes the full pipeline and returns the success envelope, or a
// *FetchError carrying a model error code. The caller is responsible for
// recording request-level metrics (RecordRequest) with the appropriate status;
// internal metrics (policy denials, cache hit/miss, fetch/transform duration)
// are recorded here so both transports are instrumented identically.
func (s *Service) Fetch(ctx context.Context, req FetchRequest) (env model.Envelope, ferr *FetchError) {
	if req.Transform == "" {
		req.Transform = "raw"
	}

	// Local fallback for tests that wire a bare Service: production (and the
	// handlers) always install collectors at construction. Assigning to the
	// shared field here would be a data race under concurrent Fetch.
	collectors := s.Collectors
	if collectors == nil {
		collectors = metrics.NewCollectors()
	}

	d := s.activeDeps()
	// Local fallback only: writing through the snapshot pointer would mutate
	// a published, shared Deps (a data race if it ever shipped with a nil Cfg).
	cfg := d.Cfg
	if cfg == nil {
		cfg = &config.Config{}
	}

	// 1. Evaluate policy on the original URL.
	decision, err := d.Engine.Evaluate(req.URL)
	if err != nil {
		return model.Envelope{}, fetchErr(model.CodeBadRequest, "malformed URL: "+err.Error())
	}
	if !decision.Allowed {
		collectors.RecordPolicyDenial()
		return model.Envelope{}, fetchErr(model.CodeDenied, decision.Reason)
	}

	// 2. Check the requested transform is known.
	tr, ok := d.Transforms.Get(req.Transform)
	if !ok {
		return model.Envelope{}, fetchErr(model.CodeUnsupported, `unknown transform "`+req.Transform+`"`)
	}

	// 3. Check the matched rule permits this transform.
	if decision.Rule != nil && !rules.AllowsTransform(*decision.Rule, req.Transform) {
		return model.Envelope{}, fetchErr(model.CodeUnsupported,
			`transform "`+req.Transform+`" is not allowed for this URL`)
	}

	// 3b. Preflight: some transforms can decide from the URL alone that they
	// cannot handle the request.
	if uv, ok := tr.(transform.URLValidator); ok {
		if err := uv.ValidateURL(req.URL); err != nil {
			var te *transform.Error
			if errors.As(err, &te) {
				return model.Envelope{}, fetchErr(te.Code, te.Message)
			}
			return model.Envelope{}, fetchErr(model.CodeUnsupported, err.Error())
		}
	}

	// 4. Resolve the auth profile. Rule-attached profiles always win. Client-
	// supplied profiles are refused (not silently dropped) unless
	// [server].allow_client_auth_profile is true — a caller whose requested
	// identity cannot be honoured must not receive a wrong-identity response
	// that looks exactly like a right-identity one.
	authProfile := ""
	switch {
	case decision.Rule != nil && decision.Rule.AuthProfile != "":
		if req.AuthProfile != "" && req.AuthProfile != decision.Rule.AuthProfile {
			// Requesting a different identity than the rule attaches cannot
			// be honoured; failing beats silently fetching as someone else.
			return model.Envelope{}, fetchErr(model.CodeBadRequest,
				`auth_profile "`+req.AuthProfile+`" is not available for this URL (a rule-attached profile is used)`)
		}
		authProfile = decision.Rule.AuthProfile
	case req.AuthProfile != "":
		if !cfg.Server.AllowClientAuthProfile {
			return model.Envelope{}, fetchErr(model.CodeBadRequest,
				"client-selected auth_profile is disabled; set [server] allow_client_auth_profile = true to permit it")
		}
		authProfile = req.AuthProfile
	}

	// 4b. Validate the resolved auth profile name.
	if authProfile != "" && d.Profiles != nil {
		if _, ok := d.Profiles.Get(authProfile); !ok {
			return model.Envelope{}, fetchErr(model.CodeBadRequest,
				`auth_profile "`+authProfile+`" is not defined`)
		}
	}

	// 5. Normalize the URL for the cache key.
	normURL, err := rules.Normalize(req.URL)
	if err != nil {
		return model.Envelope{}, fetchErr(model.CodeBadRequest, "normalize URL: "+err.Error())
	}

	// 6. Cache lookup. The key is the normalized URL, so distinct raw spellings
	//    share an entry; the current request's original spelling is re-stamped
	//    on a hit so the envelope's provenance matches the caller (fetched_at
	//    and final_url intentionally stay from the original fetch). URL-embedded
	//    credentials are part of the identity: two callers with the same
	//    normalized URL but different userinfo must not share content.
	useCache := d.Cache != nil && req.MaxChars <= 0
	if useCache {
		key := cache.Key(normURL, req.Transform, authProfile, urlCredential(req.URL))
		if cached, hit := d.Cache.Get(key); hit {
			var cachedEnv model.Envelope
			if err := json.Unmarshal(cached, &cachedEnv); err == nil {
				cachedEnv.URL = req.URL
				collectors.RecordCacheHit()
				return cachedEnv, nil
			}
			// Corrupt entry — evict it and re-fetch rather than re-serving
			// (and re-counting) the failure on every request until TTL.
			d.Cache.Delete(key)
		}
		collectors.RecordCacheMiss()

		// Single-flight the upstream fetch: the first caller for this key is
		// the leader; concurrent callers wait for its envelope instead of
		// stampeding the origin. Waiters are counted as cache hits because no
		// upstream work happened for them.
		call, leader := s.joinInflight(key)
		if !leader {
			select {
			case <-call.done:
				collectors.RecordCacheHit()
				out := call.env
				out.URL = req.URL
				return out, call.err
			case <-ctx.Done():
				return model.Envelope{}, fetchErr(model.CodeUnreachable,
					"request canceled while awaiting an in-flight fetch")
			}
		}
		defer func() { s.finishInflight(key, env, ferr) }()
	}

	// 7. Execute the transform: direct (self-fetching) or fetch→apply.
	var (
		content    string
		outputType string
		metadata   map[string]string
		preTrunc   bool
		statusCode int
		finalURL   string
	)

	if dt, ok := tr.(transform.DirectTransform); ok {
		// Direct transforms fetch through their own client and cannot apply
		// auth-profile headers. Fail closed with an explicit error instead of
		// silently fetching without the credentials the rule promised.
		if authProfile != "" {
			return model.Envelope{}, fetchErr(model.CodeUnsupported,
				`transform "`+req.Transform+`" does not support auth profiles`)
		}
		finalURL = req.URL
		if ft, ok := tr.(transform.FetchTargeter); ok {
			if canon := ft.FetchTarget(req.URL); canon != "" && canon != req.URL {
				canonDec, err := d.Engine.Evaluate(canon)
				if err != nil {
					return model.Envelope{}, fetchErr(model.CodeBadRequest, "malformed URL: "+err.Error())
				}
				if !canonDec.Allowed {
					collectors.RecordPolicyDenial()
					return model.Envelope{}, fetchErr(model.CodeDenied, canonDec.Reason)
				}
				// The canonical URL's matched rule may constrain transforms
				// more tightly than the original URL's rule; enforce it too,
				// or a redirect-shaped alias URL bypasses the allowlist.
				if canonDec.Rule != nil && !rules.AllowsTransform(*canonDec.Rule, req.Transform) {
					return model.Envelope{}, fetchErr(model.CodeUnsupported,
						`transform "`+req.Transform+`" is not allowed for this URL`)
				}
				finalURL = canon
			}
		}
		start := time.Now()
		res, derr := dt.ApplyDirect(ctx, req.URL)
		collectors.ObserveTransformDuration(req.Transform, time.Since(start))
		if derr != nil {
			var te *transform.Error
			if errors.As(derr, &te) {
				return model.Envelope{}, fetchErr(te.Code, te.Message)
			}
			return model.Envelope{}, fetchErr(model.CodeTransformFailed, derr.Error())
		}
		content, outputType, metadata, preTrunc = res.Content, res.OutputType, res.Metadata, res.Truncated
		statusCode = 200
	} else {
		fetchStart := time.Now()
		result, ferr := d.Fetcher.Fetch(ctx, req.URL, authProfile)
		fetchElapsed := time.Since(fetchStart)
		if ferr != nil {
			var fe *fetch.Error
			if errors.As(ferr, &fe) {
				if fe.Code == model.CodeDenied {
					// SSRF, redirect-policy, and robots denials are policy
					// denials too; without this the denial metric only counts
					// the initial Evaluate.
					collectors.RecordPolicyDenial()
				}
				collectors.ObserveFetchDuration(model.HTTPStatus(fe.Code), fetchElapsed)
				return model.Envelope{}, fetchErr(fe.Code, fe.Message)
			}
			collectors.ObserveFetchDuration(model.HTTPStatus(model.CodeUnreachable), fetchElapsed)
			return model.Envelope{}, fetchErr(model.CodeUnreachable, ferr.Error())
		}
		collectors.ObserveFetchDuration(result.StatusCode, fetchElapsed)

		// 5b (service side): the final (post-redirect) URL's matched rule may
		// constrain transforms more tightly than the original URL's rule —
		// enforce its allowlist too, or a redirect could deliver content under
		// a transform the final rule forbids.
		if result.FinalRule != nil && !rules.AllowsTransform(*result.FinalRule, req.Transform) {
			return model.Envelope{}, fetchErr(model.CodeUnsupported,
				`transform "`+req.Transform+`" is not allowed for the final URL after redirect`)
		}

		transformStart := time.Now()
		// Context-aware transforms (e.g. Office/pandoc) get the request
		// context so client disconnect aborts the work; pure transforms
		// use the context-free Apply.
		var res *transform.Result
		var terr error
		if ct, ok := tr.(transform.ContextTransform); ok {
			res, terr = ct.ApplyContext(ctx, result.Body, result.ContentType, result.FinalURL)
		} else {
			res, terr = tr.Apply(result.Body, result.ContentType, result.FinalURL)
		}
		collectors.ObserveTransformDuration(req.Transform, time.Since(transformStart))
		if terr != nil {
			var te *transform.Error
			if errors.As(terr, &te) {
				return model.Envelope{}, fetchErr(te.Code, te.Message)
			}
			return model.Envelope{}, fetchErr(model.CodeTransformFailed, terr.Error())
		}
		content, outputType, metadata, preTrunc = res.Content, res.OutputType, res.Metadata, res.Truncated
		statusCode = result.StatusCode
		finalURL = result.FinalURL
	}

	// 8. Truncate to max_chars — and bound metadata values too. Content
	//    truncation must not be bypassable through metadata: an upstream
	//    JSON-LD excerpt or description could otherwise inject megabytes into
	//    a max_chars=1 response (and into the cache).
	maxChars := req.MaxChars
	if maxChars <= 0 {
		maxChars = cfg.Output.MaxChars
	}
	content, truncated := model.Truncate(content, maxChars)
	metadata, metaTruncated := capMetadata(metadata, maxMetadataValueRunes)
	truncated = truncated || preTrunc || metaTruncated

	// 9. Build the success envelope.
	envelope := model.Envelope{
		OK:            true,
		URL:           req.URL,
		NormalizedURL: normURL,
		FinalURL:      finalURL,
		FetchedAt:     time.Now().UTC(),
		Status:        statusCode,
		Transform:     req.Transform,
		ContentType:   outputType,
		Truncated:     truncated,
		Content:       content,
		Metadata:      metadata,
	}

	// 10. Cache (only successful 200 responses with default truncation).
	if useCache && statusCode == 200 {
		if data, mErr := json.Marshal(envelope); mErr == nil {
			d.Cache.Set(cache.Key(normURL, req.Transform, authProfile, urlCredential(req.URL)), data)
		}
	}

	return envelope, nil
}

// joinInflight registers interest in a cache key. The first caller becomes the
// leader and must call finishInflight; concurrent callers receive the shared
// call with leader=false.
func (s *Service) joinInflight(key string) (*inflightCall, bool) {
	s.inflightMu.Lock()
	defer s.inflightMu.Unlock()
	if s.inflight == nil {
		s.inflight = make(map[string]*inflightCall)
	}
	if c, ok := s.inflight[key]; ok {
		return c, false
	}
	c := &inflightCall{done: make(chan struct{})}
	s.inflight[key] = c
	return c, true
}

// finishInflight publishes the leader's result to waiters and removes the call.
// It runs as a deferred function so it fires on every return path of Fetch,
// including the error paths.
func (s *Service) finishInflight(key string, env model.Envelope, ferr *FetchError) {
	s.inflightMu.Lock()
	c := s.inflight[key]
	delete(s.inflight, key)
	s.inflightMu.Unlock()
	if c == nil {
		return
	}
	if ferr == nil && !env.OK {
		// Defensive: a zero envelope with no error would look like success to
		// waiters. This can only arise from an unrecovered panic upstream.
		ferr = &FetchError{Code: model.CodeInternal, Message: "in-flight fetch failed"}
	}
	c.env, c.err = env, ferr
	close(c.done)
}

// maxMetadataValueRunes bounds each metadata value. Metadata is part of the
// JSON response but is not covered by [output] max_chars, so it needs its own
// cap or a hostile document can defeat the response-size contract.
const maxMetadataValueRunes = 4096

// capMetadata truncates each metadata value in place, reporting whether any
// value was cut. The bool feeds the envelope's truncated flag so the caller
// knows the response is not complete.
func capMetadata(m map[string]string, max int) (map[string]string, bool) {
	if len(m) == 0 {
		return m, false
	}
	truncated := false
	for k, v := range m {
		if cut, t := model.Truncate(v, max); t {
			m[k] = cut
			truncated = true
		}
	}
	return m, truncated
}

// urlCredential extracts the userinfo component of a raw URL for cache
// identity. rules.Normalize strips userinfo from the normalized URL (for
// policy and logging), but URL-borne Basic credentials change the upstream
// response, so two callers with the same normalized URL but different
// credentials must not share a cache entry.
func urlCredential(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return ""
	}
	return u.User.String()
}
