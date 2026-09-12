// Package fetch is the hardened outbound HTTP client. It enforces timeouts,
// response size caps, redirect limits with policy re-evaluation on the final
// URL, an SSRF guard that blocks private/link-local/metadata IPs, and applies
// named auth profiles whose values are never logged.
//
// The security model has two layers:
//
//  1. Policy: rules.Engine.Evaluate gates the original URL; every redirect hop
//     is re-checked in CheckRedirect before it is followed; the final URL is
//     re-checked again after client.Do returns. An allowed URL that 302s into a
//     denied URL is refused without contacting the denied hop (important when
//     same-host redirects would otherwise retain Authorization headers).
//
//  2. SSRF: a custom Transport.DialContext resolves the target host and refuses
//     to dial any IP in a blocked range (loopback, RFC1918, link-local, ULA,
//     multicast, unspecified, cloud metadata). [network].allow_private bypasses
//     this for internal-site deployments.
//
//  3. DNS-rebinding pin ([network].pin_dns): when on, the SSRF blocklist is
//     enforced on hostname-resolved IPs even when allow_private is set, so a
//     public hostname that resolves to a private address is refused. The IP
//     resolved at check-time is the one dialed (no second lookup that could
//     disagree). Default off; the tradeoff is that internal sites accessed by
//     hostname cannot be fetched while pinning is on.
package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/temoto/robotstxt"
	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/authprofile"
	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/egress"
	"github.com/amscotti/keyhole/internal/rules"
)

// Error codes — the closed set used by the response envelope (the server maps
// these to HTTP statuses). The fetch layer produces denied, too_large, timeout,
// and unreachable.
const (
	CodeDenied      = "denied"
	CodeTooLarge    = "too_large"
	CodeTimeout     = "timeout"
	CodeUnreachable = "unreachable"
)

// errRedirectDenied is returned from CheckRedirect when a hop is refused by
// policy. classifyErr maps it (and any error wrapping it) to CodeDenied so the
// caller never sees an intermediate denied URL as a generic unreachable.
var errRedirectDenied = errors.New("redirect denied by policy")

// Error is a typed fetch error carrying a machine-readable code.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Result is a successful fetch outcome.
type Result struct {
	StatusCode  int
	ContentType string
	Body        []byte
	FinalURL    string
	// FinalRule is the policy rule that matched the final (post-redirect) URL,
	// or nil when the default policy allowed it. The service layer re-checks
	// the transform allowlist against it so a redirect cannot land content in
	// a transform the final URL's rule forbids.
	FinalRule *config.Rule
	// Truncated is reserved for content-level truncation (max_chars);
	// the fetch layer never truncates — an oversized body is a too_large error.
	Truncated bool
}

// Resolver abstracts DNS resolution so tests can inject deterministic results
// (e.g. a hostname that "resolves" to a private IP). It is an alias for the
// egress choke point's resolver so both packages share one DNS abstraction.
type Resolver = egress.Resolver

// Fetcher makes outbound HTTP requests with SSRF protection, size caps,
// redirect policy re-evaluation, and auth profile application.
type Fetcher struct {
	client   *http.Client
	network  config.NetworkConfig
	engine   *rules.Engine
	profiles *authprofile.Registry
	logger   *zap.Logger
	dialer   *net.Dialer
	resolver Resolver

	// robots caches parsed robots.txt per scheme://host for robotsTTL so
	// respect_robots does not add a fetch+parse to every request. A nil
	// parsed value is a negative cache entry (no/blocked/unparseable
	// robots.txt → fail open) held for the shorter negative TTL.
	robotsMu sync.Mutex
	robots   map[string]robotsEntry
}

// robotsEntry is a cached robots.txt result for one origin.
type robotsEntry struct {
	data    *robotstxt.RobotsData // nil = no usable robots.txt (fail open)
	expires time.Time
}

// robotsCacheTTL and robotsNegativeTTL bound how long a robots.txt result is
// reused.
const (
	robotsCacheTTL    = 10 * time.Minute
	robotsNegativeTTL = time.Minute
)

// robotsSkipKey marks requests issued by checkRobots itself, so redirect
// handling does not recursively check robots for the robots.txt fetch.
type robotsSkipKey struct{}

// New builds a Fetcher from the network config, policy engine, and auth
// profile registry. A nil engine means "no policy checks" (callers that have
// already evaluated policy can pass nil); a nil profile registry means auth
// profiles are unsupported (a non-empty authProfile in Fetch then errors).
func New(cfg config.NetworkConfig, engine *rules.Engine, profiles *authprofile.Registry, logger *zap.Logger) *Fetcher {
	if logger == nil {
		logger = zap.NewNop()
	}
	timeout := cfg.TimeoutDuration()
	if timeout == 0 && cfg.Timeout != "" {
		if d, err := time.ParseDuration(cfg.Timeout); err == nil {
			timeout = d
		}
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if cfg.MaxRedirects <= 0 {
		// Match net/http's conventional cap when a caller constructs a Fetcher
		// without the config defaulting pass. A zero here would otherwise mean
		// "unlimited redirects", since CheckRedirect fully replaces the stdlib
		// default policy.
		cfg.MaxRedirects = 10
	}

	f := &Fetcher{
		network:  cfg,
		engine:   engine,
		profiles: profiles,
		logger:   logger,
		dialer: &net.Dialer{
			Timeout: timeout,
		},
		resolver: egress.DefaultResolver(),
		robots:   make(map[string]robotsEntry),
	}

	// Transport/Client construction lives in egress (the arch test enforces
	// this). The dial func stays a bound method value so SetResolver swaps
	// the live resolver — Dial reads f.resolver at call time.
	transport := egress.NewTransport(f.guardedDial, timeout)

	f.client = egress.NewClient(transport, timeout, f.checkRedirect)

	return f
}

// SetResolver injects a custom DNS resolver (for testing). It must not be
// called concurrently with in-flight fetches.
func (f *Fetcher) SetResolver(r Resolver) { f.resolver = r }

// CloseIdleConnections releases pooled idle connections held by the fetcher's
// client. Hot-reload calls it on the retired dependency snapshot so transports
// from previous configs are not stranded for the process lifetime.
func (f *Fetcher) CloseIdleConnections() {
	if f.client != nil {
		f.client.CloseIdleConnections()
	}
}

// Fetch retrieves rawURL, enforcing policy, SSRF, redirects, size caps, and
// auth profiles. A non-empty authProfile names a profile in the registry.
func (f *Fetcher) Fetch(ctx context.Context, rawURL, authProfile string) (*Result, error) {
	// 1. Policy gate on the original URL.
	var origDec rules.Decision
	if f.engine != nil {
		var err error
		origDec, err = f.engine.Evaluate(rawURL)
		if err != nil {
			return nil, &Error{Code: CodeDenied, Message: "malformed URL: " + err.Error()}
		}
		if !origDec.Allowed {
			return nil, &Error{Code: CodeDenied, Message: origDec.Reason}
		}
	}

	// 2. Build the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, &Error{Code: CodeUnreachable, Message: "build request: " + err.Error()}
	}
	// 3. Apply auth profile (headers set, log emitted with no values). This
	//    runs BEFORE the transport defaults below so a profile-supplied header
	//    (e.g. an API that requires a specific User-Agent) wins over the
	//    generic [network] user_agent; the default only fills in what the
	//    profile left unset.
	if authProfile != "" {
		if f.profiles == nil {
			return nil, &Error{Code: CodeDenied, Message: "no auth profile registry configured"}
		}
		if err := f.profiles.Apply(req, authProfile, f.logger); err != nil {
			return nil, &Error{Code: CodeDenied, Message: err.Error()}
		}
	}

	if f.network.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", f.network.UserAgent)
	}

	// 4. Optional robots.txt check (fail-open: unresolvable/missing/invalid
	//    robots.txt does not block the fetch).
	if f.network.RespectRobots {
		if err := f.checkRobots(ctx, req); err != nil {
			return nil, err
		}
	}

	// 5. Send (DialContext enforces SSRF; CheckRedirect enforces max_redirects
	//    and per-hop policy so denied intermediate URLs are never contacted).
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, f.classifyErr(rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 5b. Defense in depth: re-check policy on the final URL after redirects
	//     even though CheckRedirect already gated each hop. Covers any path
	//     where the transport rewrites the request without invoking
	//     CheckRedirect (should not happen with net/http, but cheap insurance).
	//     The final decision's rule is surfaced to the caller so the service
	//     layer can enforce the final rule's transform allowlist too.
	finalURL := resp.Request.URL.String()
	finalRule := origDec.Rule
	if f.engine != nil && finalURL != rawURL {
		dec, err := f.engine.Evaluate(finalURL)
		if err != nil {
			return nil, &Error{Code: CodeDenied, Message: "redirect to malformed URL: " + err.Error()}
		}
		if !dec.Allowed {
			return nil, &Error{Code: CodeDenied, Message: "denied by final URL policy (redirect): " + dec.Reason}
		}
		finalRule = dec.Rule
	}

	// 6. Read the body with the size cap. Read one extra byte to detect overflow.
	//    Read failures are classified like transport failures so a client
	//    timeout that fires mid-body (the client deadline covers the body, not
	//    just the headers) is a timeout, not an unreachable.
	body, err := f.readBounded(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, f.classifyErr(rawURL, err)
	}

	return &Result{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		FinalURL:    finalURL,
		FinalRule:   finalRule,
		Truncated:   false,
	}, nil
}

// checkRedirect enforces max_redirects and re-evaluates policy on every
// redirect hop before it is followed. Refusing here prevents contacting a
// denied URL (and, on same-host hops, prevents net/http from forwarding
// Authorization to a path the operator denied).
//
// It also curates auth-profile headers per hop: inherited credentials continue
// only to the same origin (and never across an HTTPS→HTTP downgrade); when the
// destination's matched rule names a profile, that profile replaces the
// inherited headers, so a redirect into a host that legitimately needs its own
// auth keeps working. See curateProfileHeaders.
func (f *Fetcher) checkRedirect(req *http.Request, via []*http.Request) error {
	if f.network.MaxRedirects > 0 && len(via) > f.network.MaxRedirects {
		return fmt.Errorf("max_redirects (%d) exceeded", f.network.MaxRedirects)
	}
	if req == nil || req.URL == nil || len(via) == 0 || via[0] == nil || via[0].URL == nil {
		return nil
	}

	var rule *config.Rule
	if f.engine != nil {
		dec, err := f.engine.Evaluate(req.URL.String())
		if err != nil {
			return fmt.Errorf("%w: malformed redirect URL: %v", errRedirectDenied, err)
		}
		if !dec.Allowed {
			return fmt.Errorf("%w: %s", errRedirectDenied, dec.Reason)
		}
		rule = dec.Rule
	}

	f.curateProfileHeaders(via[0].URL, req, rule)

	// A redirect to a different host is still a fetch of that host's content,
	// so its robots.txt applies too. The robots request itself is marked to
	// avoid recursing here.
	if f.network.RespectRobots && req.Context().Value(robotsSkipKey{}) == nil {
		if rerr := f.checkRobots(req.Context(), req); rerr != nil {
			return fmt.Errorf("%w: %s", errRedirectDenied, rerr.Error())
		}
	}
	return nil
}

// curateProfileHeaders keeps auth-profile credentials scoped to the URLs the
// operator attached the profile to. net/http copies the original request's
// headers onto every redirect hop (and only strips a fixed sensitive-header
// list, and only when the registrable domain changes), so without this a
// profile's custom credential header could reach any redirect target that
// passes policy.
//
// Rules:
//   - the destination rule names a profile → strip any inherited profile
//     headers and apply that profile (the destination is configured to need it);
//   - no destination profile, same origin → inherited headers continue
//     (the common same-host API redirect);
//   - no destination profile, different origin or HTTPS→HTTP downgrade →
//     strip all profile-set headers.
func (f *Fetcher) curateProfileHeaders(origin *url.URL, req *http.Request, rule *config.Rule) {
	if f.profiles == nil {
		return
	}
	dstProfile := ""
	if rule != nil {
		dstProfile = rule.AuthProfile
	}
	if dstProfile == "" && sameOrigin(origin, req.URL) {
		return
	}
	f.profiles.Strip(req)
	if dstProfile == "" {
		return
	}
	if err := f.profiles.Apply(req, dstProfile, f.logger); err != nil {
		f.logger.Warn("redirect auth profile not applied",
			zap.String("profile", dstProfile),
			zap.String("url", authprofile.SanitizeURL(req.URL.String())),
			zap.Error(err),
		)
	}
}

// sameOrigin reports whether the redirect destination shares the origin's host
// and effective port without a TLS downgrade. http→https counts as same-origin
// (an upgrade, e.g. a bare-host http URL canonicalizing to https); https→http
// never does.
func sameOrigin(origin, dst *url.URL) bool {
	if origin == nil || dst == nil {
		return false
	}
	if !strings.EqualFold(origin.Hostname(), dst.Hostname()) {
		return false
	}
	if origin.Scheme == "https" && dst.Scheme != "https" {
		return false
	}
	if effectivePort(origin) == effectivePort(dst) {
		return true
	}
	// Neither URL pins a port: the difference is the scheme's default port
	// (an http→https upgrade, since a downgrade was rejected above).
	return origin.Port() == "" && dst.Port() == ""
}

// effectivePort returns the explicit port or the scheme default ("80"/"443").
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// checkRobots fetches and evaluates the target host's robots.txt. It fails
// open: if robots.txt is unreachable, missing, or unparseable, the request is
// allowed. Only an explicit disallow in a valid robots.txt blocks the fetch.
// The robots.txt request goes through the same SSRF guard as any other
// request, is policy-evaluated like any other URL, and results are cached per
// origin so redirect hops do not add a fetch per hop.
func (f *Fetcher) checkRobots(ctx context.Context, contentReq *http.Request) error {
	u := contentReq.URL
	if u == nil {
		return nil
	}
	robotsURL := u.Scheme + "://" + u.Host + "/robots.txt"

	// Policy applies to every URL this process fetches, robots.txt included.
	// When the operator denied it, skip the check (fail open) rather than
	// making the content request depend on a URL policy forbids.
	if f.engine != nil {
		if dec, err := f.engine.Evaluate(robotsURL); err != nil || !dec.Allowed {
			return nil
		}
	}

	robots, err := f.robotsFor(ctx, u.Scheme, u.Host, robotsURL)
	if err != nil || robots == nil {
		return nil // fail open
	}

	// The robots check must run against what is actually requested: the
	// normalized (dot-segment-resolved, empty-path-to-"/") path, and the
	// User-Agent actually sent (a profile may have overridden it).
	testPath := u.Path
	if norm, nerr := rules.Normalize(contentReq.URL.String()); nerr == nil {
		if nu, perr := url.Parse(norm); perr == nil && nu.Path != "" {
			testPath = nu.Path
		}
	}
	if testPath == "" {
		testPath = "/"
	}
	ua := contentReq.Header.Get("User-Agent")
	if ua == "" {
		ua = "*"
	}
	if !robots.TestAgent(testPath, ua) {
		return &Error{
			Code:    CodeDenied,
			Message: fmt.Sprintf("denied by robots.txt for path %s", testPath),
		}
	}
	return nil
}

// robotsFor returns the parsed robots.txt for an origin, using (and filling)
// the per-origin cache. A nil result with nil error means "no usable
// robots.txt — fail open". Fetch errors are not propagated: robots is
// best-effort by contract.
func (f *Fetcher) robotsFor(ctx context.Context, scheme, host, robotsURL string) (*robotstxt.RobotsData, error) {
	key := scheme + "://" + host
	now := time.Now()

	f.robotsMu.Lock()
	if e, ok := f.robots[key]; ok && now.Before(e.expires) {
		f.robotsMu.Unlock()
		return e.data, nil
	}
	f.robotsMu.Unlock()

	data, err := f.fetchRobots(ctx, robotsURL)
	var dataPtr *robotstxt.RobotsData
	ttl := robotsNegativeTTL
	if err == nil {
		if parsed, perr := robotstxt.FromBytes(data); perr == nil {
			dataPtr = parsed
			ttl = robotsCacheTTL
		}
	}
	f.robotsMu.Lock()
	f.robots[key] = robotsEntry{data: dataPtr, expires: now.Add(ttl)}
	f.robotsMu.Unlock()
	return dataPtr, nil
}

// fetchRobots performs the bounded robots.txt GET. Errors mean "no usable
// robots.txt" to the caller.
func (f *Fetcher) fetchRobots(ctx context.Context, robotsURL string) ([]byte, error) {
	ctx = context.WithValue(ctx, robotsSkipKey{}, true)
	robotsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return nil, err
	}
	if f.network.UserAgent != "" {
		robotsReq.Header.Set("User-Agent", f.network.UserAgent)
	}

	resp, err := f.client.Do(robotsReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("robots.txt status %d", resp.StatusCode)
	}

	limit := f.network.MaxSize
	if limit <= 0 {
		limit = 5 * 1024 * 1024 // sanity cap on robots.txt size
	}
	if limit >= math.MaxInt64-1 {
		limit = math.MaxInt64 - 1
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("robots.txt exceeds %d bytes", limit)
	}
	return data, nil
}

// readBounded reads up to max_size+1 bytes from r. If the body exceeds max_size
// the result is a too_large error (the body is NOT returned truncated). A
// non-positive limit falls back to the documented 5 MiB default so an
// incompletely-built NetworkConfig cannot unbounded-read.
func (f *Fetcher) readBounded(r io.Reader, contentLength int64) ([]byte, error) {
	limit := f.network.MaxSize
	if limit <= 0 {
		limit = 5 * 1024 * 1024
	}
	if limit >= math.MaxInt64-1 {
		// A pathological max_size would overflow limit+1 into a negative
		// LimitReader count, which reads as immediate EOF (an empty "success").
		limit = math.MaxInt64 - 1
	}
	lr := io.LimitReader(r, limit+1)
	// Preallocate from the declared Content-Length when it is plausible:
	// io.ReadAll's growth strategy allocates roughly twice the body size.
	var buf bytes.Buffer
	if contentLength > 0 && contentLength <= limit {
		buf.Grow(int(contentLength))
	}
	if _, err := buf.ReadFrom(lr); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	body := buf.Bytes()
	if int64(len(body)) > limit {
		return nil, &Error{
			Code:    CodeTooLarge,
			Message: fmt.Sprintf("response body exceeds max_size (%d bytes)", limit),
		}
	}
	return body, nil
}

// classifyErr converts a transport/request error into a typed fetch Error.
// Errors that are already typed (too_large from readBounded, policy denials)
// pass through unchanged.
func (f *Fetcher) classifyErr(rawURL string, err error) *Error {
	var typed *Error
	if errors.As(err, &typed) {
		return typed
	}
	if errors.Is(err, errRedirectDenied) {
		// Strip the transport's "Get <url>: " wrapper so the message is
		// policy-focused. errors.Is still matches through the chain.
		msg := err.Error()
		if i := strings.LastIndex(msg, errRedirectDenied.Error()); i >= 0 {
			msg = strings.TrimSpace(msg[i:])
		}
		return &Error{Code: CodeDenied, Message: msg}
	}
	var ssrfErr *egress.BlockedError
	if errors.As(err, &ssrfErr) {
		return &Error{
			Code:    CodeDenied,
			Message: fmt.Sprintf("ssrf: host %s resolves to blocked address %s", ssrfErr.Host, ssrfErr.IP),
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		// A canceled context is the caller's choice, but from the caller's
		// perspective the fetch didn't complete — classify as unreachable when
		// the caller canceled (vs. the client's own timeout which is a
		// DeadlineExceeded).
		if errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return &Error{Code: CodeUnreachable, Message: "request canceled"}
		}
		return &Error{Code: CodeTimeout, Message: "request timed out"}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &Error{Code: CodeTimeout, Message: "request timed out"}
	}
	if u := authprofile.SanitizeURL(rawURL); u != "" {
		return &Error{Code: CodeUnreachable, Message: fmt.Sprintf("fetch %s: %s", u, err.Error())}
	}
	return &Error{Code: CodeUnreachable, Message: "fetch failed: " + err.Error()}
}

// --- SSRF guard -----------------------------------------------------------
//
// The dial-level enforcement lives in the egress choke point
// (internal/egress) so the YouTube DirectTransform shares the exact same
// policy. This method only maps the fetcher's network config onto an egress
// policy; the resolver stays dynamic (read at call time) so SetResolver
// keeps working in tests.
func (f *Fetcher) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return egress.Dial(ctx, egress.Policy{
		AllowPrivate: f.network.AllowPrivate,
		PinDNS:       f.network.PinDNS,
	}, f.resolver, f.dialer, network, addr)
}
