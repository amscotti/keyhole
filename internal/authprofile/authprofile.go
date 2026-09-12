// Package authprofile manages named outbound-auth profiles. Each profile is a
// set of HTTP headers applied to a fetch request when the matched rule names an
// auth_profile. Header values typically come from environment variables (expanded
// at config-load time) and are therefore secret; this package never logs them —
// only the fact that a profile was applied, alongside the target URL.
package authprofile

import (
	"fmt"
	"net/http"
	"net/url"

	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/config"
)

// Registry maps profile names to their resolved header sets. It is built once
// at load (and rebuilt on reload) from the [[auth_profiles]] config table.
type Registry struct {
	profiles map[string]config.AuthProfile
	// headerNames is the union of every header any profile sets, canonicalized.
	// Strip uses it to remove all credential headers from a redirect request
	// before the destination's policy (and possibly a new profile) is applied.
	headerNames map[string]struct{}
}

// New builds a Registry from the configured auth profiles. Duplicate names are
// rejected at config validation time, so no duplicate check is needed here.
func New(profiles []config.AuthProfile) *Registry {
	m := make(map[string]config.AuthProfile, len(profiles))
	names := make(map[string]struct{})
	for _, p := range profiles {
		m[p.Name] = p
		for hdr := range p.Headers {
			names[http.CanonicalHeaderKey(hdr)] = struct{}{}
		}
	}
	return &Registry{profiles: m, headerNames: names}
}

// Get returns the profile for name, or false if no such profile exists.
func (r *Registry) Get(name string) (config.AuthProfile, bool) {
	p, ok := r.profiles[name]
	return p, ok
}

// Strip removes every header that any configured profile can set from req.
// Redirect handling calls it before crossing an origin boundary so a profile's
// credentials travel only to URLs the operator attached them to — never to a
// host an upstream chose with a 3xx. Safe to call on a nil registry/request.
func (r *Registry) Strip(req *http.Request) {
	if r == nil || req == nil {
		return
	}
	for name := range r.headerNames {
		req.Header.Del(name)
	}
}

// SanitizeURL reduces a URL to scheme://host/path for logging. Userinfo and
// query strings can carry credentials, so both are dropped; on parse failure
// the empty string is returned rather than the raw URL. The MCP server uses it
// for the same reason.
func SanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// Apply sets the headers from the named profile on req. An empty name is a
// no-op (no profile requested). An unknown name returns an error. When logger
// is non-nil, a single Info line is emitted: "auth profile '<name>' applied to
// <url>". Header values are never logged.
//
// Headers already present on the request are preserved — the caller's explicit
// values take precedence. The fetcher applies profiles before its transport
// defaults (User-Agent), so a profile-supplied header wins over the generic
// [network] user_agent while still not clobbering headers the caller itself
// set for a security purpose.
func (r *Registry) Apply(req *http.Request, name string, logger *zap.Logger) error {
	if name == "" {
		return nil
	}
	p, ok := r.profiles[name]
	if !ok {
		return fmt.Errorf("auth profile %q is not defined", name)
	}
	for hdr, val := range p.Headers {
		if req.Header.Get(hdr) == "" {
			req.Header.Set(hdr, val)
		}
	}
	if logger != nil {
		logger.Info("auth profile applied",
			zap.String("profile", name),
			zap.String("url", SanitizeURL(req.URL.String())),
		)
	}
	return nil
}
