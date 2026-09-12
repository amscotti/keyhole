// Package config loads and validates the Keyhole TOML configuration.
//
// The configuration is the security boundary of the product — the clients are
// AI agents, so a typo must never silently weaken policy. Decoding is therefore
// strict (an unknown key is a load error) and every security-sensitive invariant
// is checked in a validation pass: a rule must declare its match and allow flag,
// transform names must be known, auth_profile references must resolve, sizes and
// durations must be sane. Environment-variable substitution is applied only to
// auth-profile header values (the one place secrets live) and a missing variable
// is a load error. When [server].reload is true the file is watched and a fully
// parsed, validated replacement is swapped in atomically; an invalid edit is
// rejected and the previous config keeps serving.
package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/net/http/httpguts"
)

// validTransforms is the closed set of transform names a rule may reference.
// It mirrors the transforms implemented in later phases; an unknown name here is
// a load-time error so a misspelled transform cannot grant unintended access.
var validTransforms = map[string]struct{}{
	"raw":      {},
	"markdown": {},
	"article":  {},
	"youtube":  {},
	"office":   {},
}

// Config holds the parsed, validated configuration.
type Config struct {
	DefaultPolicy string        `toml:"default_policy"`
	Server        ServerConfig  `toml:"server"`
	Logging       LoggingConfig `toml:"logging"`
	Metrics       MetricsConfig `toml:"metrics"`
	Network       NetworkConfig `toml:"network"`
	Cache         CacheConfig   `toml:"cache"`
	MCP           MCPConfig     `toml:"mcp"`
	Output        OutputConfig  `toml:"output"`
	Youtube       YoutubeConfig `toml:"youtube"`
	Office        OfficeConfig  `toml:"office"`
	AuthProfiles  []AuthProfile `toml:"auth_profiles"`
	Rules         []Rule        `toml:"rules"`
}

// ServerConfig holds the HTTP server settings.
type ServerConfig struct {
	Listen string `toml:"listen"`
	APIKey string `toml:"api_key"`
	Reload bool   `toml:"reload"`
	// AllowClientAuthProfile, when true, lets the caller pick any defined
	// auth_profile on a request. When false (the default), only a profile
	// attached to the matched rule is applied — clients cannot select secrets.
	// This is the safer default for the AI-agent threat model.
	AllowClientAuthProfile bool `toml:"allow_client_auth_profile"`
	// Rate configures per-client-IP rate limiting on /fetch. When
	// RPS is zero (the default) rate limiting is disabled.
	Rate RateConfig `toml:"rate"`
}

// RateConfig configures a per-client-IP token-bucket rate limiter applied to
// /fetch. RPS is the steady-state refill rate (requests/second); Burst is the
// maximum number of requests admitted in a burst. A request exceeding the
// limit gets 429 with a Retry-After header. When RPS is zero the limiter is
// disabled (no rate limiting).
type RateConfig struct {
	RPS   float64 `toml:"rps"`
	Burst int     `toml:"burst"`
}

// LoggingConfig holds the structured logging settings.
type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
	Output string `toml:"output"`
}

// MetricsConfig holds the Prometheus endpoint settings.
type MetricsConfig struct {
	Enabled bool   `toml:"enabled"`
	Path    string `toml:"path"`
}

// NetworkConfig holds the outbound HTTP settings used by the fetcher.
type NetworkConfig struct {
	Timeout       string `toml:"timeout"`
	MaxSize       int64  `toml:"max_size"`
	MaxRedirects  int    `toml:"max_redirects"`
	UserAgent     string `toml:"user_agent"`
	AllowPrivate  bool   `toml:"allow_private"`
	RespectRobots bool   `toml:"respect_robots"`
	// PinDNS, when true, enforces the SSRF blocklist on resolved IPs even when
	// AllowPrivate is set. This is the DNS-rebinding mitigation: a
	// hostname resolving to a private/link-local/metadata IP is refused even in
	// allow_private deployments, because a public hostname mapping to an
	// internal address is the classic rebinding signal. Default off — the
	// tradeoff is that internal sites accessed by hostname cannot be fetched
	// when pinning is on.
	PinDNS bool `toml:"pin_dns"`

	timeout time.Duration // populated by validate
}

// TimeoutDuration returns the parsed network timeout. It is only valid after
// Load/validate has run.
func (n NetworkConfig) TimeoutDuration() time.Duration { return n.timeout }

// CacheConfig holds the in-memory TTL cache settings.
type CacheConfig struct {
	Enabled    bool   `toml:"enabled"`
	TTL        string `toml:"ttl"`
	MaxEntries int    `toml:"max_entries"`
	// MaxBytes bounds the total size of cached values. Entry count alone is
	// not a memory bound: each cached envelope can be as large as
	// [output] max_chars, so N entries of M bytes needs a byte budget too.
	MaxBytes int64 `toml:"max_bytes"`

	ttl time.Duration // populated by validate
}

// TTLDuration returns the parsed cache TTL. It is only valid after Load/validate.
func (c CacheConfig) TTLDuration() time.Duration { return c.ttl }

// MCPConfig holds the optional MCP transport settings. Transport selects stdio
// (the default for local agents) or "http" (Streamable HTTP, for remote
// clients); when transport = "http", Listen is the address to serve on.
type MCPConfig struct {
	Enabled   bool   `toml:"enabled"`
	Transport string `toml:"transport"`
	Listen    string `toml:"listen"`
	// DisableLocalhostProtection turns off the MCP library's DNS-rebinding
	// guard, which rejects requests whose Host header does not match a
	// loopback listener. Only needed when a reverse proxy that preserves the
	// original Host sits in front of a loopback bind; leave false otherwise.
	DisableLocalhostProtection bool `toml:"disable_localhost_protection"`
}

// OutputConfig holds the default response shaping settings.
type OutputConfig struct {
	MaxChars int `toml:"max_chars"`
}

// YoutubeConfig holds the YouTube transcript settings.
type YoutubeConfig struct {
	TranscriptLanguage string `toml:"transcript_language"`
	IncludeTimestamps  bool   `toml:"include_timestamps"`
	MaxChars           int    `toml:"max_chars"`
}

// OfficeConfig holds the pandoc-based office conversion settings.
type OfficeConfig struct {
	PandocPath string `toml:"pandoc_path"`
	Timeout    string `toml:"timeout"`

	timeout time.Duration // populated by validate
}

// TimeoutDuration returns the parsed office conversion timeout. It is only valid
// after Load/validate has run.
func (o OfficeConfig) TimeoutDuration() time.Duration { return o.timeout }

// AuthProfile is a named set of outbound request headers. Header values may
// reference environment variables as ${VAR}; the values are never logged.
type AuthProfile struct {
	Name    string            `toml:"name"`
	Headers map[string]string `toml:"headers"`
}

// Rule is a single allow/deny entry. Match is a glob over the normalized URL.
// Allow is a pointer so that omitting it is detectable as a load error: a rule
// must state its intent explicitly rather than silently defaulting to deny.
type Rule struct {
	Match       string   `toml:"match"`
	Allow       *bool    `toml:"allow"`
	Transforms  []string `toml:"transforms"`
	AuthProfile string   `toml:"auth_profile"`
	// IgnoreQuery drops the query string before matching this rule's glob, so a
	// rule can match a path regardless of its parameters. Default false: the
	// query is part of the normalized URL and participates in matching.
	IgnoreQuery bool `toml:"ignore_query"`
}

// Allowed reports whether this rule permits the URL. It must be called only
// after validation, which guarantees Allow is non-nil.
func (r Rule) Allowed() bool { return r.Allow != nil && *r.Allow }

// Load reads, strictly decodes, validates, and environment-substitutes the TOML
// file at path. Any failure returns a single-line error prefixed with
// "config error:" naming the offending table and field where possible.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config error: read %s: %w", path, err)
	}
	return loadBytes(data, path)
}

// loadBytes decodes, defaults, validates, and environment-substitutes config
// bytes already read from path. Kept separate from Load so the reloader can
// apply its stability check to the bytes it actually validated.
func loadBytes(data []byte, path string) (*Config, error) {
	cfg, err := decode(data, path)
	if err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.substituteEnv(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// decode strictly unmarshals src into a Config, turning go-toml's structured
// errors into clear, field-aware messages. path is used to give syntax errors
// a file:line:column location.
func decode(src []byte, path string) (*Config, error) {
	var cfg Config
	dec := toml.NewDecoder(strings.NewReader(string(src)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, configError("%s", formatDecodeError(err, path))
	}
	return &cfg, nil
}

// formatDecodeError converts a go-toml decode error into a clear, single-line
// message naming the offending field (and its table) where possible:
//
//   - StrictMissingError (unknown keys) → `unknown field "x" in [table]`.
//   - DecodeError (bad value/type or TOML syntax) → `path:line:col: [table].field: <detail>`
//     (the location is what makes a missing quote or bracket fixable).
//
// Anything else is returned as-is.
func formatDecodeError(err error, path string) string {
	var sme *toml.StrictMissingError
	if errors.As(err, &sme) && len(sme.Errors) > 0 {
		// go-toml reports every unknown key; the first is enough to act on and
		// keeps the message a single, focused line.
		return formatMissingKey(sme.Errors[0].Key())
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		detail := strings.TrimPrefix(err.Error(), "toml: ")
		detail = strings.TrimSpace(detail)
		row, col := de.Position()
		loc := fmt.Sprintf("%s:%d:%d", path, row, col)
		if key := formatKeyPath(de.Key()); key != "" {
			return loc + ": " + key + ": " + detail
		}
		return loc + ": " + detail
	}
	return strings.TrimSpace(strings.TrimPrefix(err.Error(), "toml: "))
}

// formatMissingKey renders an unknown-key path as `unknown field "leaf" in
// [a.b]`, or `unknown field "leaf"` at the top level.
func formatMissingKey(key toml.Key) string {
	if len(key) == 0 {
		return "unknown field"
	}
	leaf := key[len(key)-1]
	if len(key) == 1 {
		return fmt.Sprintf("unknown field %q", leaf)
	}
	return fmt.Sprintf("unknown field %q in [%s]", leaf, strings.Join(key[:len(key)-1], "."))
}

// formatKeyPath renders a value-error key path as `a.b.field`.
func formatKeyPath(key toml.Key) string {
	return strings.Join(key, ".")
}

// configError prefixes a detail with the canonical "config error:" banner.
func configError(format string, args ...any) error {
	return fmt.Errorf("config error: "+format, args...)
}

// defaultMaxSize is the documented default for [network].max_size (5 MiB). A
// zero/omitted value must never mean "unlimited" — that would let a large
// upstream response OOM the process.
const defaultMaxSize int64 = 5 * 1024 * 1024

// defaultCacheMaxBytes is the documented default for [cache].max_bytes
// (64 MiB). Like [network].max_size, zero means "default", never "unlimited".
const defaultCacheMaxBytes int64 = 64 * 1024 * 1024

// applyDefaults fills in zero values with the documented defaults so the server
// can start from a minimal config file. Durations are defaulted here as strings
// and parsed by validate.
func (c *Config) applyDefaults() {
	if c.DefaultPolicy == "" {
		c.DefaultPolicy = "deny"
	}
	if c.Server.Listen == "" {
		c.Server.Listen = ":8080"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stdout"
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
	if c.Network.Timeout == "" {
		c.Network.Timeout = "30s"
	}
	if c.Network.UserAgent == "" {
		c.Network.UserAgent = "github.com/amscotti/keyhole/0.1"
	}
	// max_size = 0 (omitted) → 5 MiB. TOML decoding cannot distinguish an
	// explicit `max_size = 0` from an omitted field, so both mean "default";
	// explicit negative values are rejected by validate. There is no
	// "unlimited" mode by design.
	if c.Network.MaxSize == 0 {
		c.Network.MaxSize = defaultMaxSize
	}
	if c.Network.MaxRedirects == 0 {
		c.Network.MaxRedirects = 10
	}
	if c.Cache.TTL == "" {
		c.Cache.TTL = "10m"
	}
	// max_entries omitted → 10000 (the documented default). Zero must not
	// mean "unbounded": the cache exists partly to bound memory.
	if c.Cache.MaxEntries == 0 {
		c.Cache.MaxEntries = 10000
	}
	// max_bytes omitted → 64 MiB (the documented default). Like max_entries,
	// zero means "default", never "unbounded".
	if c.Cache.MaxBytes == 0 {
		c.Cache.MaxBytes = defaultCacheMaxBytes
	}
	// [output] max_chars omitted → 100000 (the documented default). Zero means
	// "default": an explicit zero cannot be distinguished from an omitted key,
	// and an unlimited mode is deliberately not expressible.
	if c.Output.MaxChars == 0 {
		c.Output.MaxChars = 100000
	}
	if c.Office.Timeout == "" {
		c.Office.Timeout = "30s"
	}
}

// validate runs every security-sensitive check and parses duration strings,
// returning a single-line error naming the offending table and field. It is the
// fail-closed gate that stops a typo from weakening policy.
func (c *Config) validate() error {
	switch c.DefaultPolicy {
	case "allow", "deny":
	default:
		return configError(`default_policy must be "allow" or "deny", got %q`, c.DefaultPolicy)
	}

	switch t := strings.ToLower(c.MCP.Transport); t {
	case "", "stdio", "http":
	default:
		return configError(`[mcp] transport must be "stdio" or "http", got %q`, c.MCP.Transport)
	}

	// transport = "http" is a served transport, so it needs a listen address;
	// fail closed rather than silently picking a default that may surprise an
	// operator. stdio ignores listen.
	if strings.ToLower(c.MCP.Transport) == "http" && strings.TrimSpace(c.MCP.Listen) == "" {
		return configError(`[mcp] listen is required when transport = "http"`)
	}

	if err := c.parseDurations(); err != nil {
		return err
	}

	if c.Network.MaxSize < 0 {
		return configError("[network] max_size must be >= 0, got %d", c.Network.MaxSize)
	}
	if c.Network.MaxRedirects < 0 {
		return configError("[network] max_redirects must be >= 0, got %d", c.Network.MaxRedirects)
	}
	if c.Cache.MaxEntries < 0 {
		return configError("[cache] max_entries must be >= 0, got %d", c.Cache.MaxEntries)
	}
	if c.Cache.MaxBytes < 0 {
		return configError("[cache] max_bytes must be >= 0, got %d", c.Cache.MaxBytes)
	}
	if c.Metrics.Path != "" {
		if !strings.HasPrefix(c.Metrics.Path, "/") {
			return configError(`[metrics] path must start with "/", got %q`, c.Metrics.Path)
		}
		switch c.Metrics.Path {
		case "/healthz", "/readyz", "/fetch":
			// Registering these patterns would panic at boot (duplicate
			// route); fail at config load with a fixable message instead.
			return configError("[metrics] path %q conflicts with a reserved route", c.Metrics.Path)
		}
	}
	if c.Output.MaxChars < 0 {
		return configError("[output] max_chars must be >= 0, got %d", c.Output.MaxChars)
	}
	if c.Youtube.MaxChars < 0 {
		return configError("[youtube] max_chars must be >= 0, got %d", c.Youtube.MaxChars)
	}

	if err := c.validateRate(); err != nil {
		return err
	}

	profileNames, err := c.validateAuthProfiles()
	if err != nil {
		return err
	}
	if err := c.validateRules(profileNames); err != nil {
		return err
	}
	return nil
}

// parseDurations converts the network/cache/office duration strings into their
// typed fields, failing closed on any value that time.ParseDuration rejects.
func (c *Config) parseDurations() error {
	d, err := time.ParseDuration(c.Network.Timeout)
	if err != nil {
		return configError("[network] timeout: invalid duration %q", c.Network.Timeout)
	}
	if d <= 0 {
		// A zero/negative timeout disables the client's deadline entirely
		// (Go treats a negative dial deadline as "already expired"), so every
		// fetch would fail while the service still reports healthy.
		return configError("[network] timeout must be > 0, got %q", c.Network.Timeout)
	}
	c.Network.timeout = d

	d, err = time.ParseDuration(c.Cache.TTL)
	if err != nil {
		return configError("[cache] ttl: invalid duration %q", c.Cache.TTL)
	}
	if d <= 0 {
		return configError("[cache] ttl must be > 0, got %q", c.Cache.TTL)
	}
	c.Cache.ttl = d

	d, err = time.ParseDuration(c.Office.Timeout)
	if err != nil {
		return configError("[office] timeout: invalid duration %q", c.Office.Timeout)
	}
	if d <= 0 {
		return configError("[office] timeout must be > 0, got %q", c.Office.Timeout)
	}
	c.Office.timeout = d
	return nil
}

// validateRate enforces sane rate-limit settings. A positive rps requires a
// positive burst (otherwise no request is ever admitted); negative values are
// always invalid. A zero rps disables rate limiting entirely.
func (c *Config) validateRate() error {
	r := c.Server.Rate
	if math.IsNaN(r.RPS) || math.IsInf(r.RPS, 0) {
		// NaN is the dangerous one: every comparison is false, so a NaN rate
		// would sail through a `< 0` check and poison the token bucket into
		// rejecting every request forever.
		return configError("[server.rate] rps must be a finite number, got %v", r.RPS)
	}
	if r.RPS < 0 {
		return configError("[server.rate] rps must be >= 0, got %v", r.RPS)
	}
	if r.Burst < 0 {
		return configError("[server.rate] burst must be >= 0, got %d", r.Burst)
	}
	if r.RPS > 0 && r.Burst == 0 {
		return configError("[server.rate] burst must be > 0 when rps is set (got rps=%v, burst=0)", r.RPS)
	}
	return nil
}

// validateAuthProfiles checks that every profile has a unique non-empty name and
// returns the set of known names for rule cross-referencing.
func (c *Config) validateAuthProfiles() (map[string]struct{}, error) {
	names := make(map[string]struct{}, len(c.AuthProfiles))
	for i, p := range c.AuthProfiles {
		if p.Name == "" {
			return nil, configError("[auth_profiles] profile #%d: \"name\" is required", i+1)
		}
		if _, dup := names[p.Name]; dup {
			return nil, configError("[auth_profiles] duplicate profile name %q", p.Name)
		}
		names[p.Name] = struct{}{}
		for hdr, val := range p.Headers {
			// Reject at load, not at request time: a CRLF would otherwise
			// fail as a confusing "unreachable" 502 mid-fetch. Values are
			// re-checked after env substitution (which can inject anything).
			if !httpguts.ValidHeaderFieldName(hdr) {
				return nil, configError("[auth_profiles] profile %q: invalid header name %q", p.Name, hdr)
			}
			if !httpguts.ValidHeaderFieldValue(val) {
				return nil, configError("[auth_profiles] profile %q header %q: invalid header value", p.Name, hdr)
			}
		}
	}
	return names, nil
}

// validateRules enforces that each rule declares match + allow, references only
// known transforms and auth profiles. ruleIdx is 1-based in messages.
func (c *Config) validateRules(profileNames map[string]struct{}) error {
	for i, r := range c.Rules {
		n := i + 1
		if r.Match == "" {
			return configError("[rules] rule #%d: \"match\" is required", n)
		}
		if r.Allow == nil {
			return configError("[rules] rule #%d: \"allow\" is required (set true or false)", n)
		}
		for _, t := range r.Transforms {
			if _, ok := validTransforms[t]; !ok {
				return configError("[rules] rule #%d: unknown transform %q", n, t)
			}
		}
		if r.AuthProfile != "" {
			if _, ok := profileNames[r.AuthProfile]; !ok {
				return configError("[rules] rule #%d: auth_profile %q is not defined", n, r.AuthProfile)
			}
		}
	}
	return nil
}

// substituteEnv expands ${VAR} references in the places secrets live:
// auth-profile header values and [server] api_key. A referenced variable that
// is unset (or set to the empty string) is a load error so a misconfigured
// deployment fails loudly rather than sending an empty header or installing a
// predictable literal as the ingress key.
func (c *Config) substituteEnv() error {
	// Index loop, not value copy: the slice holds structs, and mutating
	// through the copy only worked because Headers is a shared map ref.
	for i := range c.AuthProfiles {
		p := &c.AuthProfiles[i]
		for hdr, val := range p.Headers {
			expanded, err := expandEnv(val, fmt.Sprintf("[auth_profiles] profile %q header %q", p.Name, hdr))
			if err != nil {
				return err
			}
			if !httpguts.ValidHeaderFieldValue(expanded) {
				return configError("[auth_profiles] profile %q header %q: environment substitution produced an invalid header value", p.Name, hdr)
			}
			p.Headers[hdr] = expanded
		}
	}
	if c.Server.APIKey != "" {
		expanded, err := expandEnv(c.Server.APIKey, "[server] api_key")
		if err != nil {
			return err
		}
		c.Server.APIKey = expanded
	}
	return nil
}

// envVarPattern matches ${NAME} where NAME is a typical environment variable
// identifier. Only the braced form is supported, deliberately: it is explicit
// and avoids accidental expansion.
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces every ${VAR} in val with os.Getenv(VAR); an unset or empty
// VAR produces a clear, field-attributed error. Empty is treated as missing
// because "source .env" style setups silently leave a variable empty when its
// own source is unset — the classic cause of `Authorization: Bearer ` reaching
// an upstream.
func expandEnv(val, where string) (string, error) {
	var missing string
	out := envVarPattern.ReplaceAllStringFunc(val, func(match string) string {
		name := match[2 : len(match)-1] // strip ${ and }
		v, ok := os.LookupEnv(name)
		if !ok || v == "" {
			if missing == "" {
				missing = name
			}
			return match
		}
		return v
	})
	if missing != "" {
		return "", configError(
			`%s: environment variable %q is not set or is empty`, where, missing)
	}
	return out, nil
}
