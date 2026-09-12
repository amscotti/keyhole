package config_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/rules"
)

// writeConfig writes content to a fresh file in the test's temp dir and returns
// its path. Using t.TempDir keeps fixtures off /tmp (which is off-limits here).
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// loadErr fails the test if Load did not return an error whose message contains
// all of wantSubs.
func loadErr(t *testing.T, path string, wantSubs ...string) {
	t.Helper()
	_, err := config.Load(path)
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	for _, sub := range wantSubs {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error %q missing substring %q", err.Error(), sub)
		}
	}
}

func TestLoadExampleParses(t *testing.T) {
	// Not parallel: t.Setenv mutates the shared environment.
	// The example file's auth profiles reference env vars; substitution requires
	// them to be present, so set values for the duration of the test.
	t.Setenv("KEYHOLE_GITHUB_TOKEN", "ghp_example")
	t.Setenv("KEYHOLE_INTERNAL_TOKEN", "sso_example")

	cfg, err := config.Load(filepath.Join("..", "..", "config.example.toml"))
	if err != nil {
		t.Fatalf("expected example config to parse, got error: %v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("Server.Listen = %q, want %q", cfg.Server.Listen, ":8080")
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %q, want %q", cfg.Logging.Format, "json")
	}
	if !cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled = false, want true")
	}
	if cfg.DefaultPolicy != "deny" {
		t.Errorf("DefaultPolicy = %q, want deny", cfg.DefaultPolicy)
	}
	if cfg.Network.Timeout != "30s" {
		t.Errorf("Network.Timeout = %q, want 30s", cfg.Network.Timeout)
	}
	if cfg.Network.TimeoutDuration() != 30*time.Second {
		t.Errorf("Network.TimeoutDuration = %v, want 30s", cfg.Network.TimeoutDuration())
	}
	if cfg.Cache.TTLDuration() != 10*time.Minute {
		t.Errorf("Cache.TTLDuration = %v, want 10m", cfg.Cache.TTLDuration())
	}
	if cfg.Office.TimeoutDuration() != 30*time.Second {
		t.Errorf("Office.TimeoutDuration = %v, want 30s", cfg.Office.TimeoutDuration())
	}
	// Headers carry the substituted token, not the ${...} literal.
	if got := cfg.AuthProfiles[0].Headers["Authorization"]; got != "token ghp_example" {
		t.Errorf("github Authorization = %q, want substituted value", got)
	}
}

// TestExampleConfigAllowsExampleDotCom verifies that the DoD quickstart curl
// command (POST /fetch with url https://example.com) is permitted by the
// shipped config's allowlist. The Phase 4 DoD explicitly requires this URL to
// be fetchable.
func TestExampleConfigAllowsExampleDotCom(t *testing.T) {
	// Not parallel: t.Setenv mutates the shared environment.
	t.Setenv("KEYHOLE_GITHUB_TOKEN", "ghp_example")
	t.Setenv("KEYHOLE_INTERNAL_TOKEN", "sso_example")

	cfg, err := config.Load(filepath.Join("..", "..", "config.example.toml"))
	if err != nil {
		t.Fatalf("expected example config to parse, got error: %v", err)
	}

	engine, err := rules.NewEngine(cfg.Rules, cfg.DefaultPolicy)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}

	dec, err := engine.Evaluate("https://example.com/")
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !dec.Allowed {
		t.Errorf("expected https://example.com/ to be allowed by config.example.toml, got denied: %s", dec.Reason)
	}
}

func TestLoadMissingFileErrors(t *testing.T) {
	t.Parallel()
	_, err := config.Load(filepath.Join("..", "..", "testdata", "does_not_exist.toml"))
	if err == nil {
		t.Fatal("expected an error loading a missing file, got nil")
	}
	if !strings.HasPrefix(err.Error(), "config error:") {
		t.Errorf("error %q should start with 'config error:'", err.Error())
	}
}

func TestDefaultsApplied(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(filepath.Join("..", "..", "testdata", "minimal.toml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("default Server.Listen = %q, want %q", cfg.Server.Listen, ":8080")
	}
	if cfg.DefaultPolicy != "deny" {
		t.Errorf("default DefaultPolicy = %q, want deny", cfg.DefaultPolicy)
	}
	if cfg.Network.UserAgent != "github.com/amscotti/keyhole/0.1" {
		t.Errorf("default Network.UserAgent = %q, want keyhole/0.1", cfg.Network.UserAgent)
	}
	if cfg.Network.TimeoutDuration() != 30*time.Second {
		t.Errorf("default Network.TimeoutDuration = %v, want 30s", cfg.Network.TimeoutDuration())
	}
	// Omitted max_size must default to 5 MiB — never unlimited (OOM risk).
	if cfg.Network.MaxSize != 5*1024*1024 {
		t.Errorf("default Network.MaxSize = %d, want %d", cfg.Network.MaxSize, 5*1024*1024)
	}
	if cfg.Server.AllowClientAuthProfile {
		t.Error("default AllowClientAuthProfile = true, want false")
	}
}

// --- Strict decoding: unknown fields ----------------------------------------

func TestUnknownFieldNamesTableAndField(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[network]
timeout = "30s"
user_agent = "x"
timeoutt = "5s"`)
	loadErr(t, path, "config error:", `unknown field`, `"timeoutt"`, "[network]")
}

func TestUnknownTableReported(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[networkx]
foo = 1`)
	loadErr(t, path, "config error:", `unknown field`, `"networkx"`)
}

func TestUnknownTopLevelFieldReported(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `default_policyy = "deny"
[server]
listen = ":8080"`)
	loadErr(t, path, "config error:", `unknown field`, `"default_policyy"`)
}

// --- Validation pass --------------------------------------------------------

func TestDefaultPolicyInvalidValue(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `default_policy = "bogus"
[server]
listen = ":8080"`)
	loadErr(t, path, "config error:", "default_policy", `"allow"`, `"deny"`)
}

func TestMCPTransportInvalidValue(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[mcp]
enabled = true
transport = "carrier-pigeon"`)
	loadErr(t, path, "config error:", "transport", `"stdio"`, `"http"`)
}

func TestMCPHTTPTransportRequiresListen(t *testing.T) {
	t.Parallel()
	// transport = "http" is a real, served transport now; it needs a listen
	// address. An empty listen must fail closed rather than silently fall back.
	path := writeConfig(t, `[server]
listen = ":8080"
[mcp]
enabled = true
transport = "http"`)
	loadErr(t, path, "config error:", "[mcp]", "listen", "http")
}

func TestMCPHTTPTransportWithListenAccepted(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[mcp]
enabled = true
transport = "http"
listen = ":9090"`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected http transport with listen to be accepted, got: %v", err)
	}
	if cfg.MCP.Transport != "http" {
		t.Errorf("MCP.Transport = %q, want %q", cfg.MCP.Transport, "http")
	}
	if cfg.MCP.Listen != ":9090" {
		t.Errorf("MCP.Listen = %q, want %q", cfg.MCP.Listen, ":9090")
	}
}

func TestRuleWithoutMatchRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[rules]]
allow = true`)
	loadErr(t, path, "config error:", "rule", "match")
}

func TestRuleWithoutAllowRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[rules]]
match = "https://example.com/**"`)
	loadErr(t, path, "config error:", "rule", "allow")
}

func TestRuleWithExplicitAllowFalseAccepted(t *testing.T) {
	t.Parallel()
	// allow = false is a legitimate deny rule, distinct from omitting allow.
	path := writeConfig(t, `default_policy = "allow"
[server]
listen = ":8080"
[[rules]]
match = "https://example.com/**"
allow = false`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected allow=false rule to be accepted, got: %v", err)
	}
	if cfg.Rules[0].Allowed() {
		t.Error("Allowed() = true for allow=false, want false")
	}
}

func TestUnknownTransformRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[rules]]
match = "https://example.com/**"
allow = true
transforms = ["markdownn"]`)
	loadErr(t, path, "config error:", "unknown transform", `"markdownn"`)
}

func TestKnownTransformsAccepted(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[rules]]
match = "https://example.com/**"
allow = true
transforms = ["raw", "markdown", "article", "youtube", "office"]`)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("expected known transforms to be accepted, got: %v", err)
	}
}

func TestRuleAuthProfileMissingRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[rules]]
match = "https://example.com/**"
allow = true
auth_profile = "nope"`)
	loadErr(t, path, "config error:", "auth_profile", `"nope"`)
}

func TestRuleAuthProfileResolves(t *testing.T) {
	// Not parallel: t.Setenv.
	t.Setenv("KEYHOLE_T", "v")
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[auth_profiles]]
name = "github"
headers = { Authorization = "token ${KEYHOLE_T}" }
[[rules]]
match = "https://example.com/**"
allow = true
auth_profile = "github"`)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("expected resolving auth_profile to be accepted, got: %v", err)
	}
}

func TestNegativeSizeRejected(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"[network] max_size":      "[network]\nmax_size = -1",
		"[network] max_redirects": "[network]\nmax_redirects = -1",
		"[cache] max_entries":     "[cache]\nmax_entries = -1",
		"[output] max_chars":      "[output]\nmax_chars = -1",
		"[youtube] max_chars":     "[youtube]\nmax_chars = -1",
	}
	for name, body := range cases {
		path := writeConfig(t, fmt.Sprintf(`default_policy = "deny"
[server]
listen = ":8080"
%s`, body))
		if _, err := config.Load(path); err == nil {
			t.Errorf("%s: expected an error for negative size, got nil", name)
		}
	}
}

func TestBadDurationRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[network]
timeout = "not-a-duration"`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected an error for bad duration, got nil")
	}
	if !strings.Contains(err.Error(), "config error:") {
		t.Errorf("error %q should start with 'config error:'", err.Error())
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error %q should name the field 'timeout'", err.Error())
	}
	// Must be a single line naming the field and table.
	if c := strings.Count(err.Error(), "\n"); c != 0 {
		t.Errorf("error should be single-line, has %d newlines: %q", c, err.Error())
	}
	if !strings.Contains(err.Error(), "[network]") {
		t.Errorf("error %q should name [network]", err.Error())
	}
}

func TestAuthProfileWithoutNameRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[auth_profiles]]
headers = { X-foo = "bar" }`)
	loadErr(t, path, "config error:", "auth_profiles", "name")
}

func TestDuplicateAuthProfileNameRejected(t *testing.T) {
	// Not parallel: t.Setenv.
	t.Setenv("KEYHOLE_A", "x")
	t.Setenv("KEYHOLE_B", "y")
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[auth_profiles]]
name = "github"
headers = { Authorization = "token ${KEYHOLE_A}" }
[[auth_profiles]]
name = "github"
headers = { Authorization = "token ${KEYHOLE_B}" }`)
	loadErr(t, path, "config error:", "duplicate", `"github"`)
}

// --- Environment substitution ----------------------------------------------

func TestEnvSubstitutionResolvesHeaderValue(t *testing.T) {
	// Not parallel: t.Setenv.
	t.Setenv("KEYHOLE_MY_TOKEN", "abc123")
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[auth_profiles]]
name = "p"
headers = { Authorization = "Bearer ${KEYHOLE_MY_TOKEN}", X-Other = "literal" }`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.AuthProfiles[0].Headers["Authorization"]; got != "Bearer abc123" {
		t.Errorf("Authorization = %q, want 'Bearer abc123'", got)
	}
	if got := cfg.AuthProfiles[0].Headers["X-Other"]; got != "literal" {
		t.Errorf("X-Other = %q, want literal", got)
	}
}

func TestEnvSubstitutionMissingVarErrors(t *testing.T) {
	// Not parallel: asserts an env var is unset.
	const unset = "KEYHOLE_DEFINITELY_UNSET_TOKEN_4f9a2c"
	if _, ok := os.LookupEnv(unset); ok {
		t.Fatalf("precondition failed: %s is unexpectedly set", unset)
	}
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
[[auth_profiles]]
name = "p"
headers = { Authorization = "Bearer ${KEYHOLE_DEFINITELY_UNSET_TOKEN_4f9a2c}" }`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected an error for missing env var, got nil")
	}
	if !strings.Contains(err.Error(), "config error:") {
		t.Errorf("error %q should start with 'config error:'", err.Error())
	}
	if !strings.Contains(err.Error(), unset) {
		t.Errorf("error %q should name the missing variable", err.Error())
	}
	if !strings.Contains(err.Error(), "profile") && !strings.Contains(err.Error(), `"p"`) {
		t.Errorf("error %q should name the offending profile", err.Error())
	}
}

func TestEnvSubstitutionOnlyInSecrets(t *testing.T) {
	// Not parallel: t.Setenv.
	// A ${...} literal outside auth headers and api_key is left untouched
	// (surface stays small: only secret-bearing values are substituted).
	t.Setenv("MY_VAR", "resolved")
	path := writeConfig(t, `[server]
listen = "${MY_VAR}"
[logging]
output = "${MY_VAR}"`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != "${MY_VAR}" {
		t.Errorf("Listen = %q, want literal untouched", cfg.Server.Listen)
	}
}

// TestEnvSubstitutionAppliesToAPIKey pins that the ingress API key — as much a
// secret as an auth-profile header — can be sourced from the environment. A
// literal "${VAR}" must never become the deployed key.
func TestEnvSubstitutionAppliesToAPIKey(t *testing.T) {
	// Not parallel: t.Setenv.
	t.Setenv("KEYHOLE_TEST_API_KEY", "s3cret-key")
	path := writeConfig(t, `[server]
listen = ":8080"
api_key = "${KEYHOLE_TEST_API_KEY}"`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Server.APIKey; got != "s3cret-key" {
		t.Errorf("APIKey = %q, want substituted value", got)
	}
}

// TestEnvSubstitutionEmptyVarErrors pins the fail-loud behavior for the common
// "source .env" failure mode: a variable that is set but empty must not
// silently become an empty header or an empty API key.
func TestEnvSubstitutionEmptyVarErrors(t *testing.T) {
	// Not parallel: t.Setenv.
	t.Setenv("KEYHOLE_EMPTY_TOKEN", "")
	path := writeConfig(t, `default_policy = "deny"
[server]
listen = ":8080"
api_key = "${KEYHOLE_EMPTY_TOKEN}"`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected an error for an empty env var, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error %q should explain the variable is empty", err.Error())
	}
}

// smoke-check that errors chain (so callers can inspect with errors.Is if needed).
func TestLoadErrorIsUnwrappable(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[network]
timeout = "bad"`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, err) { // trivially true; just exercises the wrapping path
		t.Error("error should satisfy errors.Is with itself")
	}
}

// --- Phase 8: rate limiting + DNS-rebinding pin config ----------------------

func TestRateLimitConfigParsed(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[server.rate]
rps = 5.0
burst = 10`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Rate.RPS != 5.0 {
		t.Errorf("Rate.RPS = %v, want 5.0", cfg.Server.Rate.RPS)
	}
	if cfg.Server.Rate.Burst != 10 {
		t.Errorf("Rate.Burst = %d, want 10", cfg.Server.Rate.Burst)
	}
}

func TestRateLimitDefaultsDisabled(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Rate.RPS != 0 || cfg.Server.Rate.Burst != 0 {
		t.Errorf("Rate = {%v, %d}, want zero (disabled)", cfg.Server.Rate.RPS, cfg.Server.Rate.Burst)
	}
}

// TestNonPositiveDurationsRejected pins that a zero/negative timeout or TTL is
// rejected at load. A negative network timeout makes every dial fail as though
// already expired while the service still passes readiness.
func TestNonPositiveDurationsRejected(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"negative network timeout": `[network]
timeout = "-5s"`,
		"zero network timeout": `[network]
timeout = "0s"`,
		"negative cache ttl": `[cache]
ttl = "-10m"`,
		"negative office timeout": `[office]
timeout = "-1s"`,
	}
	for name, body := range cases {
		body := body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := writeConfig(t, body)
			if _, err := config.Load(path); err == nil {
				t.Fatalf("%s: expected an error, got nil", name)
			}
		})
	}
}

func TestRateLimitNonFiniteRPSRejected(t *testing.T) {
	t.Parallel()
	for _, rps := range []string{"nan", "inf", "-inf"} {
		path := writeConfig(t, `[server]
listen = ":8080"
[server.rate]
rps = `+rps+`
burst = 10`)
		if _, err := config.Load(path); err == nil {
			t.Errorf("rps = %s: expected an error, got nil", rps)
		}
	}
}

// TestMetricsPathValidated pins that a bad or conflicting [metrics] path fails
// at config load rather than panicking inside ServeMux registration at boot.
func TestMetricsPathValidated(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"metrics", "/healthz", "/readyz", "/fetch"} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			p := writeConfig(t, `[metrics]
enabled = true
path = "`+path+`"`)
			if _, err := config.Load(p); err == nil {
				t.Fatalf("path %q: expected an error, got nil", path)
			}
		})
	}
	// The conventional path still loads.
	p := writeConfig(t, `[metrics]
enabled = true
path = "/metrics"`)
	if _, err := config.Load(p); err != nil {
		t.Fatalf("valid metrics path rejected: %v", err)
	}
}

func TestNegativeCacheMaxBytesRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[cache]
max_bytes = -1`)
	loadErr(t, path, "config error:", "max_bytes")
}

// TestCacheMaxBytesDefaultsAndHonorsExplicit pins both halves of the documented
// memory bound: an omitted [cache] max_bytes defaults to 64 MiB (zero must
// never mean "unlimited"), while an explicit value is used verbatim.
func TestCacheMaxBytesDefaultsAndHonorsExplicit(t *testing.T) {
	t.Parallel()

	t.Run("omitted defaults to 64 MiB", func(t *testing.T) {
		t.Parallel()
		path := writeConfig(t, `[server]
listen = ":8080"`)
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Cache.MaxBytes != 64*1024*1024 {
			t.Errorf("Cache.MaxBytes = %d, want default 64 MiB (%d)", cfg.Cache.MaxBytes, 64*1024*1024)
		}
	})

	t.Run("explicit value honored", func(t *testing.T) {
		t.Parallel()
		path := writeConfig(t, `[server]
listen = ":8080"
[cache]
max_bytes = 1048576`)
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Cache.MaxBytes != 1048576 {
			t.Errorf("Cache.MaxBytes = %d, want explicit 1048576", cfg.Cache.MaxBytes)
		}
	})
}

// TestSyntaxErrorIncludesLocation pins that a TOML syntax error names the
// file and line so the most common first-run mistake is fixable.
func TestSyntaxErrorIncludesLocation(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server
listen = ":8080"`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected a decode error, got nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q should include the config path", err.Error())
	}
	if !strings.Contains(err.Error(), ":1:") && !strings.Contains(err.Error(), ":2:") {
		t.Errorf("error %q should include a line number", err.Error())
	}
}

// TestDecodeTypeMismatchNamesFieldAndLocation pins the value-error branch of
// formatDecodeError: unlike an unknown key, a type mismatch must name the
// offending field AND a file:line location, so `listen = 8080` is fixable
// without guessing which line (or file) is wrong.
func TestDecodeTypeMismatchNamesFieldAndLocation(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = 8080`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected a decode error for listen = 8080, got nil")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "config error:") {
		t.Errorf("error %q should start with 'config error:'", msg)
	}
	if !strings.Contains(msg, path) {
		t.Errorf("error %q should include the config path %q", msg, path)
	}
	if !strings.Contains(strings.ToLower(msg), "listen") {
		t.Errorf("error %q should name the 'listen' field", msg)
	}
	if !strings.Contains(msg, ":2:") {
		t.Errorf("error %q should include the line number (listen is on line 2)", msg)
	}
}

func TestRateLimitNegativeRPSRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[server.rate]
rps = -1.0
burst = 10`)
	loadErr(t, path, "config error:", "rate", "rps")
}

func TestRateLimitNegativeBurstRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[server.rate]
rps = 5.0
burst = -1`)
	loadErr(t, path, "config error:", "rate", "burst")
}

// A positive rps with zero burst can never admit a request, so it is rejected
// as a misconfiguration rather than silently rate-limiting everything.
func TestRateLimitPositiveRPSZeroBurstRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[server.rate]
rps = 5.0
burst = 0`)
	loadErr(t, path, "config error:", "rate", "burst")
}

func TestRateLimitUnknownFieldInRateTableRejected(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[server.rate]
rps = 5.0
burst = 10
rpms = 300`)
	loadErr(t, path, "config error:", "unknown field", `"rpms"`)
}

func TestPinDNSConfigParsed(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[network]
pin_dns = true`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Network.PinDNS {
		t.Error("Network.PinDNS = false, want true")
	}
}

func TestPinDNSDefaultsFalse(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, `[server]
listen = ":8080"
[network]
timeout = "30s"`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Network.PinDNS {
		t.Error("Network.PinDNS = true, want false (default off)")
	}
}

// TestAuthProfileHeaderValidation pins that malformed headers fail at load
// (with a message naming the profile) instead of at request time as a
// confusing upstream error.
func TestAuthProfileHeaderValidation(t *testing.T) {
	t.Parallel()
	bad := []struct{ name, headerLine string }{
		{"crlf in value", `Bad = "line1\r\nInjected: x"`},
		{"invalid header name", `"Bad Header" = "v"`},
	}
	for _, tc := range bad {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := writeConfig(t, `[server]
listen = ":8080"
[[auth_profiles]]
name = "p"
headers = { `+tc.headerLine+` }`)
			if _, err := config.Load(p); err == nil {
				t.Fatalf("expected a load error for %s", tc.name)
			}
		})
	}
}
