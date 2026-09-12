package rules

import (
	"testing"

	"github.com/amscotti/keyhole/internal/config"
)

// TestMatrix is the crown jewel: every case the PLAN.md Phase 2 TODO lists as a
// named table-test row. Add a row here whenever a matching behavior is added.
func TestMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		policy  string
		rules   []config.Rule
		url     string
		allowed bool
	}{
		// --- matching shapes --------------------------------------------------
		{
			name:   "exact url match",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/page", Allow: bptr(true)},
			},
			url:     "https://example.com/page",
			allowed: true,
		},
		{
			name:   "single star matches one segment",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/*", Allow: bptr(true)},
			},
			url:     "https://example.com/seg",
			allowed: true,
		},
		{
			name:   "single star does not cross segment",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/*", Allow: bptr(true)},
			},
			url:     "https://example.com/a/b",
			allowed: false,
		},
		{
			name:   "double star crosses whole domain tree",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/**", Allow: bptr(true)},
			},
			url:     "https://example.com/a/b/c",
			allowed: true,
		},
		// M1: a bare-host URL with a query but no path matches /** after the
		// empty path is normalized to /.
		{
			name:   "bare host with query matches double star",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/**", Allow: bptr(true)},
			},
			url:     "https://example.com?a=1",
			allowed: true,
		},

		// --- query handling ---------------------------------------------------
		{
			name:   "query preserved participates in match",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/s?a=*", Allow: bptr(true)},
			},
			url:     "https://example.com/s?a=1",
			allowed: true,
		},
		{
			name:   "query mismatch denies when preserved",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/s?a=1", Allow: bptr(true)},
			},
			url:     "https://example.com/s?a=2",
			allowed: false,
		},
		// R2: '?' is a literal query separator, not a single-char wildcard.
		// The pattern must not match a URL where a path char replaces '?'.
		{
			name:   "query separator is literal not single-char wildcard",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/watch?v=*", Allow: bptr(true)},
			},
			url:     "https://example.com/watchxv=abc",
			allowed: false,
		},
		{
			name:   "query separator is literal not wildcard X variant",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/watch?v=*", Allow: bptr(true)},
			},
			url:     "https://example.com/watchXv=abc",
			allowed: false,
		},
		{
			name:   "ignore_query matches regardless of parameters",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/s", IgnoreQuery: true, Allow: bptr(true)},
			},
			url:     "https://example.com/s?anything=here",
			allowed: true,
		},
		// R1: a query-bearing pattern with ignore_query=true must match — the
		// query is stripped from the pattern as well as the target.
		{
			name:   "ignore_query with query in pattern matches target query",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/watch?v=*", IgnoreQuery: true, Allow: bptr(true)},
			},
			url:     "https://example.com/watch?v=dQw4w9WgXcQ",
			allowed: true,
		},
		{
			name:   "ignore_query with query in pattern matches any params",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/watch?v=*", IgnoreQuery: true, Allow: bptr(true)},
			},
			url:     "https://example.com/watch?x=1&y=2",
			allowed: true,
		},

		// --- normalization inputs that must still match -----------------------
		{
			name:   "default port stripped then matched",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/**", Allow: bptr(true)},
			},
			url:     "https://example.com:443/a",
			allowed: true,
		},
		{
			name:   "fragment stripped then matched",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/**", Allow: bptr(true)},
			},
			url:     "https://example.com/a#frag",
			allowed: true,
		},
		{
			name:   "case-insensitive host matched against lowercase pattern",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/**", Allow: bptr(true)},
			},
			url:     "https://EXAMPLE.com/a",
			allowed: true,
		},
		{
			name:   "idn punycode host matches ascii pattern",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://xn--bcher-kva.example/**", Allow: bptr(true)},
			},
			url:     "https://Bücher.example/a",
			allowed: true,
		},

		// --- B1: dot-segment traversal must not bypass allow rules ------------
		// The upstream server resolves "/public/../secret" → "/secret", so the
		// matcher must resolve dot segments too — otherwise a URL approved as
		// under /public/ is actually served from /secret/.
		{
			name:   "dot segment traversal blocked by policy",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/public/**", Allow: bptr(true)},
			},
			url:     "https://example.com/public/../secret",
			allowed: false,
		},
		{
			name:   "encoded dot traversal blocked by policy",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/public/**", Allow: bptr(true)},
			},
			url:     "https://example.com/public/%2e%2e/secret",
			allowed: false,
		},
		{
			name:   "encoded dot slash traversal blocked by policy",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/public/**", Allow: bptr(true)},
			},
			url:     "https://example.com/..%2fsecret",
			allowed: false,
		},

		// --- specificity & tie-break ------------------------------------------
		{
			name:   "most specific wins",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/**", Allow: bptr(true)},
				{Match: "https://example.com/hr/**", Allow: bptr(false)},
			},
			url:     "https://example.com/hr/secret",
			allowed: false,
		},
		{
			name:   "tie resolves to deny",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/x", Allow: bptr(true)},
				{Match: "https://example.com/x", Allow: bptr(false)},
			},
			url:     "https://example.com/x",
			allowed: false,
		},
		{
			name:   "deny overrides allow at equal specificity",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/v1/**", Allow: bptr(true)},
				{Match: "https://example.com/v1/**", Allow: bptr(false)},
			},
			url:     "https://example.com/v1/x",
			allowed: false,
		},

		// --- R1: pattern normalization under default-allow --------------------
		// Deny rules with a non-canonical authority must still block. Without
		// pattern normalization these are silently dead in blocklist mode.
		{
			name:   "deny with uppercase host blocks under default allow",
			policy: "allow",
			rules: []config.Rule{
				{Match: "https://SECRET.com/**", Allow: bptr(false)},
			},
			url:     "https://secret.com/x",
			allowed: false,
		},
		{
			name:   "deny with explicit default port blocks under default allow",
			policy: "allow",
			rules: []config.Rule{
				{Match: "https://secret.com:443/**", Allow: bptr(false)},
			},
			url:     "https://secret.com/x",
			allowed: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := mustEngine(t, tc.policy, tc.rules...)
			d, err := e.Evaluate(tc.url)
			if err != nil {
				t.Fatalf("Evaluate(%q): %v", tc.url, err)
			}
			if d.Allowed != tc.allowed {
				t.Errorf("Evaluate(%q): Allowed=%v want %v (reason=%q)",
					tc.url, d.Allowed, tc.allowed, d.Reason)
			}
		})
	}
}

func TestTransformPermission(t *testing.T) {
	t.Parallel()
	// nil Transforms (field omitted) → all transforms permitted.
	all := config.Rule{Match: "https://x/**", Allow: bptr(true)} // Transforms nil
	// empty (non-nil) Transforms → raw only.
	rawOnly := config.Rule{Match: "https://x/**", Allow: bptr(true), Transforms: []string{}}
	// explicit list → only those.
	some := config.Rule{Match: "https://x/**", Allow: bptr(true), Transforms: []string{"markdown", "article"}}

	check := func(r config.Rule, transform string, want bool) {
		t.Helper()
		if got := AllowsTransform(r, transform); got != want {
			t.Errorf("AllowsTransform(transforms=%v, %q) = %v, want %v", r.Transforms, transform, got, want)
		}
	}

	check(all, "raw", true)
	check(all, "markdown", true)
	check(all, "office", true)

	check(rawOnly, "raw", true)
	check(rawOnly, "markdown", false)

	check(some, "markdown", true)
	check(some, "article", true)
	check(some, "raw", false)
	check(some, "youtube", false)
}

func TestEvaluate_DecisionCarriesMatchedRule(t *testing.T) {
	t.Parallel()
	withTransforms := config.Rule{
		Match: "https://example.com/**", Allow: bptr(true),
		Transforms: []string{"markdown"}, AuthProfile: "sso",
	}
	e := mustEngine(t, "deny", withTransforms)
	d, err := e.Evaluate("https://example.com/a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Rule == nil {
		t.Fatal("expected a matched rule on an allow decision, got nil")
	}
	if d.Rule.AuthProfile != "sso" {
		t.Errorf("Rule.AuthProfile = %q, want sso", d.Rule.AuthProfile)
	}
	if !AllowsTransform(*d.Rule, "markdown") {
		t.Error("matched rule should permit markdown")
	}
}

// --- IPv6 literal hosts (bracketed) --------------------------------------
// Bracketed IPv6 authorities contain glob metacharacters; the compiled pattern
// must match its own host (literal brackets) and never widen to another host.

func TestMatrixIPv6(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		policy  string
		rules   []config.Rule
		url     string
		allowed bool
	}{
		{
			name:   "ipv6 allow rule matches its own host",
			policy: "deny",
			rules: []config.Rule{
				{Match: "http://[::1]:8080/**", Allow: bptr(true)},
			},
			url:     "http://[::1]:8080/x",
			allowed: true,
		},
		{
			name:   "ipv6 pattern does not widen to other hosts",
			policy: "deny",
			rules: []config.Rule{
				{Match: "http://[::1]:8080/**", Allow: bptr(true)},
			},
			url:     "http://1:8080/x",
			allowed: false,
		},
		{
			name:   "ipv6 deny rule blocks under default allow",
			policy: "allow",
			rules: []config.Rule{
				{Match: "http://[::1]:8080/**", Allow: bptr(false)},
			},
			url:     "http://[::1]:8080/x",
			allowed: false,
		},
		{
			name:   "ipv6 deny rule does not block other hosts",
			policy: "allow",
			rules: []config.Rule{
				{Match: "http://[::1]:8080/**", Allow: bptr(false)},
			},
			url:     "http://example.com/x",
			allowed: true,
		},
		{
			name:   "ipv6 without port matches any-port-free target",
			policy: "deny",
			rules: []config.Rule{
				{Match: "http://[fe80::1]/**", Allow: bptr(true)},
			},
			url:     "http://[fe80::1]/x",
			allowed: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := mustEngine(t, tc.policy, tc.rules...)
			d, err := e.Evaluate(tc.url)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if d.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v (reason %q)", d.Allowed, tc.allowed, d.Reason)
			}
		})
	}
}

// TestMatrixCanonicalHosts pins that policy matching agrees with dialing for
// alternate IP and port spellings: if a resolver accepts the spelling, the
// matcher must evaluate it as the address actually contacted.
func TestMatrixCanonicalHosts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		policy  string
		rules   []config.Rule
		url     string
		allowed bool
	}{
		{
			name:   "deny canonical ip blocks packed decimal form",
			policy: "allow",
			rules: []config.Rule{
				{Match: "http://127.0.0.1/**", Allow: bptr(false)},
			},
			url:     "http://2130706433/x",
			allowed: false,
		},
		{
			name:   "deny canonical ip blocks hex form",
			policy: "allow",
			rules: []config.Rule{
				{Match: "http://127.0.0.1/**", Allow: bptr(false)},
			},
			url:     "http://0x7f000001/x",
			allowed: false,
		},
		{
			name:   "deny canonical ip blocks short form",
			policy: "allow",
			rules: []config.Rule{
				{Match: "http://127.0.0.1/**", Allow: bptr(false)},
			},
			url:     "http://127.1/x",
			allowed: false,
		},
		{
			name:   "deny ipv6 literal blocks expanded form",
			policy: "allow",
			rules: []config.Rule{
				{Match: "http://[::1]/**", Allow: bptr(false)},
			},
			url:     "http://[0:0:0:0:0:0:0:1]/x",
			allowed: false,
		},
		{
			name:   "deny ipv4 literal blocks v4-mapped form",
			policy: "allow",
			rules: []config.Rule{
				{Match: "http://127.0.0.1/**", Allow: bptr(false)},
			},
			url:     "http://[::ffff:127.0.0.1]/x",
			allowed: false,
		},
		{
			name:   "deny without port blocks leading-zero default port",
			policy: "allow",
			rules: []config.Rule{
				{Match: "https://example.com/**", Allow: bptr(false)},
			},
			url:     "https://example.com:0443/x",
			allowed: false,
		},
		{
			name:   "allow written in packed form matches canonical url",
			policy: "deny",
			rules: []config.Rule{
				{Match: "http://2130706433/**", Allow: bptr(true)},
			},
			url:     "http://127.0.0.1/x",
			allowed: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := mustEngine(t, tc.policy, tc.rules...)
			d, err := e.Evaluate(tc.url)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if d.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v (reason %q)", d.Allowed, tc.allowed, d.Reason)
			}
		})
	}
}

// --- bare-host / query-only patterns --------------------------------------
// Normalize maps an empty target path to "/", so a pattern written without a
// path must be compiled with "/" to stay live (a dead deny fails open).

func TestMatrixBareHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		policy  string
		rules   []config.Rule
		url     string
		allowed bool
	}{
		{
			name:   "bare host allow matches root",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com", Allow: bptr(true)},
			},
			url:     "https://example.com/",
			allowed: true,
		},
		{
			name:   "bare host deny blocks under default allow",
			policy: "allow",
			rules: []config.Rule{
				{Match: "https://evil.example.com", Allow: bptr(false)},
			},
			url:     "https://evil.example.com/",
			allowed: false,
		},
		{
			name:   "query-only pattern matches target with root path",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com?a=1", Allow: bptr(true)},
			},
			url:     "https://example.com/?a=1",
			allowed: true,
		},
		{
			name:   "fragment in pattern is dropped like targets",
			policy: "deny",
			rules: []config.Rule{
				{Match: "https://example.com/page#frag", Allow: bptr(true)},
			},
			url:     "https://example.com/page",
			allowed: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := mustEngine(t, tc.policy, tc.rules...)
			d, err := e.Evaluate(tc.url)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if d.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v (reason %q)", d.Allowed, tc.allowed, d.Reason)
			}
		})
	}
}

// --- wildcard IDN hosts -----------------------------------------------------

func TestMatrixWildcardIDN(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://*.münchen.de/**", Allow: bptr(true)})
	d, err := e.Evaluate("https://www.xn--mnchen-3ya.de/page")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("wildcard IDN pattern should match punycoded target (reason %q)", d.Reason)
	}
	d, err = e.Evaluate("https://www.example.de/page")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Allowed {
		t.Fatal("wildcard IDN pattern must not match a different domain")
	}
}

// --- load-time rejection of dead patterns ---------------------------------

func TestNewEngineRejectsDeadPatterns(t *testing.T) {
	t.Parallel()
	for _, match := range []string{
		"/admin/**",      // schemeless
		"example.com/**", // schemeless host
		"https://",       // empty authority
		"https:///x",     // empty authority with path
		// Wildcard inside a non-ASCII (IDN) label: cannot be punycoded, so it
		// can never match a normalized target — silently dead otherwise.
		"https://münchen*.example.com/**",
		"https://*.münchen*.de/**",
		// Targets have userinfo stripped and ports canonicalized, so these
		// patterns are provably dead (or malformed) and must not compile.
		"https://user:pass@example.com/**",
		"https://example.com:99999/**",
		"https://example.com:12x/**",
		"https://example.com:0/**",
		// Bracketed non-IPs are glob character classes, not IPv6 literals;
		// treating them as IPv6 silently widened the rule.
		"https://[ab]x.example.com/**",
		"https://[fe80::*]/**",
		"https://[::1/**",
		// Only http/https are fetchable; a literal other scheme is dead.
		"ftp://example.com/**",
		// Hosts that cannot be canonicalized (underscore is rejected by the
		// IDNA lookup profile) can never match a normalized target.
		"https://my_service.internal/**",
	} {
		_, err := NewEngine([]config.Rule{{Match: match, Allow: bptr(false)}}, "allow")
		if err == nil {
			t.Errorf("pattern %q should be rejected at load", match)
		}
	}
	// Sanity: an ASCII wildcard over punycodable IDN labels stays valid
	// (covered behaviorally in TestMatrixWildcardIDN).
	if _, err := NewEngine([]config.Rule{{Match: "https://*.münchen.de/**", Allow: bptr(true)}}, "deny"); err != nil {
		t.Errorf("valid wildcard IDN pattern rejected: %v", err)
	}
}
