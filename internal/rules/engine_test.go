package rules

import (
	"testing"
	"testing/quick"

	"github.com/amscotti/keyhole/internal/config"
)

// bptr returns a pointer to b, to build config.Rule.Allow in tests (the field is
// a pointer so that omitting it is a detectable load error).
func bptr(b bool) *bool { return &b }

func TestEvaluate_DefaultPolicyDeny(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "deny") // no rules
	d, err := e.Evaluate("https://example.com/a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Error("default_policy=deny with no matching rule should deny")
	}
}

func TestEvaluate_DefaultPolicyAllow(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "allow")
	d, err := e.Evaluate("https://example.com/a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Error("default_policy=allow with no matching rule should allow")
	}
}

func TestEvaluate_ExactURLAllow(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://example.com/a", Allow: bptr(true)})
	d, err := e.Evaluate("https://example.com/a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Error("exact match allow rule should allow")
	}
}

func TestEvaluate_ExactURLNoMatch(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://example.com/a", Allow: bptr(true)})
	d, err := e.Evaluate("https://example.com/b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Error("non-matching exact rule with deny default should deny")
	}
}

func TestEvaluate_SingleStarWithinSegment(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://example.com/*", Allow: bptr(true)})
	mustAllow := func(url string, want bool) {
		t.Helper()
		d, err := e.Evaluate(url)
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", url, err)
		}
		if d.Allowed != want {
			t.Errorf("Evaluate(%q): Allowed=%v want %v", url, d.Allowed, want)
		}
	}
	mustAllow("https://example.com/foo", true)      // single segment
	mustAllow("https://example.com/", true)         // matches empty segment
	mustAllow("https://example.com/foo/bar", false) // * does not cross /
}

func TestEvaluate_DoubleStarWholeDomain(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://example.com/**", Allow: bptr(true)})
	mustAllow := func(url string, want bool) {
		t.Helper()
		d, err := e.Evaluate(url)
		if err != nil {
			t.Fatalf("Evaluate(%q): %v", url, err)
		}
		if d.Allowed != want {
			t.Errorf("Evaluate(%q): Allowed=%v want %v", url, d.Allowed, want)
		}
	}
	mustAllow("https://example.com/foo", true)
	mustAllow("https://example.com/foo/bar/baz", true) // ** crosses segments
	mustAllow("https://example.com/", true)
}

func TestEvaluate_MostSpecificWins(t *testing.T) {
	t.Parallel()
	// Broad allow, narrow deny: the narrow rule must win.
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://example.com/**", Allow: bptr(true)},
		config.Rule{Match: "https://example.com/hr/**", Allow: bptr(false)})

	d, err := e.Evaluate("https://example.com/hr/secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Error("more-specific deny must win over broad allow")
	}
	if d.Rule == nil || d.Rule.Match != "https://example.com/hr/**" {
		t.Errorf("expected winning rule to be the hr deny, got %+v", d.Rule)
	}

	// Outside the carve-out the broad allow still applies.
	d2, err := e.Evaluate("https://example.com/public")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d2.Allowed {
		t.Error("broad allow must still apply outside the deny carve-out")
	}
}

func TestEvaluate_MostSpecificAllowBeatsBroadDeny(t *testing.T) {
	t.Parallel()
	// The reverse carve-out: broad deny, narrow allow must permit the carve-out.
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://example.com/**", Allow: bptr(false)},
		config.Rule{Match: "https://example.com/public/**", Allow: bptr(true)})

	d, err := e.Evaluate("https://example.com/public/doc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Error("more-specific allow must win over broad deny (carve-outs work both ways)")
	}
}

// TestEvaluate_SuffixRuleOutranksSamePrefixBroadRule pins the secondary
// specificity rule: "host/**/*.docx" and "host/**" share a literal prefix, so
// the decision must go to the pattern with more literal content (the .docx
// rule) even when it is listed second. Without this, a broad rule's transform
// allowlist (or auth_profile) silently shadows the narrow rule — the shipped
// config.example.toml office example could never win.
func TestEvaluate_SuffixRuleOutranksSamePrefixBroadRule(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://docs.example.com/**", Allow: bptr(true), Transforms: []string{"markdown"}},
		config.Rule{Match: "https://docs.example.com/**/*.docx", Allow: bptr(true), Transforms: []string{"office"}})

	d, err := e.Evaluate("https://docs.example.com/a/file.docx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Rule == nil || d.Rule.Match != "https://docs.example.com/**/*.docx" {
		t.Fatalf("winning rule = %+v, want the .docx rule", d.Rule)
	}
	if !AllowsTransform(*d.Rule, "office") {
		t.Fatal("the .docx rule must allow the office transform")
	}
}

func TestEvaluate_TieGoesToDeny(t *testing.T) {
	t.Parallel()
	// Two rules with equal specificity but different intent; deny wins.
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://example.com/path", Allow: bptr(true)},
		config.Rule{Match: "https://example.com/path", Allow: bptr(false)})

	d, err := e.Evaluate("https://example.com/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Error("equal-specificity tie must resolve to deny (fail closed)")
	}
}

func TestEvaluate_DenyOverridesAllow(t *testing.T) {
	t.Parallel()
	// Definition-of-Down bullet: a deny among the most-specific matching rules
	// overrides an allow at the same specificity.
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://example.com/v1/**", Allow: bptr(true)},
		config.Rule{Match: "https://example.com/v1/**", Allow: bptr(false)})

	d, err := e.Evaluate("https://example.com/v1/x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Error("deny must override allow at equal specificity")
	}
	if d.Rule == nil || d.Rule.Allowed() {
		t.Error("winning rule must be the deny")
	}
}

// TestEvaluate_PatternNormalized proves R1: deny rules written with a
// non-canonical authority (uppercase host, explicit default port, trailing DNS
// dot, uppercase scheme) must still match a normally-presented URL. Without
// pattern normalization at compile time these deny rules are silently dead,
// widening access under default-allow (blocklist mode, PLAN.md:50).
func TestEvaluate_PatternNormalized(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		pattern string
		url     string
	}{
		{"uppercase host", "https://EXAMPLE.com/**", "https://example.com/secret"},
		{"uppercase scheme", "HTTPS://example.com/**", "https://example.com/secret"},
		{"explicit default https port", "https://example.com:443/**", "https://example.com/secret"},
		{"explicit default http port", "http://example.com:80/**", "http://example.com/secret"},
		{"trailing dot host", "https://example.com./**", "https://example.com/secret"},
		{"idn pattern canonicalized", "https://Bücher.example/**", "https://xn--bcher-kva.example/a"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := mustEngine(t, "allow",
				config.Rule{Match: tc.pattern, Allow: bptr(false)})
			d, err := e.Evaluate(tc.url)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Allowed {
				t.Errorf("deny rule %q should block %q under default-allow (rule is silently dead without pattern normalization)",
					tc.pattern, tc.url)
			}
		})
	}
}

// TestEvaluate_PatternNormalizedPreservesNonDefaultPort ensures the pattern
// normalizer does not strip a non-default port.
func TestEvaluate_PatternNormalizedPreservesNonDefaultPort(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://EXAMPLE.com:8443/**", Allow: bptr(true)})
	// Default-port URL must NOT match the non-default-port pattern.
	d, err := e.Evaluate("https://example.com/secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Error("non-default-port pattern should not match default-port URL")
	}
	// Non-default-port URL must match.
	d, err = e.Evaluate("https://example.com:8443/secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Error("non-default-port pattern should match non-default-port URL")
	}
}

func TestEvaluate_MalformedNeverPanics(t *testing.T) {
	t.Parallel()
	e := mustEngine(t, "deny",
		config.Rule{Match: "https://example.com/**", Allow: bptr(true)})
	// Property: any input string must return (no panic); malformed → error.
	f := func(s string) bool {
		_, _ = e.Evaluate(s)
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Errorf("Evaluate panicked or misbehaved on random input: %v", err)
	}
}

// mustEngine builds an Engine from defaultPolicy + rules, failing the test on a
// compile error (e.g. a bad glob pattern in the test fixture).
func mustEngine(t *testing.T, defaultPolicy string, rules ...config.Rule) *Engine {
	t.Helper()
	e, err := NewEngine(rules, defaultPolicy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}
