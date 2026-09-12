package rules

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		// The Definition-of-Done golden case from PLAN.md Phase 2.
		{"dod", "https://EXAMPLE.com:443/a?b=c#frag", "https://example.com/a?b=c"},

		{"lowercase scheme and host", "HTTPS://Example.COM/Path", "https://example.com/Path"},
		{"strip default https port", "https://example.com:443/", "https://example.com/"},
		{"strip default http port", "http://example.com:80/", "http://example.com/"},
		{"keep non-default port", "https://example.com:8443/", "https://example.com:8443/"},
		{"strip fragment", "https://example.com/a#section", "https://example.com/a"},
		{"strip fragment keep query", "https://example.com/a?x=1#f", "https://example.com/a?x=1"},
		{"preserve query", "https://example.com/a?b=c&d=e", "https://example.com/a?b=c&d=e"},
		{"preserve path case", "https://example.com/Foo/Bar", "https://example.com/Foo/Bar"},
		{"idn punycode", "https://Bücher.example/a", "https://xn--bcher-kva.example/a"},
		{"idn punycode whole tree", "https://münchen.de/path", "https://xn--mnchen-3ya.de/path"},
		{"already punycode stays", "https://xn--bcher-kva.example/a", "https://xn--bcher-kva.example/a"},
		// R1: trailing DNS dot is stripped so targets and patterns agree.
		{"trailing dot stripped", "https://example.com./a", "https://example.com/a"},
		{"trailing slash path", "https://example.com/a/", "https://example.com/a/"},
		{"ipv4 literal", "http://192.168.1.1:8080/x", "http://192.168.1.1:8080/x"},
		// M1: an empty path is normalised to "/" so a bare-host URL matches /**.
		{"empty path normalized to root", "https://example.com", "https://example.com/"},
		{"empty path with query normalized to root", "https://example.com?a=1", "https://example.com/?a=1"},

		// B1: dot-segment resolution (RFC 3986 §5.2.4). The upstream server
		// resolves "."/".." segments, so policy must match the resolved path
		// — never the verbatim request path.
		{"dot segment resolved", "https://example.com/a/./b", "https://example.com/a/b"},
		{"dot dot resolved", "https://example.com/public/../secret", "https://example.com/secret"},
		{"dot dot escapes root clamped", "https://example.com/../secret", "https://example.com/secret"},
		{"dot dot multiple escapes clamped", "https://example.com/a/../../../b", "https://example.com/b"},
		{"trailing dot preserved through resolution", "https://example.com/a/b/../", "https://example.com/a/"},
		{"trailing single dot resolved", "https://example.com/a/.", "https://example.com/a/"},
		// Percent-encoded dots are decoded by url.Parse into u.Path, so they
		// participate in dot-segment resolution before matching.
		{"encoded dot dot resolved", "https://example.com/public/%2e%2e/secret", "https://example.com/secret"},
		{"encoded dot dot uppercase resolved", "https://example.com/public/%2E%2E/secret", "https://example.com/secret"},
		{"encoded dot slash resolved", "https://example.com/..%2fsecret", "https://example.com/secret"},
		// Legitimate percent-encoding is preserved through resolution.
		{"percent encoded space preserved", "https://example.com/a%20b", "https://example.com/a%20b"},
		// M1: userinfo is stripped so credentials don't ride into the normalized
		// form (where logging/metrics could touch them) and don't prevent a
		// host-scoped glob from matching.
		{"userinfo stripped", "http://user:pass@example.com/a", "http://example.com/a"},
		{"userinfo stripped https", "https://token@example.com/a", "https://example.com/a"},

		// Policy and dialing must agree on IP literals: resolvers accept
		// packed/hex/octal/short forms, so all spellings canonicalize to the
		// address actually dialed (otherwise a deny rule on the canonical
		// form is silently bypassed).
		{"packed decimal ip", "http://2130706433/x", "http://127.0.0.1/x"},
		{"packed decimal public ip", "http://3405803781/x", "http://203.0.113.5/x"},
		{"hex ip", "http://0x7f000001/x", "http://127.0.0.1/x"},
		{"octal ip", "http://0177.0.0.1/x", "http://127.0.0.1/x"},
		{"short ip", "http://127.1/x", "http://127.0.0.1/x"},
		{"three part ip", "http://127.0.1/x", "http://127.0.0.1/x"},
		{"expanded ipv6", "http://[0:0:0:0:0:0:0:1]/x", "http://[::1]/x"},
		{"ipv4 mapped ipv6 unmapped", "http://[::ffff:127.0.0.1]/x", "http://127.0.0.1/x"},

		// Ports are numeric, not textual: ":0443" dials 443, so it must not
		// sidestep a port-less deny rule.
		{"leading zero default port stripped", "https://example.com:0443/x", "https://example.com/x"},
		{"leading zero non-default port canonicalized", "http://example.com:08080/x", "http://example.com:8080/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Normalize(tc.in)
			if err != nil {
				t.Fatalf("Normalize(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("Normalize(%q)\n  got:  %q\n  want: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeErrors(t *testing.T) {
	t.Parallel()
	bad := []string{
		"",                 // empty
		"not a url at all", // no scheme/host
		"://missing-scheme",
		"/just/a/path",
		"ftp://example.com/x",              // unsupported scheme (only http/https)
		"https://example.com:0/x",          // port zero
		"https://example.com:99999/x",      // port out of range
		"https://example.com:12x/x",        // non-numeric port
		"https://./x",                      // empty host after trailing-dot strip
		"https://999.1.1.1/x",              // numeric-like IP out of range
		"https://09.0.0.1/x",               // malformed octal numeric form
		strings.Repeat("a", MaxURLBytes+1), // URL length cap
	}
	for _, in := range bad {
		in := in
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			if _, err := Normalize(in); err == nil {
				t.Errorf("Normalize(%q) expected an error, got nil", in)
			}
		})
	}
}

// TestResolveDotSegmentsIsLinear guards the DoS fix: the earlier
// string-concatenation implementation copied the remaining input (and the
// accumulated output) once per segment, so a large path burned quadratic CPU.
// The allocation count is the observable signal — a linear implementation
// allocates the output buffer and the result string, nothing per segment.
func TestResolveDotSegmentsIsLinear(t *testing.T) {
	// Not parallel: testing.AllocsPerRun must own the process.
	p := "/a" + strings.Repeat("/../", 100000) + "x"
	allocs := testing.AllocsPerRun(3, func() { _ = resolveDotSegments(p) })
	if allocs > 10 {
		t.Fatalf("resolveDotSegments allocated %v times for %d segments; want a linear implementation", allocs, 100000)
	}
	if got := resolveDotSegments("/a/b/../c/./d/"); got != "/a/c/d/" {
		t.Fatalf("resolveDotSegments semantics changed: got %q", got)
	}
}
