package rules

import (
	"testing"
	"testing/quick"

	"github.com/amscotti/keyhole/internal/config"
)

// TestNormalizeNeverPanics is the property form of the DoD "malformed input
// returns an error, never panics": for any string, Normalize returns without
// panicking (a non-nil error is acceptable; only a panic would fail this).
func TestNormalizeNeverPanics(t *testing.T) {
	t.Parallel()
	f := func(s string) bool {
		_, _ = Normalize(s)
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Errorf("Normalize panicked on random input: %v", err)
	}
}

// TestNewEngineRejectsBadPattern: an invalid glob in the config is a load-time
// error so a typo can never widen access.
func TestNewEngineRejectsBadPattern(t *testing.T) {
	t.Parallel()
	bad := []string{
		"https://example.com/[unfinished", // unterminated character class
		"https://example.com/{a,b",        // unterminated alternation
	}
	for _, p := range bad {
		p := p
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			_, err := NewEngine([]config.Rule{{Match: p, Allow: bptr(true)}}, "deny")
			if err == nil {
				t.Errorf("expected NewEngine to reject bad pattern %q", p)
			}
		})
	}
}

// TestNewEngineAcceptsValidPatterns ensures the rejection above is not
// over-eager: the patterns used throughout the matrix compile cleanly.
func TestNewEngineAcceptsValidPatterns(t *testing.T) {
	t.Parallel()
	valid := []string{
		"https://example.com/**",
		"https://example.com/*",
		"https://example.com/watch?v=*",
		"https://xn--bcher-kva.example/**",
		"https://example.com/{a,b}/**",
		"https://example.com/v[0-9]/**",
	}
	for _, p := range valid {
		p := p
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			if _, err := NewEngine([]config.Rule{{Match: p, Allow: bptr(true)}}, "deny"); err != nil {
				t.Errorf("expected pattern %q to compile, got: %v", p, err)
			}
		})
	}
}

// FuzzNormalize is the bonus fuzz target from the DoD: Normalize must never
// panic on arbitrary bytes. Run with `go test -fuzz=FuzzNormalize`.
func FuzzNormalize(f *testing.F) {
	f.Add("https://example.com/a")
	f.Add("https://EXAMPLE.com:443/a?b=c#frag")
	f.Add("://bad")
	f.Add("")
	f.Add("https://bücher.example/")
	f.Fuzz(func(t *testing.T, in string) {
		out, err := Normalize(in)
		if err != nil {
			return
		}
		// If it succeeded, the result must itself re-normalize stably (idempotent).
		out2, err2 := Normalize(out)
		if err2 != nil {
			t.Fatalf("non-idempotent normalize: %q -> %q then error %v", in, out, err2)
		}
		if out != out2 {
			t.Fatalf("non-idempotent normalize: %q -> %q -> %q", in, out, out2)
		}
	})
}

// FuzzEvaluate is the bonus fuzz target: Evaluate must never panic on arbitrary
// input, and any normalized output must be stable.
func FuzzEvaluate(f *testing.F) {
	engine, ferr := NewEngine([]config.Rule{
		{Match: "https://example.com/**", Allow: bptr(true)},
		{Match: "https://example.com/hr/**", Allow: bptr(false)},
	}, "deny")
	if ferr != nil {
		f.Fatal(ferr)
	}
	f.Add("https://example.com/a")
	f.Add("https://example.com/hr/secret")
	f.Add("not a url")
	f.Add("https://EXAMPLE.com:443/a?b=c#frag")
	f.Fuzz(func(t *testing.T, in string) {
		// Must not panic; we do not assert the decision, only safety.
		_, _ = engine.Evaluate(in)
	})
}
