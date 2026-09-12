package rules

import (
	"testing"

	"github.com/amscotti/keyhole/internal/config"
)

// BenchmarkEvaluate measures the policy-decision hot path: normalize + match
// against a realistic rule set. This is called on every fetch request (and
// again on the final URL after redirects), so it must stay cheap.
func BenchmarkEvaluate(b *testing.B) {
	rules := []config.Rule{
		{Match: "https://internal.example.com/**", Allow: bptr(true), Transforms: []string{"raw", "markdown", "article"}},
		{Match: "https://internal.example.com/hr/**", Allow: bptr(false)},
		{Match: "https://docs.example.com/**", Allow: bptr(true), Transforms: []string{"markdown", "article"}},
		{Match: "https://example.com/**", Allow: bptr(true), Transforms: []string{"raw", "markdown", "article"}},
		{Match: "https://www.youtube.com/watch?v=*", Allow: bptr(true), Transforms: []string{"youtube"}, IgnoreQuery: true},
		{Match: "https://youtu.be/**", Allow: bptr(true), Transforms: []string{"youtube"}},
		{Match: "https://docs.example.com/**/*.docx", Allow: bptr(true), Transforms: []string{"office"}},
	}
	engine, err := NewEngine(rules, "deny")
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := engine.Evaluate("https://example.com/some/deep/path/page?query=value")
		if err != nil {
			b.Fatalf("Evaluate: %v", err)
		}
	}
}

// BenchmarkNormalize isolates the URL normalization step (called per Evaluate).
func BenchmarkNormalize(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		_, err := Normalize("https://EXAMPLE.com:443/some/deep/path/page?query=value#frag")
		if err != nil {
			b.Fatalf("Normalize: %v", err)
		}
	}
}
