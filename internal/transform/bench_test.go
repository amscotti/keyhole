package transform_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/amscotti/keyhole/internal/transform"
)

// BenchmarkMarkdown measures the HTML→Markdown conversion — the most
// CPU-intensive transform. It uses the rich fixture (headings, links, tables,
// code blocks) to represent a realistic page.
func BenchmarkMarkdown(b *testing.B) {
	html, err := os.ReadFile(filepath.Join("testdata", "rich.html"))
	if err != nil {
		b.Fatalf("read fixture: %v", err)
	}
	tr := transform.Markdown{}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := tr.Apply(html, "text/html; charset=utf-8", "https://example.com/page")
		if err != nil {
			b.Fatalf("Apply: %v", err)
		}
	}
}
