package transform_test

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amscotti/keyhole/internal/transform"
)

var updateGoldens = flag.Bool("update", false, "regenerate golden files")

func TestMain(m *testing.M) {
	// Helper-process mode: re-executed as a child by
	// TestPandocRunnerOutputOverflowRealSubprocess (marker env set, pandoc
	// argv inherited). This branch runs before flag parsing, which the
	// inherited `-f/-t` argv would otherwise break.
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		os.Exit(helperUnboundedOutput())
	}
	flag.Parse()
	os.Exit(m.Run())
}

// helperUnboundedOutput emits far more than the runner's byte cap, then
// blocks until killed. Exiting 0 is unreachable in the passing case — the
// runner must kill the child promptly once output exceeds the cap.
func helperUnboundedOutput() int {
	chunk := []byte(strings.Repeat("unbounded-output-stand-in\n", 64))
	for i := 0; i < 64; i++ {
		if _, err := os.Stdout.Write(chunk); err != nil {
			return 1
		}
	}
	select {} // idle until the runner kills us
}

// loadFixture reads a file from testdata/.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// goldenPath returns the path for a golden file paired with an HTML fixture.
func goldenPath(htmlName string) string {
	base := strings.TrimSuffix(htmlName, ".html")
	return filepath.Join("testdata", base+".golden.md")
}

// checkGolden compares actual against the stored golden (or writes it with -update).
func checkGolden(t *testing.T, path, actual string) {
	t.Helper()
	if *updateGoldens {
		if err := os.WriteFile(path, []byte(actual), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", path, err)
	}
	if actual != string(want) {
		t.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", path, want, actual)
	}
}

func TestRawReturnsBodyVerbatim(t *testing.T) {
	t.Parallel()
	tr := transform.Raw{}
	body := []byte("<html><body>Hello</body></html>")
	res, err := tr.Apply(body, "text/html", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Content != string(body) {
		t.Errorf("raw content = %q, want %q", res.Content, body)
	}
}

func TestRawPreservesContentType(t *testing.T) {
	t.Parallel()
	tr := transform.Raw{}
	body := []byte("<html><body>Hello</body></html>")
	res, err := tr.Apply(body, "text/html; charset=utf-8", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(res.OutputType, "text/html") {
		t.Errorf("OutputType = %q, want text/html prefix", res.OutputType)
	}
}

func TestRawDefaultsContentTypeWhenEmpty(t *testing.T) {
	t.Parallel()
	tr := transform.Raw{}
	res, err := tr.Apply([]byte("plain"), "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OutputType == "" {
		t.Error("OutputType should not be empty when contentType is empty")
	}
}

func TestRawWorksWithAnyContentType(t *testing.T) {
	t.Parallel()
	tr := transform.Raw{}
	res, err := tr.Apply([]byte("plain text"), "text/plain", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Content != "plain text" {
		t.Errorf("content = %q", res.Content)
	}
}

// TestRawDecodesNonUTF8 pins the charset fix: the envelope is JSON and cannot
// carry ISO-8859-1 bytes, so raw must transcode to UTF-8 (instead of emitting
// replacement characters) and stop advertising the origin charset.
func TestRawDecodesNonUTF8(t *testing.T) {
	t.Parallel()
	tr := transform.Raw{}
	body := []byte("<html><body>caf\xe9</body></html>")
	res, err := tr.Apply(body, "text/html; charset=iso-8859-1", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Content, "café") {
		t.Errorf("content = %q, want decoded %q", res.Content, "café")
	}
	if strings.Contains(res.OutputType, "iso-8859-1") {
		t.Errorf("OutputType = %q must not advertise the origin charset", res.OutputType)
	}
	if !strings.Contains(strings.ToLower(res.OutputType), "utf-8") {
		t.Errorf("OutputType = %q should advertise utf-8", res.OutputType)
	}
}

// TestRawLeavesBinaryUntouched pins that non-textual bodies are not parsed as
// text (which would corrupt them further with the windows-1252 fallback).
func TestRawLeavesBinaryUntouched(t *testing.T) {
	t.Parallel()
	tr := transform.Raw{}
	body := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a}
	res, err := tr.Apply(body, "image/png", "https://example.com/i.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Content != string(body) {
		t.Errorf("binary content was modified: %q", res.Content)
	}
	if res.OutputType != "image/png" {
		t.Errorf("OutputType = %q, want image/png", res.OutputType)
	}
}

func TestMarkdownDecodesNonUTF8(t *testing.T) {
	t.Parallel()
	tr := transform.Markdown{}
	body := []byte("<html><body><p>caf\xe9</p></body></html>")
	res, err := tr.Apply(body, "text/html; charset=iso-8859-1", "https://example.com/page")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Content, "café") {
		t.Errorf("markdown = %q, want decoded %q", res.Content, "café")
	}
}

// TestMarkdownSniffsMetaCharset covers the header-less case: the charset is
// declared in the document, and the decoder must honor it.
func TestMarkdownSniffsMetaCharset(t *testing.T) {
	t.Parallel()
	tr := transform.Markdown{}
	body := []byte("<html><head><meta charset=\"iso-8859-1\"></head><body><p>caf\xe9</p></body></html>")
	res, err := tr.Apply(body, "text/html", "https://example.com/page")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Content, "café") {
		t.Errorf("markdown = %q, want decoded %q", res.Content, "café")
	}
}

func TestMarkdownRejectsNonHTML(t *testing.T) {
	t.Parallel()
	tr := transform.Markdown{}
	_, err := tr.Apply([]byte("hello"), "text/plain", "")
	if err == nil {
		t.Fatal("expected error for non-HTML markdown transform")
	}
	var te *transform.Error
	if !errors.As(err, &te) {
		t.Fatalf("expected *transform.Error, got %T", err)
	}
	if te.Code != transform.CodeUnsupported {
		t.Errorf("code = %q, want %q", te.Code, transform.CodeUnsupported)
	}
}

func TestMarkdownConvertsRichPage(t *testing.T) {
	t.Parallel()
	body := loadFixture(t, "rich.html")
	tr := transform.Markdown{}
	res, err := tr.Apply(body, "text/html; charset=utf-8", "https://example.com/guide")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGolden(t, goldenPath("rich.markdown"), res.Content)
}

func TestArticleRejectsNonHTML(t *testing.T) {
	t.Parallel()
	tr := transform.Article{}
	_, err := tr.Apply([]byte("hello"), "application/json", "")
	if err == nil {
		t.Fatal("expected error for non-HTML article transform")
	}
	var te *transform.Error
	if !errors.As(err, &te) {
		t.Fatalf("expected *transform.Error, got %T", err)
	}
	if te.Code != transform.CodeUnsupported {
		t.Errorf("code = %q, want %q", te.Code, transform.CodeUnsupported)
	}
}

// TestArticleFallsBackWhenReadabilityFindsNothing pins the degradation path:
// an SPA shell or body-less page must not surface as a 500 from a library
// internals error; it should come back as full-page Markdown.
func TestArticleFallsBackWhenReadabilityFindsNothing(t *testing.T) {
	t.Parallel()
	tr := transform.Article{}
	body := []byte(`<html><body><div id="root"></div></body></html>`)
	res, err := tr.Apply(body, "text/html; charset=utf-8", "https://example.com/app")
	if err != nil {
		t.Fatalf("expected fallback success, got error: %v", err)
	}
	if res.OutputType != "text/markdown; charset=utf-8" {
		t.Errorf("OutputType = %q", res.OutputType)
	}
}

func TestArticleExtractsCleanContent(t *testing.T) {
	t.Parallel()
	body := loadFixture(t, "noisy.html")
	tr := transform.Article{}
	res, err := tr.Apply(body, "text/html; charset=utf-8", "https://example.com/post")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGolden(t, goldenPath("noisy.article"), res.Content)

	if res.Metadata == nil {
		t.Fatal("expected non-nil metadata")
	}
	if title, ok := res.Metadata["title"]; !ok || title == "" {
		t.Error("expected non-empty title in metadata")
	}
}

func TestMarkdownIsNoisierThanArticle(t *testing.T) {
	t.Parallel()
	body := loadFixture(t, "noisy.html")

	mdRes, err := transform.Markdown{}.Apply(body, "text/html", "https://example.com/post")
	if err != nil {
		t.Fatalf("markdown: %v", err)
	}
	artRes, err := transform.Article{}.Apply(body, "text/html", "https://example.com/post")
	if err != nil {
		t.Fatalf("article: %v", err)
	}

	// The markdown output should contain the nav/ad/sidebar content that the
	// article extraction strips. We assert on a few marker strings present in
	// the fixture's noise sections.
	mdLower := strings.ToLower(mdRes.Content)
	for _, noise := range []string{"subscribe", "special offer", "related posts"} {
		if !strings.Contains(mdLower, noise) {
			t.Errorf("markdown output should contain noise marker %q (full output:\n%s)", noise, mdRes.Content)
		}
	}

	// The article output should NOT contain those noise markers.
	artLower := strings.ToLower(artRes.Content)
	for _, noise := range []string{"subscribe", "special offer", "related posts", "sponsored"} {
		if strings.Contains(artLower, noise) {
			t.Errorf("article output should NOT contain noise marker %q (full output:\n%s)", noise, artRes.Content)
		}
	}
}

func TestRegistryGet(t *testing.T) {
	t.Parallel()
	r := transform.NewRegistry()
	for _, name := range []string{"raw", "markdown", "article"} {
		tr, ok := r.Get(name)
		if !ok {
			t.Errorf("registry missing transform %q", name)
			continue
		}
		if tr.Name() != name {
			t.Errorf("transform name = %q, want %q", tr.Name(), name)
		}
	}
}

func TestRegistryUnknownTransform(t *testing.T) {
	t.Parallel()
	r := transform.NewRegistry()
	if _, ok := r.Get("nonexistent"); ok {
		t.Error("expected false for unknown transform")
	}
}
