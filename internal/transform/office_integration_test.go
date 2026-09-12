//go:build integration

// Integration tests for the Office transform. These require the pandoc binary
// (mise-pinned) and are excluded from the default gate (`mise run test`). Run
// them with `mise run test-integration` (which sets -tags=integration).
//
// Per the Phase 6 Definition of Done, each test skips cleanly with a clear
// message when pandoc is absent or a required reader is missing — it never
// fakes a pass.
package transform_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amscotti/keyhole/internal/transform"
)

// requirePandoc skips the test when pandoc is not on PATH. Returns the pandoc
// path so tests can pass it to the transform.
func requirePandoc(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("pandoc")
	if err != nil {
		t.Skip("pandoc not installed — skipping office integration test")
	}
	return path
}

// pandocHasReader verifies the installed pandoc lists format as an input
// reader. When a reader is missing the calling test skips with a note, matching
// the DoD: ".pptx and .xlsx fixtures convert if the installed pandoc readers
// support them; if a reader is missing, the test skips with a message".
func pandocHasReader(t *testing.T, format string) {
	t.Helper()
	out, err := exec.Command("pandoc", "--list-input-formats").Output()
	if err != nil {
		t.Skipf("could not list pandoc input formats: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == format {
			return
		}
	}
	t.Skipf("pandoc does not list reader for %q — skipping (note: file an issue; do not fake it)", format)
}

// officeFixture loads a binary office fixture from testdata/.
func officeFixture(t *testing.T, name string) []byte {
	t.Helper()
	return loadFixture(t, name)
}

// TestIntegrationOfficeDocxGolden converts the sample.docx fixture to GFM and
// compares against the committed golden file. The DoD: "A fixture .docx converts
// to GFM with headings, lists, and tables intact (golden file)."
func TestIntegrationOfficeDocxGolden(t *testing.T) {
	pandocHasReader(t, "docx")
	path := requirePandoc(t)

	body := officeFixture(t, "sample.docx")
	o := transform.NewOffice(transform.OfficeOptions{
		PandocPath: path,
		Timeout:    30 * time.Second,
	})
	res, err := o.Apply(
		body,
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"https://example.com/sample.docx",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGolden(t, goldenPath("sample.docx"), res.Content)

	// Assert the structural elements the DoD names are intact.
	md := res.Content
	for _, marker := range []string{"# Heading One", "## Heading Two", "- Item one", "1.  First", "| Name", "Alpha"} {
		if !strings.Contains(md, marker) {
			t.Errorf("docx output missing %q\n--- output ---\n%s", marker, md)
		}
	}
}

// TestIntegrationOfficePptx converts the sample.pptx fixture and asserts a
// table and list content survive the round-trip. Skips if the pptx reader is
// unavailable.
func TestIntegrationOfficePptx(t *testing.T) {
	pandocHasReader(t, "pptx")
	path := requirePandoc(t)

	body := officeFixture(t, "sample.pptx")
	o := transform.NewOffice(transform.OfficeOptions{
		PandocPath: path,
		Timeout:    30 * time.Second,
	})
	res, err := o.Apply(
		body,
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"https://example.com/sample.pptx",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// pptx conversion is lossier than docx (inline styling is stripped) but the
	// table and list items should survive.
	for _, marker := range []string{"Item one", "| Name", "Alpha"} {
		if !strings.Contains(res.Content, marker) {
			t.Errorf("pptx output missing %q\n--- output ---\n%s", marker, res.Content)
		}
	}
}

// TestIntegrationOfficeXlsx converts the sample.xlsx fixture and asserts the
// table is present. Skips if the xlsx reader is unavailable.
func TestIntegrationOfficeXlsx(t *testing.T) {
	pandocHasReader(t, "xlsx")
	path := requirePandoc(t)

	body := officeFixture(t, "sample.xlsx")
	o := transform.NewOffice(transform.OfficeOptions{
		PandocPath: path,
		Timeout:    30 * time.Second,
	})
	res, err := o.Apply(
		body,
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"https://example.com/sample.xlsx",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, marker := range []string{"Sheet1", "| Name", "Alpha", "Beta"} {
		if !strings.Contains(res.Content, marker) {
			t.Errorf("xlsx output missing %q\n--- output ---\n%s", marker, res.Content)
		}
	}
}

// TestIntegrationOfficeTimeout verifies a hanging pandoc is killed after the
// configured timeout and surfaces a timeout error. A 1ms timeout reliably
// fires before pandoc can start and convert a real document.
func TestIntegrationOfficeTimeout(t *testing.T) {
	path := requirePandoc(t)

	body := officeFixture(t, "sample.docx")
	o := transform.NewOffice(transform.OfficeOptions{
		PandocPath: path,
		Timeout:    1 * time.Millisecond,
	})
	_, err := o.Apply(
		body,
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"https://example.com/sample.docx",
	)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	var te *transform.Error
	if !errors.As(err, &te) {
		t.Fatalf("expected *transform.Error, got %T (%v)", err, err)
	}
	if te.Code != transform.CodeTimeout {
		t.Errorf("code = %q, want %q", te.Code, transform.CodeTimeout)
	}
}

// TestIntegrationOfficeRegistry verifies the Office transform is registered and
// discoverable via the registry name "office" (used by the REST handler when a
// rule lists transforms = ["office"]).
func TestIntegrationOfficeRegistry(t *testing.T) {
	o := transform.NewOffice(transform.OfficeOptions{})
	r := transform.NewRegistry()
	r.Register(o)
	got, ok := r.Get("office")
	if !ok {
		t.Fatal(`registry missing "office" transform`)
	}
	if got.Name() != "office" {
		t.Errorf("name = %q, want %q", got.Name(), "office")
	}
}

// TestIntegrationOfficeOdt exercises the allowlisted odt path. There is no
// committed binary odt fixture; one is generated with the same pinned pandoc
// and converted back, so the format is verified rather than merely advertised.
func TestIntegrationOfficeOdt(t *testing.T) {
	pandocHasReader(t, "odt")
	path := requirePandoc(t)

	dir := t.TempDir()
	src := filepath.Join(dir, "in.md")
	odt := filepath.Join(dir, "sample.odt")
	if err := os.WriteFile(src, []byte("# ODT Heading\n\n- Item one\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if out, err := exec.Command(path, "-f", "markdown", "-t", "odt", "-o", odt, src).CombinedOutput(); err != nil {
		t.Skipf("could not generate odt with pandoc: %v (%s)", err, out)
	}
	body, err := os.ReadFile(odt)
	if err != nil {
		t.Fatalf("read generated odt: %v", err)
	}

	o := transform.NewOffice(transform.OfficeOptions{PandocPath: path, Timeout: 30 * time.Second})
	res, err := o.Apply(body, "application/vnd.oasis.opendocument.text", "https://example.com/sample.odt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, marker := range []string{"ODT Heading", "Item one"} {
		if !strings.Contains(res.Content, marker) {
			t.Errorf("odt output missing %q\n--- output ---\n%s", marker, res.Content)
		}
	}
}
