package transform

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestOfficeFormatByContentType verifies the content-type → pandoc format
// dispatch. Only the allowlisted Office MIME types reach pandoc; everything else
// is an unsupported error so pandoc is never fed a format it does not read.
func TestOfficeFormatByContentType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		contentType string
		sourceURL   string
		want        string
	}{
		{
			name:        "docx openxml",
			contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			sourceURL:   "https://example.com/doc",
			want:        "docx",
		},
		{
			name:        "docx openxml with charset param",
			contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document; charset=binary",
			sourceURL:   "https://example.com/doc",
			want:        "docx",
		},
		{
			name:        "pptx openxml",
			contentType: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
			sourceURL:   "https://example.com/deck",
			want:        "pptx",
		},
		{
			name:        "xlsx openxml",
			contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			sourceURL:   "https://example.com/sheet",
			want:        "xlsx",
		},
		{
			name:        "odt oasis",
			contentType: "application/vnd.oasis.opendocument.text",
			sourceURL:   "https://example.com/doc",
			want:        "odt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := officeFormat(tc.contentType, tc.sourceURL)
			if !ok {
				t.Fatalf("officeFormat(%q) = false, want true", tc.contentType)
			}
			if got != tc.want {
				t.Errorf("officeFormat(%q) = %q, want %q", tc.contentType, got, tc.want)
			}
		})
	}
}

// TestOfficeFormatByExtensionFallback verifies that when the content-type is
// generic or missing, the format is inferred from the URL extension.
func TestOfficeFormatByExtensionFallback(t *testing.T) {
	t.Parallel()
	cases := []struct {
		contentType string
		sourceURL   string
		want        string
	}{
		{contentType: "application/octet-stream", sourceURL: "https://example.com/report.docx", want: "docx"},
		{contentType: "application/octet-stream", sourceURL: "https://example.com/deck.pptx", want: "pptx"},
		{contentType: "application/octet-stream", sourceURL: "https://example.com/data.xlsx", want: "xlsx"},
		{contentType: "application/octet-stream", sourceURL: "https://example.com/notes.odt", want: "odt"},
		{contentType: "", sourceURL: "https://example.com/report.docx?download=1", want: "docx"},
		{contentType: "binary", sourceURL: "https://example.com/UPPER.DOCX", want: "docx"},
	}
	for _, tc := range cases {
		got, ok := officeFormat(tc.contentType, tc.sourceURL)
		if !ok {
			t.Fatalf("officeFormat(%q, %q) = false, want true", tc.contentType, tc.sourceURL)
		}
		if got != tc.want {
			t.Errorf("officeFormat(%q, %q) = %q, want %q", tc.contentType, tc.sourceURL, got, tc.want)
		}
	}
}

// TestOfficeFormatUnknownTypeIsRejected verifies that non-Office content types
// and non-Office extensions do not dispatch to pandoc.
func TestOfficeFormatUnknownTypeIsRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		contentType string
		sourceURL   string
	}{
		{contentType: "text/html", sourceURL: "https://example.com/page"},
		{contentType: "application/pdf", sourceURL: "https://example.com/doc.pdf"},
		{contentType: "application/json", sourceURL: "https://example.com/data.json"},
		{contentType: "", sourceURL: "https://example.com/noext"},
	}
	for _, tc := range cases {
		if _, ok := officeFormat(tc.contentType, tc.sourceURL); ok {
			t.Errorf("officeFormat(%q, %q) should be false", tc.contentType, tc.sourceURL)
		}
	}
}

// TestOfficeApplyUnsupportedContentType verifies the Apply path returns a typed
// unsupported error for content the office transform cannot handle.
func TestOfficeApplyUnsupportedContentType(t *testing.T) {
	t.Parallel()
	o := NewOffice(OfficeOptions{PandocPath: "/nonexistent/pandoc", Timeout: time.Second})
	_, err := o.Apply([]byte("x"), "text/html", "https://example.com/page")
	if err == nil {
		t.Fatal("expected error for non-office content type")
	}
	var te *Error
	if !errors.As(err, &te) {
		t.Fatalf("expected *transform.Error, got %T", err)
	}
	if te.Code != CodeUnsupported {
		t.Errorf("code = %q, want %q", te.Code, CodeUnsupported)
	}
}

// TestOfficePandocMissingReturnsUnsupported verifies that a missing pandoc
// binary yields a clean unsupported error — never a panic or empty content.
// This is the Phase 6 DoD item: "Pandoc absent → clean unsupported error".
func TestOfficePandocMissingReturnsUnsupported(t *testing.T) {
	t.Parallel()
	o := NewOffice(OfficeOptions{
		PandocPath: "/definitely/not/installed/pandoc-binary",
		Timeout:    5 * time.Second,
	})
	_, err := o.Apply(
		[]byte("fake docx"),
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"https://example.com/doc.docx",
	)
	if err == nil {
		t.Fatal("expected error when pandoc is missing")
	}
	var te *Error
	if !errors.As(err, &te) {
		t.Fatalf("expected *transform.Error, got %T (%v)", err, err)
	}
	if te.Code != CodeUnsupported {
		t.Errorf("code = %q, want %q", te.Code, CodeUnsupported)
	}
	if !strings.Contains(te.Message, "pandoc") {
		t.Errorf("error message should mention pandoc, got %q", te.Message)
	}
}

// TestOfficeConvertTimeout verifies the timeout path: when the context deadline
// is exceeded, the error is classified as CodeTimeout. This uses a fake runner
// that blocks until the context is cancelled, so it does not require real
// pandoc and runs in the default test gate.
func TestOfficeConvertTimeout(t *testing.T) {
	t.Parallel()
	o := &Office{
		opts: OfficeOptions{
			PandocPath: "pandoc",
			Timeout:    50 * time.Millisecond,
			MaxBytes:   defaultOfficeMaxBytes,
		},
		runner: blockingRunner{},
	}
	_, err := o.convert(context.Background(), "docx", []byte("data"))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var te *Error
	if !errors.As(err, &te) {
		t.Fatalf("expected *transform.Error, got %T (%v)", err, err)
	}
	if te.Code != CodeTimeout {
		t.Errorf("code = %q, want %q", te.Code, CodeTimeout)
	}
}

// TestOfficeConvertOutputOverflow verifies the output size cap: when pandoc
// produces more than MaxBytes, the result is a too_large error. Uses a fake
// runner that emits a fixed large payload, so no real pandoc is needed.
func TestOfficeConvertOutputOverflow(t *testing.T) {
	t.Parallel()
	o := &Office{
		opts: OfficeOptions{
			PandocPath: "pandoc",
			Timeout:    5 * time.Second,
			MaxBytes:   16,
		},
		runner: fixedRunner{output: bytes.Repeat([]byte("x"), 100)},
	}
	_, err := o.convert(context.Background(), "docx", []byte("data"))
	if err == nil {
		t.Fatal("expected too_large error")
	}
	var te *Error
	if !errors.As(err, &te) {
		t.Fatalf("expected *transform.Error, got %T (%v)", err, err)
	}
	if te.Code != CodeTooLarge {
		t.Errorf("code = %q, want %q", te.Code, CodeTooLarge)
	}
}

// --- fake runners for unit tests (no real pandoc needed) ---
// Implementations of officeRunner so timeout and overflow paths are unit-
// testable without pandoc installed.

// blockingRunner simulates a pandoc process that hangs until the context
// expires, exercising the timeout classification.
type blockingRunner struct{}

func (blockingRunner) run(ctx context.Context, _ string, _ []byte, _ int64) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// fixedRunner returns a predetermined output regardless of input. When the
// output exceeds maxOut the convert method detects overflow.
type fixedRunner struct{ output []byte }

func (f fixedRunner) run(_ context.Context, _ string, _ []byte, _ int64) ([]byte, error) {
	return f.output, nil
}

// TestPandocRunnerOutputOverflowRealSubprocess drives the real pandocRunner
// against a single-process stand-in that emits unbounded output (yes repeats
// its arguments forever). The runner must kill the child promptly (not stall
// until the context deadline) and return a typed too_large error — previously
// the child blocked on a full stdout pipe, Wait() hung until the timeout
// fired, and the caller saw a misleading timeout classification.
func TestPandocRunnerOutputOverflowRealSubprocess(t *testing.T) {
	yes, err := exec.LookPath("yes")
	if err != nil {
		t.Skip("no `yes` binary available as an unbounded-output stand-in")
	}

	r := pandocRunner{path: yes}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err = r.run(ctx, "docx", []byte("doc"), 4096)
	elapsed := time.Since(start)

	var te *Error
	if !errors.As(err, &te) {
		t.Fatalf("want *transform.Error, got %v", err)
	}
	if te.Code != CodeTooLarge {
		t.Fatalf("code = %q, want %q", te.Code, CodeTooLarge)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("runner stalled for %v; the overflow path must kill the child promptly", elapsed)
	}
}

// gateRunner blocks until released, letting the test hold the single
// concurrency slot while a second conversion tries to queue.
type gateRunner struct {
	release <-chan struct{}
	started chan struct{}
}

func (g gateRunner) run(_ context.Context, _ string, _ []byte, _ int64) ([]byte, error) {
	close(g.started)
	<-g.release
	return []byte("ok"), nil
}

// TestOfficeConvertQueueTimeout verifies the concurrency bound: with one slot
// held by an in-flight conversion, a second conversion waits at most the
// conversion timeout and then fails with a typed timeout error naming the
// queue — instead of stacking pandoc subprocesses without limit.
func TestOfficeConvertQueueTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	started := make(chan struct{})
	o := &Office{
		opts: OfficeOptions{
			PandocPath:     "pandoc",
			Timeout:        150 * time.Millisecond,
			MaxBytes:       1024,
			MaxConcurrency: 1,
		},
		runner: gateRunner{release: release, started: started},
		sem:    make(chan struct{}, 1),
	}

	done := make(chan error, 1)
	go func() {
		_, err := o.convert(context.Background(), "docx", []byte("first"))
		done <- err
	}()
	<-started // first conversion now holds the slot

	_, err := o.convert(context.Background(), "docx", []byte("second"))
	var te *Error
	if !errors.As(err, &te) {
		t.Fatalf("want *transform.Error, got %v", err)
	}
	if te.Code != CodeTimeout {
		t.Fatalf("code = %q, want %q", te.Code, CodeTimeout)
	}
	if !strings.Contains(te.Message, "queue") {
		t.Fatalf("message should name the queue, got %q", te.Message)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first conversion should succeed after release, got %v", err)
	}

	// Slot freed: a third conversion runs immediately.
	started2 := make(chan struct{})
	o2 := &Office{
		opts:   o.opts,
		runner: gateRunner{release: release, started: started2},
		sem:    make(chan struct{}, 1),
	}
	go func() { _, _ = o2.convert(context.Background(), "docx", []byte("third")) }()
	select {
	case <-started2:
	case <-time.After(2 * time.Second):
		t.Fatal("conversion should start immediately once the slot is free")
	}
}

// TestOfficeApplyContextPropagatesCancellation verifies the cancellation fix:
// ApplyContext must honor the caller's context so a disconnected client aborts
// the pandoc work instead of holding a conversion slot until [office].timeout.
// A pre-canceled context must fail — with the old context.Background() wiring
// the same call succeeded.
func TestOfficeApplyContextPropagatesCancellation(t *testing.T) {
	t.Parallel()
	rec := &ctxCaptureRunner{}
	o := &Office{
		opts: OfficeOptions{
			PandocPath: "pandoc",
			Timeout:    5 * time.Second,
			MaxBytes:   defaultOfficeMaxBytes,
		},
		runner: rec,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // client already gone
	_, err := o.ApplyContext(ctx, []byte("data"),
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"http://example.test/doc.docx")
	if err == nil {
		t.Fatal("expected cancellation error for pre-canceled context; got success (context not propagated)")
	}
	if rec.got == nil {
		t.Fatal("runner never invoked")
	}
	select {
	case <-rec.got.Done():
	default:
		t.Fatal("runner context is not done; the request context was not propagated")
	}
}

// ctxCaptureRunner records the context it receives so tests can prove the
// request context (not a background one) reaches the subprocess.
type ctxCaptureRunner struct{ got context.Context }

func (r *ctxCaptureRunner) run(ctx context.Context, _ string, _ []byte, _ int64) ([]byte, error) {
	r.got = ctx
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []byte("# ok"), nil
}
