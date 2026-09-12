package transform

// Office transform.
//
// Office documents (docx, pptx, xlsx, odt) fetched as binary blobs are
// converted to GitHub-Flavoured Markdown by shelling out to the optional pandoc
// binary (mise-pinned). Pandoc reads the document from stdin and writes GFM to
// stdout — no temp files are needed: the installed pandoc 3.x readers accept
// all supported formats on stdin (verified: `pandoc -f <fmt> -t gfm -` works
// for docx, pptx, xlsx, and odt).
//
// Only allowlisted content-types (and, as a fallback, allowlisted file
// extensions) reach pandoc. A missing pandoc binary yields a clean unsupported
// error ("office conversion requires pandoc") rather than a panic. A hanging
// pandoc is killed after [office].timeout and surfaces as a timeout error.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/amscotti/keyhole/internal/model"
)

// defaultOfficeMaxBytes caps pandoc's stdout. The fetched input is already
// bounded by [network].max_size, but pandoc's Markdown output can be larger
// than the binary source (e.g. expanding a compressed xlsx). This is a safety
// bound, not the user-facing truncation limit — the server's [output].max_chars
// handles that.
const defaultOfficeMaxBytes = 50 * 1024 * 1024 // 50 MiB

// OfficeOptions configures the Office transform. It mirrors [office] in the TOML
// config plus the output cap that keeps pandoc stdout bounded.
type OfficeOptions struct {
	// PandocPath is the path to the pandoc binary. Empty defaults to "pandoc"
	// (resolved via PATH).
	PandocPath string
	// Timeout bounds a single pandoc invocation. Zero defaults to 30s.
	Timeout time.Duration
	// MaxBytes caps the pandoc stdout output; zero defaults to
	// defaultOfficeMaxBytes.
	MaxBytes int64
	// MaxConcurrency bounds simultaneous pandoc subprocesses. Zero defaults to
	// defaultOfficeConcurrency. Each conversion holds up to MaxBytes of output
	// buffer plus an OS process for up to Timeout, so without a bound a burst
	// of office requests can exhaust memory and the process table.
	MaxConcurrency int
}

// defaultOfficeConcurrency caps simultaneous pandoc conversions. Deliberately
// modest: conversions are subprocess-heavy and memory-heavy; excess requests
// queue (bounded by Timeout) instead of piling on.
const defaultOfficeConcurrency = 4

// Office converts office documents to GFM Markdown via pandoc.
type Office struct {
	opts   OfficeOptions
	runner officeRunner
	sem    chan struct{}
}

// NewOffice builds an Office transform. The pandoc path and timeout default
// sensibly when zero so the transform is usable with a minimal config.
func NewOffice(opts OfficeOptions) *Office {
	if opts.PandocPath == "" {
		opts.PandocPath = "pandoc"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultOfficeMaxBytes
	}
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = defaultOfficeConcurrency
	}
	return &Office{
		opts:   opts,
		runner: pandocRunner{path: opts.PandocPath},
		sem:    make(chan struct{}, opts.MaxConcurrency),
	}
}

// Name implements Transform.
func (Office) Name() string { return "office" }

// Apply implements Transform by delegating to ApplyContext with a background
// context. Production requests go through the server, which prefers
// ApplyContext and passes the request context — this shim exists only for
// callers outside the request path.
func (o *Office) Apply(body []byte, contentType, sourceURL string) (*Result, error) {
	return o.ApplyContext(context.Background(), body, contentType, sourceURL)
}

// ApplyContext implements ContextTransform. It dispatches by content-type
// (with an extension fallback from the source URL), then runs pandoc to
// produce GFM Markdown. The request context flows into convert so a
// disconnected client aborts the subprocess instead of holding a pandoc slot
// until [office].timeout.
func (o *Office) ApplyContext(ctx context.Context, body []byte, contentType, sourceURL string) (*Result, error) {
	format, ok := officeFormat(contentType, sourceURL)
	if !ok {
		return nil, &Error{
			Code:    CodeUnsupported,
			Message: fmt.Sprintf("office transform only applies to office documents (docx, pptx, xlsx, odt); got content-type %q", contentType),
		}
	}

	content, err := o.convert(ctx, format, body)
	if err != nil {
		return nil, err
	}

	return &Result{
		Content:    content,
		OutputType: "text/markdown; charset=utf-8",
	}, nil
}

// convert runs pandoc on body and returns the GFM output, enforcing the
// concurrency bound, timeout, and output cap. Errors are classified into typed
// transform.Error codes.
func (o *Office) convert(ctx context.Context, format string, body []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, o.opts.Timeout)
	defer cancel()

	// Bound simultaneous pandoc subprocesses. Waiting is itself bounded by the
	// conversion timeout — under sustained overload, queued conversions fail
	// with a timeout error instead of stacking unbounded memory and processes.
	// (A nil sem — Office built as a bare struct literal rather than via
	// NewOffice — skips the bound.)
	if o.sem != nil {
		select {
		case o.sem <- struct{}{}:
			defer func() { <-o.sem }()
		case <-ctx.Done():
			return "", &Error{
				Code:    CodeTimeout,
				Message: "office conversion queue timed out (too many concurrent conversions; retry)",
			}
		}
	}

	out, err := o.runner.run(ctx, format, body, o.opts.MaxBytes+1)
	if err != nil {
		return "", classifyOfficeError(ctx, err)
	}
	// Overflow: the runner read up to MaxBytes+1; if it returned that much, the
	// real output exceeds the cap.
	if int64(len(out)) > o.opts.MaxBytes {
		return "", &Error{
			Code:    CodeTooLarge,
			Message: fmt.Sprintf("pandoc output exceeded %d byte cap", o.opts.MaxBytes),
		}
	}
	return string(out), nil
}

// classifyOfficeError maps a subprocess error to a typed *transform.Error. A
// context deadline (the timeout firing) is CodeTimeout; a missing-pandoc
// *Error passes through unchanged; everything else is classified as a transform
// failure with the underlying detail for diagnosis.
func classifyOfficeError(ctx context.Context, err error) *Error {
	// A pandoc-absent error is already a typed *Error — pass it straight through.
	var te *Error
	if errors.As(err, &te) {
		return te
	}
	if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
		return &Error{Code: CodeTimeout, Message: "pandoc conversion timed out"}
	}
	return &Error{Code: CodeTransformFailed, Message: "pandoc conversion failed: " + err.Error()}
}

// --- format dispatch -------------------------------------------------------

// officeFormat resolves the pandoc input format from the response content-type,
// falling back to the URL's file extension when the content-type is generic or
// absent. Returns ok=false for anything that is not an allowlisted Office type,
// so pandoc is never handed a format it may not support.
func officeFormat(contentType, sourceURL string) (string, bool) {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if fmt, ok := contentTypeToFormat[ct]; ok {
		return fmt, true
	}

	u, err := url.Parse(sourceURL)
	if err == nil {
		ext := strings.ToLower(filepath.Ext(u.Path))
		if fmt, ok := extToFormat[ext]; ok {
			return fmt, true
		}
	}
	return "", false
}

// contentTypeToFormat maps allowlisted Office MIME types to pandoc reader names.
// Only these types reach pandoc — a generic binary blob does not.
var contentTypeToFormat = map[string]string{
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   "docx",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         "xlsx",
	"application/vnd.oasis.opendocument.text":                                   "odt",
}

// extToFormat is the extension fallback used when the content-type is generic
// (e.g. application/octet-stream) or missing.
var extToFormat = map[string]string{
	".docx": "docx",
	".pptx": "pptx",
	".xlsx": "xlsx",
	".odt":  "odt",
}

// --- pandoc runner ---------------------------------------------------------

// officeRunner abstracts the pandoc subprocess so the convert method's timeout
// and overflow classification are unit-testable without pandoc installed. The
// maxOut parameter is the byte ceiling the runner must enforce on stdout.
type officeRunner interface {
	run(ctx context.Context, format string, stdin []byte, maxOut int64) ([]byte, error)
}

// pandocRunner is the production runner: it executes the pandoc binary, piping
// the document via stdin and reading GFM from stdout.
type pandocRunner struct {
	path string
}

func (p pandocRunner) run(ctx context.Context, format string, stdin []byte, maxOut int64) ([]byte, error) {
	// A missing pandoc is a clean unsupported error, not a transform failure.
	// The message tells the operator exactly what to do.
	if _, err := exec.LookPath(p.path); err != nil {
		return nil, &Error{
			Code:    CodeUnsupported,
			Message: "office conversion requires pandoc (mise install)",
		}
	}

	cmd := exec.CommandContext(ctx, p.path, "-f", format, "-t", "gfm", "-")
	cmd.Stdin = bytes.NewReader(stdin)
	// If pandoc forks a helper that inherits stdout/stderr, killing pandoc
	// leaves Wait blocked reading pipes the grandchild still holds. WaitDelay
	// force-closes those pipes shortly after the process exits, so the
	// [office] timeout is actually honored.
	cmd.WaitDelay = 2 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("pandoc stdout pipe: %w", err)
	}
	stderr := &capBuffer{cap: maxStderrBytes}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("pandoc start: %w", err)
	}

	// Read at most maxOut bytes so a runaway conversion cannot exhaust memory.
	data, readErr := io.ReadAll(io.LimitReader(stdout, maxOut))
	if int64(len(data)) >= maxOut {
		// The output hit the cap: real output is at least maxOut bytes
		// (= MaxBytes+1), which convert() classifies as overflow. Kill
		// pandoc now — otherwise it blocks writing into a full pipe and
		// Wait() stalls until the context deadline, pinning the request
		// for the whole [office] timeout and misclassifying as timeout.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return data, &Error{
			Code:    CodeTooLarge,
			Message: fmt.Sprintf("pandoc output exceeded %d byte cap", maxOut-1),
		}
	}
	waitErr := cmd.Wait()

	// If the context expired (timeout), classify as timeout regardless of other
	// errors — cmd.Wait returns the signal error but ctx.Err() is authoritative.
	if ctx.Err() != nil {
		return data, ctx.Err()
	}
	if readErr != nil {
		return data, fmt.Errorf("pandoc stdout read: %w", readErr)
	}
	if waitErr != nil {
		// Bound the stderr text that rides into the API error (and log): a
		// document can make pandoc emit up to maxStderrBytes of diagnostics,
		// which has no business being the response body. Fall back to the exit
		// status when stderr is empty, or the message is just "pandoc failed: ".
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = waitErr.Error()
		}
		if cut, truncated := model.Truncate(detail, maxPandocErrorRunes); truncated {
			detail = cut + " (truncated)"
		}
		return data, fmt.Errorf("pandoc failed: %s", detail)
	}
	return data, nil
}

// maxPandocErrorRunes bounds the pandoc stderr excerpt surfaced to callers.
const maxPandocErrorRunes = 1024

// maxStderrBytes bounds how much of pandoc's stderr is buffered. A
// pathological document can emit large diagnostics; without a cap the buffer
// grows without bound (stdout is capped, stderr was not).
const maxStderrBytes = 64 * 1024

// capBuffer buffers up to cap bytes and silently discards anything beyond,
// always reporting success to the writer so the child never blocks on a full
// stderr pipe.
type capBuffer struct {
	buf bytes.Buffer
	cap int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if c.cap > 0 {
		n := min(len(p), c.cap)
		_, _ = c.buf.Write(p[:n])
		c.cap -= n
	}
	return len(p), nil
}

func (c *capBuffer) String() string { return c.buf.String() }
