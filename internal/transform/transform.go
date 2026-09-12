// Package transform is a registry of content transforms. Each transform takes
// the raw fetched bytes (body, content-type, source URL) and produces a content
// string plus the content-type of its output. Transforms declare which input
// content-types they apply to; an inapplicable transform returns a typed error
// so the server can map it to the correct HTTP status.
//
// The built-in transforms:
//   - raw:      identity — returns the body (decoded to UTF-8) as raw HTML.
//   - markdown: full-page HTML→Markdown via html-to-markdown v2.
//   - article:  reader-mode extraction (go-readability) then markdown of the
//     extracted article.
//   - youtube:  video metadata + transcript via a dedicated client.
//   - office:   docx/pptx/xlsx/odt → Markdown via pandoc.
package transform

import (
	"context"
	"fmt"
	"strings"
)

// Result is the output of a successful transform.
type Result struct {
	Content string
	// OutputType is the content type of the produced content.
	OutputType string
	Metadata   map[string]string
	// Truncated is set when the transform itself cut the content below its own
	// limit (e.g. the YouTube transform applies [youtube].max_chars). The server
	// ORs this with its own [output].max_chars truncation when building the
	// response envelope.
	Truncated bool
}

// Error is a typed transform error carrying a code the server maps to HTTP status.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Error codes produced by transforms. These mirror the codes in internal/model
// so the server can map them directly to HTTP statuses via model.HTTPStatus.
const (
	CodeUnsupported     = "unsupported"
	CodeTransformFailed = "transform_failed"
	// CodeUnreachable / CodeTimeout are emitted by the YouTube transform for
	// network failures against the YouTube data source.
	CodeUnreachable = "unreachable"
	CodeTimeout     = "timeout"
	// CodeTooLarge is emitted by the Office transform when pandoc's stdout
	// exceeds the configured output cap, or by the YouTube caption path when
	// a timedtext response exceeds the size bound.
	CodeTooLarge = "too_large"
	// CodeDenied is emitted when a DirectTransform refuses a host or URL for
	// security reasons (e.g. caption BaseURL host allowlist).
	CodeDenied = "denied"
)

// Transform converts fetched content. The source URL is provided so transforms
// that need it (article extraction resolves relative links) can use it.
type Transform interface {
	Name() string
	Apply(body []byte, contentType, sourceURL string) (*Result, error)
}

// ContextTransform is optionally implemented by transforms whose Apply does
// blocking work that must honor cancellation — subprocesses, network calls on
// the non-direct path, anything beyond pure CPU. The server prefers
// ApplyContext over Apply and passes the request context, so a disconnected
// client aborts the work instead of holding resources until an internal
// timeout. Transforms that are pure functions of their input (raw, markdown,
// article) do not need it; Apply alone is fine for them.
type ContextTransform interface {
	Transform
	ApplyContext(ctx context.Context, body []byte, contentType, sourceURL string) (*Result, error)
}

// DirectTransform is optionally implemented by transforms that retrieve their
// own content via a dedicated client (e.g. the YouTube transform uses the
// YouTube innertube API rather than the generic HTTP fetcher). When a transform
// implements this interface the server calls ApplyDirect instead of the normal
// Fetch → Apply pipeline, avoiding a wasteful — and potentially policy-
// conflicting — double-fetch of the source page.
type DirectTransform interface {
	ApplyDirect(ctx context.Context, sourceURL string) (*Result, error)
}

// URLValidator is optionally implemented by transforms that can decide, from the
// source URL alone and before any content is fetched, that they cannot handle a
// request. The server calls ValidateURL before fetching; a non-nil error
// short-circuits to a typed response. This lets e.g. the markdown transform
// refuse YouTube URLs cheaply (pointing the caller at transform "youtube")
// rather than fetching a large watch page only to reject it afterwards.
type URLValidator interface {
	ValidateURL(sourceURL string) error
}

// FetchTargeter is optionally implemented by DirectTransforms whose actual
// network target differs from the user-supplied URL. The YouTube transform, for
// example, always dials the canonical https://www.youtube.com/watch?v=<id>
// regardless of whether the request used youtu.be/, /shorts/, etc. The server
// evaluates policy on the canonical target too — a deny there blocks, per
// ("a deny rule anywhere in the chain blocks") — and reports it as
// final_url so provenance reflects the URL that was actually fetched
// ("final URL after redirects"). Returning "" means the transform
// fetches the source URL verbatim (no canonicalization applies).
type FetchTargeter interface {
	FetchTarget(sourceURL string) string
}

// Registry maps transform names to implementations.
type Registry struct {
	transforms map[string]Transform
}

// NewRegistry builds a Registry with the default set of transforms.
func NewRegistry() *Registry {
	r := &Registry{transforms: make(map[string]Transform)}
	r.Register(&Raw{})
	r.Register(&Markdown{})
	r.Register(&Article{})
	return r
}

// Register adds (or replaces) a transform in the registry.
func (r *Registry) Register(t Transform) {
	r.transforms[t.Name()] = t
}

// Get returns the transform for name, or false if not found.
func (r *Registry) Get(name string) (Transform, bool) {
	t, ok := r.transforms[name]
	return t, ok
}

// Names returns the set of registered transform names.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.transforms))
	for name := range r.transforms {
		names = append(names, name)
	}
	return names
}

// --- helpers --------------------------------------------------------------

// isHTML reports whether a Content-Type header value indicates HTML.
func isHTML(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "text/html" || ct == "application/xhtml+xml"
}

// unsupportedError is a shorthand for the common "wrong content type" error.
func unsupportedError(transform, contentType string) *Error {
	return &Error{
		Code:    CodeUnsupported,
		Message: fmt.Sprintf("transform %q requires HTML input, got content-type %q", transform, contentType),
	}
}
