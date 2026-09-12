package transform

// Raw returns the body as fetched — the "raw HTML" the product promises. It
// applies to any content type and preserves the original content type in its
// output so an LLM knows what it is receiving.

// Raw is the identity transform.
type Raw struct{}

// Name implements Transform.
func (Raw) Name() string { return "raw" }

// Apply implements Transform. Textual bodies are transcoded to UTF-8 (the
// envelope is JSON, which cannot carry other encodings) and the output content
// type is updated to match; non-text payloads pass through untouched.
func (Raw) Apply(body []byte, contentType, _ string) (*Result, error) {
	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}
	body, contentType = decodeText(body, contentType)
	return &Result{
		Content:    string(body),
		OutputType: contentType,
	}, nil
}
