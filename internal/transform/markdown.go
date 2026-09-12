package transform

import (
	"fmt"

	"github.com/JohannesKaufmann/html-to-markdown/v2/converter"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/base"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/commonmark"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/table"
)

// Markdown converts a full HTML page to CommonMark Markdown using
// html-to-markdown v2 with the base, commonmark, and table plugins (headings,
// lists, links, tables, code blocks). Non-HTML input is an unsupported error.
type Markdown struct{}

// Name implements Transform.
func (Markdown) Name() string { return "markdown" }

// ValidateURL implements URLValidator: YouTube *video* URLs are refused with a
// message pointing the caller at transform "youtube", so a large watch page is
// never fetched just to be rejected. Non-video YouTube pages (channel, feed,
// about) have no youtube-transform equivalent and are handled normally.
func (Markdown) ValidateURL(sourceURL string) error {
	if _, ok := ExtractVideoID(sourceURL); ok {
		return &Error{
			Code:    CodeUnsupported,
			Message: `YouTube video URLs require transform "youtube"; transform "markdown" is not applicable`,
		}
	}
	return nil
}

// Apply implements Transform.
func (Markdown) Apply(body []byte, contentType, sourceURL string) (*Result, error) {
	if err := (Markdown{}).ValidateURL(sourceURL); err != nil {
		return nil, err
	}
	if !isHTML(contentType) {
		return nil, unsupportedError("markdown", contentType)
	}
	// Decode the origin charset before parsing: html-to-markdown treats the
	// input as a UTF-8 string, so an ISO-8859-1/GBK page would otherwise be
	// full of replacement characters.
	body, _ = decodeText(body, contentType)
	// Pass the source URL as the converter's base domain so relative links
	// become absolute: an agent consuming the Markdown can follow them
	// without re-deriving the base (final_url is in the envelope, but the
	// body should stand alone).
	md, err := convertHTMLToMarkdown(string(body), sourceURL)
	if err != nil {
		return nil, &Error{
			Code:    CodeTransformFailed,
			Message: fmt.Sprintf("markdown conversion failed: %s", err),
		}
	}
	return &Result{
		Content:    md,
		OutputType: "text/markdown; charset=utf-8",
	}, nil
}

// convertHTMLToMarkdown converts an HTML string to CommonMark Markdown with
// table support. The converter is built fresh each call (it is cheap) so there
// is no shared mutable state between concurrent requests — aligning with the
// "no global state" principle.
func convertHTMLToMarkdown(htmlStr, baseURL string) (string, error) {
	conv := converter.NewConverter(
		converter.WithPlugins(
			base.NewBasePlugin(),
			commonmark.NewCommonmarkPlugin(),
			table.NewTablePlugin(),
		),
	)
	if baseURL == "" {
		return conv.ConvertString(htmlStr)
	}
	// WithDomain resolves relative href/src against the source URL.
	return conv.ConvertString(htmlStr, converter.WithDomain(baseURL))
}
