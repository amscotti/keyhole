package transform

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"codeberg.org/readeck/go-readability/v2"
)

// Article runs go-readability to extract the main article content (stripping
// nav, ads, sidebars), then converts the extracted HTML to Markdown. This is
// the "reader mode" pre-step. Non-HTML input is an unsupported error.
type Article struct{}

// Name implements Transform.
func (Article) Name() string { return "article" }

// ValidateURL implements URLValidator: YouTube *video* URLs are refused with a
// message pointing the caller at transform "youtube". Non-video YouTube pages
// are handled like any other HTML page.
func (Article) ValidateURL(sourceURL string) error {
	if _, ok := ExtractVideoID(sourceURL); ok {
		return &Error{
			Code:    CodeUnsupported,
			Message: `YouTube video URLs require transform "youtube"; transform "article" is not applicable`,
		}
	}
	return nil
}

// Apply implements Transform.
func (Article) Apply(body []byte, contentType, sourceURL string) (*Result, error) {
	if err := (Article{}).ValidateURL(sourceURL); err != nil {
		return nil, err
	}
	if !isHTML(contentType) {
		return nil, unsupportedError("article", contentType)
	}

	pageURL, err := url.Parse(sourceURL)
	if err != nil {
		return nil, &Error{
			Code:    CodeTransformFailed,
			Message: fmt.Sprintf("article: parse source URL %q: %s", sourceURL, err),
		}
	}

	parser := readability.NewParser()
	article, err := parser.Parse(bytes.NewReader(body), pageURL)
	if err != nil {
		return nil, &Error{
			Code:    CodeTransformFailed,
			Message: fmt.Sprintf("article extraction failed: %s", err),
		}
	}

	var htmlBuf bytes.Buffer
	if err := article.RenderHTML(&htmlBuf); err != nil || strings.TrimSpace(htmlBuf.String()) == "" {
		// Readability found no article body (a JS-only shell, an index page,
		// or a body-less document). That is not a server failure: degrade to
		// full-page Markdown exactly like the markdown transform would,
		// instead of returning a 5xx with a library-internal message.
		body, _ = decodeText(body, contentType)
		md, cerr := convertHTMLToMarkdown(string(body), sourceURL)
		if cerr != nil {
			return nil, &Error{
				Code:    CodeTransformFailed,
				Message: fmt.Sprintf("article fallback markdown conversion failed: %s", cerr),
			}
		}
		return &Result{
			Content:    md,
			OutputType: "text/markdown; charset=utf-8",
			Metadata:   articleMetadata(article),
		}, nil
	}

	md, err := convertHTMLToMarkdown(htmlBuf.String(), sourceURL)
	if err != nil {
		return nil, &Error{
			Code:    CodeTransformFailed,
			Message: fmt.Sprintf("article markdown conversion failed: %s", err),
		}
	}

	return &Result{
		Content:    md,
		OutputType: "text/markdown; charset=utf-8",
		Metadata:   articleMetadata(article),
	}, nil
}

// articleMetadata collects the metadata fields readability extracted into a
// flat string map suitable for the response envelope.
func articleMetadata(a readability.Article) map[string]string {
	m := make(map[string]string)
	if v := a.Title(); v != "" {
		m["title"] = v
	}
	if v := a.Byline(); v != "" {
		m["byline"] = v
	}
	if v := a.Excerpt(); v != "" {
		m["excerpt"] = v
	}
	if v := a.SiteName(); v != "" {
		m["site_name"] = v
	}
	if v := a.Language(); v != "" {
		m["language"] = v
	}
	if v := a.ImageURL(); v != "" {
		m["image"] = v
	}
	return m
}
