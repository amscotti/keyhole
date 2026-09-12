package transform

import (
	"bytes"
	"io"
	"mime"
	"strings"

	"golang.org/x/net/html/charset"
)

// decodeText converts a fetched body to UTF-8 for the JSON envelope. The
// envelope is JSON, so non-UTF-8 bytes cannot survive it: without decoding,
// ISO-8859-1/GBK/Shift_JIS pages arrive as U+FFFD replacement characters while
// the envelope still advertises the origin charset.
//
// The charset is taken from the Content-Type parameter, then (for HTML) from a
// BOM or <meta> declaration, matching browser behavior. Content types that are
// not textual are returned untouched — decoding binary payloads as text would
// corrupt them further.
//
// The returned content type keeps the media type and forces charset=utf-8 so
// the envelope never lies about the encoding.
func decodeText(body []byte, contentType string) ([]byte, string) {
	mediaType := contentType
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		mediaType = mt
	}
	if !isTextual(mediaType) {
		return body, contentType
	}
	reader, err := charset.NewReader(bytes.NewReader(body), contentType)
	if err != nil {
		return body, contentType
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return body, contentType
	}
	return decoded, withUTF8Charset(contentType, mediaType)
}

// isTextual reports whether a media type should be charset-decoded. Text types,
// JSON, and XML dialects are; images, archives, office documents, and other
// binaries are not.
func isTextual(mediaType string) bool {
	switch {
	case strings.HasPrefix(mediaType, "text/"):
		return true
	case mediaType == "application/json",
		mediaType == "application/xml",
		mediaType == "application/xhtml+xml":
		return true
	case strings.HasSuffix(mediaType, "+json"), strings.HasSuffix(mediaType, "+xml"):
		return true
	default:
		return false
	}
}

// withUTF8Charset rewrites the charset parameter of contentType (a valid
// Content-Type header) to utf-8.
func withUTF8Charset(contentType, mediaType string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		params = map[string]string{}
	}
	params["charset"] = "utf-8"
	if formatted := mime.FormatMediaType(mediaType, params); formatted != "" {
		return formatted
	}
	return mediaType
}
