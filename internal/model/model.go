// Package model defines the JSON response envelope and typed error codes shared
// across the REST handlers, the transform pipeline, and (later) the MCP surface.
//
// The envelope is the single contract between Keyhole and its clients (LLMs and
// other tools). A successful response carries the content, provenance (original,
// normalized, and final URLs), fetch metadata, and a truncated flag set when the
// content was cut to fit a max_chars limit. An error response carries a machine-
// readable code that maps deterministically to an HTTP status, so a client can
// branch on the code without parsing prose.
package model

import "time"

// Envelope is the JSON response body for every successful fetch.
type Envelope struct {
	OK            bool              `json:"ok"`
	URL           string            `json:"url"`
	NormalizedURL string            `json:"normalized_url"`
	FinalURL      string            `json:"final_url"`
	FetchedAt     time.Time         `json:"fetched_at"`
	Status        int               `json:"status"`
	Transform     string            `json:"transform"`
	ContentType   string            `json:"content_type"`
	Truncated     bool              `json:"truncated"`
	Content       string            `json:"content"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ErrorBody is the error detail carried inside an ErrorResponse.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrorResponse is the JSON response body for a failed fetch.
type ErrorResponse struct {
	OK    bool      `json:"ok"`
	Error ErrorBody `json:"error"`
}

// Typed error codes. Each maps to exactly one HTTP status via HTTPStatus.
const (
	CodeDenied          = "denied"
	CodeBadRequest      = "bad_request"
	CodeUnsupported     = "unsupported"
	CodeTooLarge        = "too_large"
	CodeTimeout         = "timeout"
	CodeUnreachable     = "unreachable"
	CodeTransformFailed = "transform_failed"
	CodeUnauthorized    = "unauthorized"
	CodeInternal        = "internal"
	CodeRateLimited     = "rate_limited"
)

// httpStatus maps each error code to its HTTP status. The mapping is a flat
// lookup so it is trivially testable and never ambiguous.
var httpStatus = map[string]int{
	CodeDenied:          403,
	CodeBadRequest:      400,
	CodeUnsupported:     400,
	CodeTooLarge:        413,
	CodeTimeout:         504,
	CodeUnreachable:     502,
	CodeTransformFailed: 500,
	CodeUnauthorized:    401,
	CodeInternal:        500,
	CodeRateLimited:     429,
}

// HTTPStatus returns the HTTP status for code, defaulting to 500 for an unknown
// code (fail closed — a code the server does not recognise is a bug, and 500
// surfaces it rather than silently returning 200).
func HTTPStatus(code string) int {
	if s, ok := httpStatus[code]; ok {
		return s
	}
	return 500
}
