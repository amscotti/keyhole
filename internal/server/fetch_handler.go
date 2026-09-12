package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/amscotti/keyhole/internal/model"
)

// maxFetchRequestBody is the upper bound on a POST /fetch JSON body. Large
// enough for any legitimate request (URL + transform + optional fields) and
// small enough to reject memory-exhaustion attempts before policy runs.
const maxFetchRequestBody = 1 << 20 // 1 MiB

// fetchRequest is the JSON body for POST /fetch (and the query-param equivalent
// for GET /fetch).
type fetchRequest struct {
	URL         string `json:"url"`
	Transform   string `json:"transform"`
	MaxChars    int    `json:"max_chars,omitempty"`
	AuthProfile string `json:"auth_profile,omitempty"`
}

// fetchHandler delegates to the shared Service for the fetch pipeline and
// writes the result as an HTTP JSON response.
type fetchHandler struct {
	svc *Service
}

// ServeHTTP handles both POST /fetch (JSON body) and GET /fetch (query params).
func (h *fetchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, ok := h.parseRequest(w, r)
	if !ok {
		h.svc.Collectors.RecordRequest(h.svc.SanitizeTransform(req.Transform), http.StatusBadRequest)
		return
	}

	envelope, ferr := h.svc.Fetch(r.Context(), FetchRequest(req))
	if ferr != nil {
		writeEnvelopeError(w, ferr.Code, ferr.Message)
		h.svc.Collectors.RecordRequest(h.svc.SanitizeTransform(req.Transform), model.HTTPStatus(ferr.Code))
		return
	}

	writeEnvelope(h.svc.Logger, w, envelope)
	h.svc.Collectors.RecordRequest(h.svc.SanitizeTransform(req.Transform), http.StatusOK)
}

// sanitizeTransform returns the transform name if it is a registered transform,
// or "unknown" otherwise. This prevents an unauthenticated client from creating
// unbounded time-series cardinality via the transform label on /metrics.
func (s *Service) SanitizeTransform(name string) string {
	d := s.activeDeps()
	if d.Transforms != nil {
		if _, ok := d.Transforms.Get(name); ok {
			return name
		}
	}
	return "unknown"
}

// parseRequest extracts the fetch request from the HTTP request body or query
// string, validates it, and writes an error response if invalid.
func (h *fetchHandler) parseRequest(w http.ResponseWriter, r *http.Request) (fetchRequest, bool) {
	var req fetchRequest
	switch r.Method {
	case http.MethodPost:
		// Bound the body before decode so a multi-gigabyte payload cannot force
		// large allocations. Read max+1 to distinguish "exactly max" from overflow.
		limited := io.LimitReader(r.Body, maxFetchRequestBody+1)
		body, err := io.ReadAll(limited)
		if err != nil {
			writeEnvelopeError(w, model.CodeBadRequest, "read body: "+err.Error())
			return fetchRequest{}, false
		}
		if int64(len(body)) > maxFetchRequestBody {
			writeEnvelopeError(w, model.CodeBadRequest, "request body too large")
			return fetchRequest{}, false
		}
		// Strict decoding: a typo like "max_char" (or "transfrom") must be an
		// error, not a silently ignored field that falls back to a default.
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeEnvelopeError(w, model.CodeBadRequest, "invalid JSON body: "+err.Error())
			return fetchRequest{}, false
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			writeEnvelopeError(w, model.CodeBadRequest, "invalid JSON body: unexpected data after JSON object")
			return fetchRequest{}, false
		}
	case http.MethodGet, http.MethodHead:
		// Parse the raw query with '+' preserved: net/url.Query() decodes '+'
		// as a space, which would rewrite a signed URL's literal '+' before
		// policy sees it (and before the outbound request).
		q := rawQueryValues(r.URL.RawQuery)
		req.URL = q.Get("url")
		req.Transform = q.Get("transform")
		req.AuthProfile = q.Get("auth_profile")
		if mc := q.Get("max_chars"); mc != "" {
			n, err := strconv.Atoi(mc)
			if err != nil {
				writeEnvelopeError(w, model.CodeBadRequest, `invalid "max_chars": must be an integer`)
				return fetchRequest{}, false
			}
			req.MaxChars = n
		}
	}

	if req.URL == "" {
		writeEnvelopeError(w, model.CodeBadRequest, `"url" is required`)
		return fetchRequest{}, false
	}
	if req.Transform == "" {
		req.Transform = "raw"
	}
	return req, true
}

// rawQueryValues parses a raw query string keeping '+' as a literal character
// rather than net/url's form-decoding it to a space. The client's URL is
// opaque data here: a '+' can be significant (base64-ish path/query values),
// and policy must evaluate exactly what would be fetched.
func rawQueryValues(rawQuery string) url.Values {
	if !strings.ContainsRune(rawQuery, '+') {
		q, err := url.ParseQuery(rawQuery)
		if err != nil {
			return url.Values{}
		}
		return q
	}
	q, err := url.ParseQuery(strings.ReplaceAll(rawQuery, "+", "%2B"))
	if err != nil {
		return url.Values{}
	}
	return q
}
