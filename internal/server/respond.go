package server

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/model"
)

// writeJSON writes body as JSON with the given HTTP status. Used for both the
// fetch envelope and the health endpoints; cache policy is set by the caller.
func writeJSON(logger *zap.Logger, w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	// Fetched content is already text, not HTML destined for a browser:
	// HTML-escaping it would inflate raw-HTML responses ~1.8x and cost CPU on
	// every fetch. Encoding is still valid JSON either way.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		logger.Error("write json response", zap.Error(err))
	}
}

// writeEnvelopeError writes a model.ErrorResponse with the given HTTP status.
// code is a machine-readable error code (e.g. model.CodeDenied); message is
// human-readable detail. Fetch-path errors (401/403/429/5xx from the
// middleware chain and the handler) are marked no-store so intermediaries never
// cache a rejection — a cached 401 could mask a fixed key, and error bodies can
// echo policy detail.
func writeEnvelopeError(w http.ResponseWriter, code, message string) {
	status := model.HTTPStatus(code)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(model.ErrorResponse{
		OK: false,
		Error: model.ErrorBody{
			Code:    code,
			Message: message,
		},
	})
}

// writeEnvelope writes a successful fetch envelope with Content-Type JSON and
// Cache-Control: no-store — fetched documents are internal content and must not
// be cached by shared proxies/intermediaries between keyhole and its caller.
func writeEnvelope(logger *zap.Logger, w http.ResponseWriter, envelope any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(logger, w, http.StatusOK, envelope)
}
