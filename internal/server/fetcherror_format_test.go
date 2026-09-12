package server_test

import (
	"testing"

	"github.com/amscotti/keyhole/internal/server"
)

// FetchError's "code: message" shape is shared by the REST handler and the MCP
// tool handler so error semantics stay identical across transports.
func TestFetchErrorStringFormat(t *testing.T) {
	t.Parallel()
	e := &server.FetchError{Code: "too_large", Message: "body exceeds limit"}
	if got, want := e.Error(), "too_large: body exceeds limit"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
