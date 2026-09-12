package fetch_test

import (
	"testing"

	"github.com/amscotti/keyhole/internal/fetch"
)

// The typed fetch error's "code: message" shape is the machine-readable
// contract the REST and MCP handlers map to transport errors.
func TestErrorStringFormat(t *testing.T) {
	t.Parallel()
	e := &fetch.Error{Code: "denied", Message: "blocked host"}
	if got, want := e.Error(), "denied: blocked host"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
