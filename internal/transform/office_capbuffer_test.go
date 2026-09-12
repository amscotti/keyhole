package transform

import (
	"strings"
	"testing"
)

// capBuffer must absorb up to cap bytes and silently discard the rest while
// always reporting a full write (so a chatty pandoc stderr never blocks).
func TestCapBufferCapsOverflow(t *testing.T) {
	t.Parallel()
	c := &capBuffer{cap: 4}
	n, err := c.Write([]byte("abcdef"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 6 {
		t.Fatalf("Write must report full length, got %d", n)
	}
	if got := c.String(); got != "abcd" {
		t.Fatalf("got %q, want %q", got, "abcd")
	}
	// Further writes after the cap is exhausted are discarded, not appended.
	if _, err := c.Write([]byte("xyz")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := c.String(); got != "abcd" {
		t.Fatalf("got %q, want %q", got, "abcd")
	}
}

func TestCapBufferPartialThenFull(t *testing.T) {
	t.Parallel()
	c := &capBuffer{cap: 5}
	_, _ = c.Write([]byte("ab"))
	_, _ = c.Write([]byte("cdef"))
	if got := c.String(); got != "abcde" {
		t.Fatalf("got %q, want %q", got, "abcde")
	}
}

func TestCapBufferZeroCapDiscards(t *testing.T) {
	t.Parallel()
	c := &capBuffer{}
	n, err := c.Write([]byte(strings.Repeat("x", 1024)))
	if err != nil || n != 1024 {
		t.Fatalf("zero-cap Write must discard and report success: n=%d err=%v", n, err)
	}
	if got := c.String(); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
