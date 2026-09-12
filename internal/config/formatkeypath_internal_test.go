package config

import (
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// formatKeyPath renders value-error key paths as dotted paths; it backs the
// "config error:" messages users see for invalid values.
func TestFormatKeyPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		key  toml.Key
		want string
	}{
		{nil, ""},
		{toml.Key{"server"}, "server"},
		{toml.Key{"network", "timeout"}, "network.timeout"},
		{toml.Key{"a", "b", "c"}, "a.b.c"},
	}
	for _, tc := range cases {
		if got := formatKeyPath(tc.key); got != tc.want {
			t.Errorf("formatKeyPath(%v) = %q, want %q", tc.key, got, tc.want)
		}
	}
}
