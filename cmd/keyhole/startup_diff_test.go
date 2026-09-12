package main

import (
	"strings"
	"testing"

	"github.com/amscotti/keyhole/internal/config"
)

// startupDiffBase is a fully-populated config used by the field-by-field table
// below. Loading fixtures through loadSnippet mirrors how the reloader sees a
// config: defaults applied and validation enforced.
const startupDiffBase = `
default_policy = "deny"
[server]
listen = ":8080"
api_key = "old-key"
reload = false
[server.rate]
rps = 1.0
burst = 2
[metrics]
enabled = false
path = "/metrics"
[logging]
level = "info"
format = "json"
output = "stdout"
[mcp]
enabled = false
transport = "stdio"
listen = ":8081"
disable_localhost_protection = false
`

// TestStartupOnlyDiffFieldLevel is the field-by-field hot-reload gate: every
// startup-only field must name itself when changed and stay silent when not,
// so an operator editing a listener/ingress value gets a loud "restart
// required" instead of a reload that silently keeps the old value. [metrics],
// [logging], and [server.rate] are named as whole tables because they are read
// as a unit at boot.
func TestStartupOnlyDiffFieldLevel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		old  string // unique anchor in startupDiffBase
		new  string // replacement for the changed-field cases
		want []string
	}{
		{
			name: "unchanged config",
			old:  `reload = false`,
			new:  `reload = false`,
			want: nil,
		},
		{
			name: "[server] listen",
			old:  `listen = ":8080"`,
			new:  `listen = ":9090"`,
			want: []string{"[server] listen"},
		},
		{
			name: "[server] api_key",
			old:  `api_key = "old-key"`,
			new:  `api_key = "new-key"`,
			want: []string{"[server] api_key"},
		},
		{
			name: "[server] rate",
			old:  `rps = 1.0`,
			new:  `rps = 2.0`,
			want: []string{"[server.rate]"},
		},
		{
			name: "[server] reload",
			old:  `reload = false`,
			new:  `reload = true`,
			want: []string{"[server] reload"},
		},
		{
			name: "[metrics] enabled",
			old:  "[metrics]\nenabled = false",
			new:  "[metrics]\nenabled = true",
			want: []string{"[metrics]"},
		},
		{
			name: "[metrics] path",
			old:  `path = "/metrics"`,
			new:  `path = "/m"`,
			want: []string{"[metrics]"},
		},
		{
			name: "[logging]",
			old:  `level = "info"`,
			new:  `level = "debug"`,
			want: []string{"[logging]"},
		},
		{
			name: "[mcp] enabled",
			old:  "[mcp]\nenabled = false",
			new:  "[mcp]\nenabled = true",
			want: []string{"[mcp] enabled"},
		},
		{
			name: "[mcp] transport",
			old:  `transport = "stdio"`,
			new:  `transport = "http"`,
			want: []string{"[mcp] transport"},
		},
		{
			name: "[mcp] listen",
			old:  `listen = ":8081"`,
			new:  `listen = ":9091"`,
			want: []string{"[mcp] listen"},
		},
		{
			name: "[mcp] disable_localhost_protection",
			old:  `disable_localhost_protection = false`,
			new:  `disable_localhost_protection = true`,
			want: []string{"[mcp] disable_localhost_protection"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			oldCfg := loadSnippet(t, startupDiffBase)
			mutated := strings.Replace(startupDiffBase, tc.old, tc.new, 1)
			if mutated == startupDiffBase && tc.old != tc.new {
				t.Fatalf("fixture anchor %q not found in startupDiffBase", tc.old)
			}
			newCfg := loadSnippet(t, mutated)

			got := startupOnlyDiff(oldCfg, newCfg)
			if len(got) != len(tc.want) {
				t.Fatalf("startupOnlyDiff = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("startupOnlyDiff = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestStartupOnlyDiffMCPFieldLevel verifies the hot-reload gate names the
// exact [mcp] field that changed: identical configs are clean, a transport
// case-only change ("STDIO" vs "stdio") is a no-op because resolveMCP
// lowercases, and each real field reports independently.
func TestStartupOnlyDiffMCPFieldLevel(t *testing.T) {
	t.Parallel()

	base := &config.Config{}
	base.MCP.Enabled = true
	base.MCP.Transport = "stdio"
	base.MCP.Listen = ":8081"

	same := &config.Config{}
	same.MCP.Enabled = true
	same.MCP.Transport = "stdio"
	same.MCP.Listen = ":8081"
	if changed := startupOnlyDiff(base, same); len(changed) != 0 {
		t.Fatalf("identical configs: changed = %v, want none", changed)
	}

	caseOnly := &config.Config{}
	caseOnly.MCP.Enabled = true
	caseOnly.MCP.Transport = "STDIO"
	caseOnly.MCP.Listen = ":8081"
	if changed := startupOnlyDiff(base, caseOnly); len(changed) != 0 {
		t.Fatalf("transport case-only change: changed = %v, want none", changed)
	}

	flipped := &config.Config{}
	flipped.MCP.Enabled = false
	flipped.MCP.Transport = "http"
	flipped.MCP.Listen = ":9090"
	changed := startupOnlyDiff(base, flipped)
	want := map[string]bool{
		"[mcp] enabled":   true,
		"[mcp] transport": true,
		"[mcp] listen":    true,
	}
	if len(changed) != len(want) {
		t.Fatalf("changed = %v, want %v", changed, want)
	}
	for _, c := range changed {
		if !want[c] {
			t.Fatalf("changed = %v, want %v", changed, want)
		}
	}
}
