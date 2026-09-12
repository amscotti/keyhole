package main

import (
	"testing"

	"github.com/amscotti/keyhole/internal/config"
)

func TestResolveMCP_FlagOrEnabledActivatesMCP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		mcpFlag       bool
		enabled       bool
		transport     string
		wantActive    bool
		wantTransport string
	}{
		{
			name:          "flag alone activates stdio",
			mcpFlag:       true,
			enabled:       false,
			transport:     "",
			wantActive:    true,
			wantTransport: "stdio",
		},
		{
			// The finding: [mcp] enabled = true (without --mcp) must activate
			// the MCP server. Previously cfg.MCP.Enabled was dead config.
			name:          "enabled-alone activates stdio",
			mcpFlag:       false,
			enabled:       true,
			transport:     "",
			wantActive:    true,
			wantTransport: "stdio",
		},
		{
			name:          "neither flag nor enabled stays REST",
			mcpFlag:       false,
			enabled:       false,
			transport:     "",
			wantActive:    false,
			wantTransport: "stdio",
		},
		{
			name:          "flag plus http transport",
			mcpFlag:       true,
			enabled:       false,
			transport:     "http",
			wantActive:    true,
			wantTransport: "http",
		},
		{
			name:          "enabled plus explicit stdio",
			mcpFlag:       false,
			enabled:       true,
			transport:     "stdio",
			wantActive:    true,
			wantTransport: "stdio",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{
				MCP: config.MCPConfig{
					Enabled:   tc.enabled,
					Transport: tc.transport,
				},
			}

			active, transport := resolveMCP(tc.mcpFlag, cfg)
			if active != tc.wantActive {
				t.Errorf("active: got %v, want %v", active, tc.wantActive)
			}
			if transport != tc.wantTransport {
				t.Errorf("transport: got %q, want %q", transport, tc.wantTransport)
			}
		})
	}
}
