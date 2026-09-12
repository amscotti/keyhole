package main

import (
	"testing"
)

func TestResolveLogOutput_StdioMCPForcesStderr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		base       string
		mcpActive  bool
		transport  string
		wantOutput string
	}{
		{
			// The finding: on the stdio transport stdout carries JSON-RPC, so
			// any configured log output (even "stdout") must be forced to stderr.
			name:       "stdio mcp overrides stdout to stderr",
			base:       "stdout",
			mcpActive:  true,
			transport:  "stdio",
			wantOutput: "stderr",
		},
		{
			name:       "stdio mcp overrides empty default to stderr",
			base:       "",
			mcpActive:  true,
			transport:  "stdio",
			wantOutput: "stderr",
		},
		{
			name:       "stdio mcp keeps a configured file path",
			base:       "/var/log/keyhole.log",
			mcpActive:  true,
			transport:  "stdio",
			wantOutput: "stderr",
		},
		{
			// HTTP transport does not use stdout for the protocol, so the
			// configured output (including stdout) must be respected.
			name:       "http mcp respects configured stdout",
			base:       "stdout",
			mcpActive:  true,
			transport:  "http",
			wantOutput: "stdout",
		},
		{
			name:       "http mcp respects configured file",
			base:       "/var/log/keyhole.log",
			mcpActive:  true,
			transport:  "http",
			wantOutput: "/var/log/keyhole.log",
		},
		{
			name:       "rest mode respects configured output",
			base:       "stdout",
			mcpActive:  false,
			transport:  "stdio",
			wantOutput: "stdout",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolveLogOutput(tc.base, tc.mcpActive, tc.transport)
			if got != tc.wantOutput {
				t.Errorf("resolveLogOutput(%q, active=%v, %q) = %q, want %q",
					tc.base, tc.mcpActive, tc.transport, got, tc.wantOutput)
			}
		})
	}
}
