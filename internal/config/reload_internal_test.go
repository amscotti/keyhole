package config

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// writeFile is a package-internal helper for reload tests (no /tmp: uses the
// test's temp dir).
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func validConfigWith(listen string) *Config {
	return &Config{Server: ServerConfig{Listen: listen}, DefaultPolicy: "deny"}
}

// TestReloadOnceSwapsValid exercises the swap path directly, independent of
// fsnotify timing: a successful Load atomically replaces Current().
func TestReloadOnceSwapsValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `[server]
listen = ":8080"`)

	seed := validConfigWith(":9999") // intentionally different from the file
	r := NewReloader(path, seed, zap.NewNop(), nil)

	if r.Current().Server.Listen != ":9999" {
		t.Fatalf("seed not stored: got %q", r.Current().Server.Listen)
	}
	if err := r.reloadOnce(); err != nil {
		t.Fatalf("reloadOnce: %v", err)
	}
	if got := r.Current().Server.Listen; got != ":8080" {
		t.Errorf("after reload Current().Server.Listen = %q, want :8080", got)
	}
}

// TestReloadOnceSkipsUnchangedBytes pins the content-hash guard: watched-
// directory activity that did not change the config must not re-run
// AfterReload (symlinked/ConfigMap layouts emit sibling events constantly).
func TestReloadOnceSkipsUnchangedBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `[server]
listen = ":8080"`
	writeFile(t, path, content)

	called := false
	r := NewReloader(path, validConfigWith(":8080"), zap.NewNop(), func(*Config) error {
		called = true
		return nil
	})
	r.lastHash = sha256.Sum256([]byte(content))
	r.hasHash = true

	if err := r.reloadOnce(); !errors.Is(err, errConfigUnchanged) {
		t.Fatalf("reloadOnce = %v, want errConfigUnchanged", err)
	}
	if called {
		t.Fatal("AfterReload must not run for unchanged bytes")
	}
}

// TestReloadOnceKeepsOldOnInvalid proves the fail-closed guarantee: an invalid
// file leaves the previously loaded Config serving.
func TestReloadOnceKeepsOldOnInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `[server]
listen = ":8080"`)

	seed := validConfigWith(":7070")
	r := NewReloader(path, seed, zap.NewNop(), nil)

	// Corrupt the file so Load fails.
	writeFile(t, path, `[server]
listen = ":8080"
timeoutt = "5s"`)

	if err := r.reloadOnce(); err == nil {
		t.Fatal("expected reloadOnce to fail on invalid file, got nil")
	}
	if got := r.Current().Server.Listen; got != ":7070" {
		t.Errorf("invalid reload should keep old config; Current = %q, want :7070", got)
	}
}
