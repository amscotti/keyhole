package config_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/amscotti/keyhole/internal/config"
)

// waitFor polls cond every 15ms until it returns true or the timeout elapses.
// It returns whether cond ever succeeded.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return cond()
}

const (
	reloadTimeout   = 3 * time.Second
	reloadSettleGap = 250 * time.Millisecond // extra wait after a change to let events settle
)

// TestReloaderSwapsOnFileChange is the DoD #4 contract: with reload enabled,
// editing the file updates the live config without restart.
func TestReloaderSwapsOnFileChange(t *testing.T) {
	// Not parallel: exercises a real fsnotify watch on a temp directory.
	path := writeConfig(t, `[server]
listen = ":8080"`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	r := config.NewReloader(path, cfg, zap.NewNop(), nil)
	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(r.Stop)

	// Edit the listen address and wait for the swap to become visible.
	newContent := []byte(`[server]
listen = ":9090"`)
	if err := os.WriteFile(path, newContent, 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	if !waitFor(t, reloadTimeout, func() bool {
		return r.Current().Server.Listen == ":9090"
	}) {
		t.Fatalf("config was not reloaded; Current().Server.Listen = %q", r.Current().Server.Listen)
	}
}

// TestReloaderRejectsInvalidKeepsOld is the DoD #4 fail-closed contract:
// replacing the file with invalid content logs an error and leaves the old
// config serving.
func TestReloaderRejectsInvalidKeepsOld(t *testing.T) {
	// Not parallel: fsnotify watch + log observer.
	path := writeConfig(t, `[server]
listen = ":8080"`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	core, obs := observer.New(zapcore.DebugLevel)
	r := config.NewReloader(path, cfg, zap.New(core), nil)
	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(r.Stop)

	// Write an invalid file (unknown key under a known table).
	if err := os.WriteFile(path, []byte(`[network]
bogus = 1`), 0o600); err != nil {
		t.Fatalf("rewrite invalid: %v", err)
	}

	// The reject log must appear, and the live config must be unchanged.
	if !waitFor(t, reloadTimeout, func() bool {
		for _, e := range obs.All() {
			if e.Message == "config reload rejected" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("expected a 'config reload rejected' log line; got: %+v", obs.All())
	}
	if got := r.Current().Server.Listen; got != ":8080" {
		t.Errorf("invalid edit should keep old config; Current = %q, want :8080", got)
	}
}

// TestReloadDisabledByDefault proves DoD #5 at the config level: the reload
// flag that gates the watcher is off by default, so a freshly-loaded minimal
// config opts out of hot-reload (the running process must be restarted).
func TestReloadDisabledByDefault(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(filepath.Join("..", "..", "testdata", "minimal.toml"))
	if err != nil {
		t.Fatalf("load minimal: %v", err)
	}
	if cfg.Server.Reload {
		t.Error("Server.Reload defaults to true; want false (off by default)")
	}
}

// TestReloaderAfterReloadRunsBeforeSwap proves that AfterReload is invoked with
// the newly loaded config and that a failing AfterReload keeps the previous
// Current() config (fail closed on apply errors).
func TestReloaderAfterReloadRunsBeforeSwap(t *testing.T) {
	path := writeConfig(t, `[server]
listen = ":8080"`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	var (
		mu         sync.Mutex
		seenListen string
	)
	r := config.NewReloader(path, cfg, zap.NewNop(), func(newCfg *config.Config) error {
		mu.Lock()
		seenListen = newCfg.Server.Listen
		mu.Unlock()
		if newCfg.Server.Listen == ":fail" {
			return errApplyFailed
		}
		return nil
	})
	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(r.Stop)

	// Successful apply.
	if err := os.WriteFile(path, []byte(`[server]
listen = ":9090"`), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !waitFor(t, reloadTimeout, func() bool {
		return r.Current().Server.Listen == ":9090"
	}) {
		mu.Lock()
		seen := seenListen
		mu.Unlock()
		t.Fatalf("expected swap to :9090; got %q (after saw %q)", r.Current().Server.Listen, seen)
	}
	mu.Lock()
	if seenListen != ":9090" {
		t.Errorf("AfterReload saw listen %q, want :9090", seenListen)
	}
	mu.Unlock()

	// Failing apply must keep :9090.
	if err := os.WriteFile(path, []byte(`[server]
listen = ":fail"`), 0o600); err != nil {
		t.Fatalf("rewrite fail: %v", err)
	}
	// Give the watcher time to attempt the reload.
	time.Sleep(reloadSettleGap)
	if !waitFor(t, reloadTimeout, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seenListen == ":fail"
	}) {
		mu.Lock()
		seen := seenListen
		mu.Unlock()
		t.Fatalf("AfterReload never saw :fail; last seen %q", seen)
	}
	if got := r.Current().Server.Listen; got != ":9090" {
		t.Errorf("failed AfterReload should keep old config; got %q", got)
	}
}

// errApplyFailed is a sentinel used by TestReloaderAfterReloadRunsBeforeSwap.
var errApplyFailed = errString("apply failed")

type errString string

func (e errString) Error() string { return string(e) }

// TestStopIsIdempotentAndConcurrentSafe verifies Stop is safe to call from
// concurrent goroutines and more than once (run under -race).
func TestStopIsIdempotentAndConcurrentSafe(t *testing.T) {
	path := writeConfig(t, `[server]
listen = ":8080"`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := config.NewReloader(path, cfg, zap.NewNop(), nil)
	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	done := make(chan struct{})
	go func() {
		r.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Stop did not return within 2s")
	}
	r.Stop() // idempotent second stop must not block or panic
}

// TestReloaderStopWithoutStartReturns pins the API contract: Stop on a
// Reloader that was never started (or whose Start failed) must return
// immediately instead of deadlocking on a done channel no loop will close.
// TestReloaderStartTwiceOrAfterStopErrors pins the lifecycle contract: Start is
// idempotent only in the error direction — a second Start or a Start after Stop
// must fail cleanly instead of racing the loop or double-closing done.
func TestReloaderStartTwiceOrAfterStopErrors(t *testing.T) {
	// Not parallel: real fsnotify watch.
	path := writeConfig(t, `[server]
listen = ":8080"`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	r := config.NewReloader(path, cfg, zap.NewNop(), nil)
	if err := r.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := r.Start(); err == nil {
		t.Fatal("second Start should return an error")
	}
	r.Stop()
	if err := r.Start(); err == nil {
		t.Fatal("Start after Stop should return an error")
	}
}

func TestReloaderStopWithoutStartReturns(t *testing.T) {
	t.Parallel()
	r := config.NewReloader("config.toml", &config.Config{}, nil, nil)
	done := make(chan struct{})
	go func() {
		r.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop without Start deadlocked")
	}
	// Idempotent second call must also return.
	r.Stop()
}
