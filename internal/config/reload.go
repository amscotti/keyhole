package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// reloadDebounce coalesces the burst of events an editor emits during a single
// save (write+sync, or atomic temp+rename) into one reload.
const reloadDebounce = 100 * time.Millisecond

// readStable's settle check: a reload only proceeds once two consecutive reads
// return identical bytes, so an interrupted or still-in-flight write (a slow
// copy, disk pressure, an editor that writes in chunks) cannot be applied as
// though it were the finished file. An empty or truncated prefix of a config is
// often valid TOML, and applying it silently changes policy.
const (
	reloadSettle         = 50 * time.Millisecond
	reloadSettleAttempts = 4
)

// errConfigUnchanged reports a watch event that did not change the config
// bytes (e.g. activity on another file in the watched directory, or a
// ConfigMap-style rename). It is not an error for logging purposes.
var errConfigUnchanged = errors.New("config unchanged")

// AfterReload is called with a freshly loaded, validated Config before the
// Reloader swaps it into Current(). Implementations rebuild live dependencies
// (policy engine, fetcher, auth profiles, …). If AfterReload returns an error
// the previous Config and previous dependencies stay active.
type AfterReload func(cfg *Config) error

// Reloader hot-swaps a validated Config when the watched file changes. It owns
// the live Config via an atomic.Pointer so readers never observe a partially
// applied policy. An invalid edit is logged and rejected: the previously loaded
// Config keeps serving and the watch continues. Hot-reload is opt-in
// ([server].reload = true); by default no Reloader runs and file edits have no
// effect until restart.
//
// AfterReload, when set, is invoked on every successful Load so the process can
// rebuild the runtime dependency graph (engine, fetcher, profiles) that main
// wires at startup. Without AfterReload, Current() alone is not enough: the
// HTTP/MCP handlers hold their own snapshots and would keep serving the old
// policy forever.
//
// Start/Stop are jointly concurrency-safe and idempotent in the safe direction:
// Stop may be called any number of times, concurrently, before or after Start;
// Start twice, or after Stop, returns an error instead of panicking.
type Reloader struct {
	path    string
	current atomic.Pointer[Config]
	logger  *zap.Logger

	// AfterReload rebuilds runtime deps from the new config. Optional.
	AfterReload AfterReload

	mu       sync.Mutex
	watcher  *fsnotify.Watcher
	started  bool
	stopped  bool
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	// lastHash is the hash of the config bytes that produced current, used to
	// skip reload work when watched-directory activity did not touch the
	// config (symlinked/ConfigMap layouts emit events for sibling files).
	lastHash [32]byte
	hasHash  bool
}

// NewReloader returns a Reloader seeded with initial. Call Start to begin
// watching. logger receives "config reloaded" / "config reload rejected" lines.
// after may be nil; when non-nil it is invoked before each successful swap.
func NewReloader(path string, initial *Config, logger *zap.Logger, after AfterReload) *Reloader {
	if logger == nil {
		logger = zap.NewNop()
	}
	r := &Reloader{
		path:        path,
		logger:      logger,
		AfterReload: after,
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	r.current.Store(initial)
	return r
}

// Current returns the live, fully validated Config.
func (r *Reloader) Current() *Config { return r.current.Load() }

// Start creates the fsnotify watch on the config file's directory and launches
// the reload loop. The directory (not just the file) is watched so atomic
// saves (temp + rename) do not silently drop the watch; when the config path is
// a symlink the target's directory is watched too (symlinked and
// ConfigMap-style mounts emit their events there). It returns an error when
// called twice or after Stop.
func (r *Reloader) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return fmt.Errorf("config reloader: Start called after Stop")
	}
	if r.started {
		return fmt.Errorf("config reloader: already started")
	}
	abs, err := filepath.Abs(r.path)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create config watcher: %w", err)
	}
	// Watch the parent directory: editors that save atomically rename a temp
	// file over the target, which invalidates a per-file watch. A directory
	// watch survives that and reports the final Create/Rename for our file.
	dirs := []string{filepath.Dir(abs)}
	if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil {
		if d := filepath.Dir(resolved); d != dirs[0] {
			dirs = append(dirs, d)
		}
	}
	for _, d := range dirs {
		if err := w.Add(d); err != nil {
			_ = w.Close()
			return fmt.Errorf("watch config directory: %w", err)
		}
	}
	if data, rerr := os.ReadFile(abs); rerr == nil {
		r.lastHash = sha256.Sum256(data)
		r.hasHash = true
	}
	r.watcher = w
	r.started = true
	go r.loop()
	return nil
}

// Stop tears down the watch and waits for the reload loop to exit. It is safe
// to call concurrently and more than once. Calling Stop before Start (or after
// a failed Start) is a no-op rather than a deadlock.
func (r *Reloader) Stop() {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		r.stopped = true
		started := r.started
		w := r.watcher
		r.mu.Unlock()

		close(r.stop)
		if w != nil {
			_ = w.Close()
		}
		if !started {
			// No loop was launched; nothing will ever close done. Unblock the
			// channel so the wait below returns immediately.
			close(r.done)
		}
	})
	<-r.done
}

// loop is the watch goroutine. It debounces events into a single reload and
// exits when Stop closes the stop channel or the watcher is closed.
func (r *Reloader) loop() {
	defer close(r.done)
	var debounce <-chan time.Time
	for {
		select {
		case <-r.stop:
			return
		case ev, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if r.relevant(ev) {
				debounce = time.After(reloadDebounce)
			}
		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			r.logger.Error("config watcher error", zap.Error(err))
		case <-debounce:
			debounce = nil
			switch err := r.reloadOnce(); {
			case err == nil:
				r.logger.Info("config reloaded", zap.String("path", r.path))
			case errors.Is(err, errConfigUnchanged):
				// Watched-directory activity that did not change the config
				// (another file, or a rename that kept the same bytes).
			default:
				r.logger.Error("config reload rejected", zap.Error(err), zap.String("path", r.path))
			}
		}
	}
}

// relevant reports whether ev could affect the watched config. Because the
// watcher is scoped to the config's own directories, any create/write/rename/
// remove in them may be the config (or a ConfigMap-style indirection pointing
// at it); the content-hash check in reloadOnce discards the rest.
func (r *Reloader) relevant(ev fsnotify.Event) bool {
	return ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0
}

// reloadOnce re-reads, decodes, and validates the file; on success it runs
// AfterReload (if set) and then atomically swaps the live Config. On any
// failure — including AfterReload — the previous Config stays in place. When
// the file's bytes are identical to the ones already applied it returns
// errConfigUnchanged without re-running AfterReload.
func (r *Reloader) reloadOnce() error {
	data, err := readStable(r.path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if r.hasHash && sum == r.lastHash {
		return errConfigUnchanged
	}
	cfg, err := loadBytes(data, r.path)
	if err != nil {
		return err
	}
	if r.AfterReload != nil {
		if err := r.AfterReload(cfg); err != nil {
			return fmt.Errorf("apply reloaded config: %w", err)
		}
	}
	r.current.Store(cfg)
	r.lastHash = sum
	r.hasHash = true
	return nil
}

// readStable reads path and only returns once two consecutive reads are
// byte-identical, so a config that is still being written is not applied
// half-formed (and logged as a success).
func readStable(path string) ([]byte, error) {
	prev, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config error: read %s: %w", path, err)
	}
	for i := 0; i < reloadSettleAttempts; i++ {
		time.Sleep(reloadSettle)
		cur, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config error: read %s: %w", path, err)
		}
		if bytes.Equal(prev, cur) {
			return cur, nil
		}
		prev = cur
	}
	return nil, fmt.Errorf("config reload: %s is still being written", path)
}
