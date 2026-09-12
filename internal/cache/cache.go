// Package cache is an in-memory TTL cache for fetched content.
//
// The cache key is sha256(normalized URL + transform + auth profile name) so
// that content retrieved under one identity can never leak to another — two
// requests for the same URL but different auth profiles produce different keys
// and therefore separate cache entries. Only successful 200 text responses are
// cached (the caller enforces this; the cache itself is agnostic). A janitor
// goroutine periodically sweeps expired entries; a Clock is injectable so TTL
// tests are deterministic without real sleeps.
package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Clock abstracts time so tests can advance it without sleeping.
type Clock interface {
	Now() time.Time
}

// realClock is the default Clock used when none is injected.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// entry is a single cached value with its expiry timestamp and its position in
// the LRU list.
type entry struct {
	key       string
	value     []byte
	expiresAt time.Time
	elem      *list.Element
}

// Options configures a Cache. TTL and MaxEntries are required for a functional
// cache; Enabled=false produces a Cache whose Get always misses (a no-op).
type Options struct {
	Enabled    bool
	TTL        time.Duration
	MaxEntries int
	// MaxBytes bounds the total size of cached values. Without it the cache is
	// bounded only by entry count, and since each entry can hold a full
	// (up to max_chars-sized) envelope, a crawl of distinct URLs could grow
	// memory to gigabytes. Zero means no byte budget (entry count only).
	MaxBytes int64
	Clock    Clock
	// Janitor is the interval between expiry sweeps. When zero, no janitor runs
	// and Start is a no-op (lazy expiry in Get still works). Use a short value
	// in tests that need proactive eviction.
	Janitor time.Duration
}

// Cache is a concurrency-safe in-memory TTL cache with LRU eviction bounded by
// entry count and (optionally) total value bytes.
type Cache struct {
	enabled    bool
	ttl        time.Duration
	maxEntries int
	maxBytes   int64
	clock      Clock
	janitor    time.Duration

	mu      sync.Mutex
	entries map[string]*entry
	// lru orders entries most-recently-used first. Eviction is O(1) from the
	// back; a hit moves its entry to the front. The previous implementation
	// scanned all entries to find the LRU one (O(n) under the lock) on every
	// Set once full.
	lru     *list.List
	bytes   int64
	stopCh  chan struct{}
	stopped bool
}

// New creates a Cache from opts. A Cache with Enabled=false never stores or
// returns entries — it is a safe placeholder when [cache] enabled = false.
func New(opts Options) *Cache {
	clock := opts.Clock
	if clock == nil {
		clock = realClock{}
	}
	return &Cache{
		enabled:    opts.Enabled,
		ttl:        opts.TTL,
		maxEntries: opts.MaxEntries,
		maxBytes:   opts.MaxBytes,
		clock:      clock,
		janitor:    opts.Janitor,
		entries:    make(map[string]*entry),
		lru:        list.New(),
		stopCh:     make(chan struct{}),
	}
}

// Get returns the cached value for key if it exists and has not expired. An
// expired entry is lazily removed on read. A hit refreshes the entry's recency
// so eviction is least-recently-USED, not first-in-first-out. A disabled cache
// always returns (nil, false).
//
// The returned slice is owned by the cache; callers must treat it as read-only
// (a defensive copy would double allocation on every hit).
func (c *Cache) Get(key string) ([]byte, bool) {
	if !c.enabled {
		return nil, false
	}
	now := c.clock.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !now.Before(e.expiresAt) {
		c.removeLocked(key)
		return nil, false
	}
	c.lru.MoveToFront(e.elem)
	return e.value, true
}

// Set stores value under key with an expiry of now + TTL. If the cache is at
// capacity (entry count or byte budget), the least recently used entries are
// evicted first (hits refresh recency; see Get). A value larger than the byte
// budget is not stored at all. A disabled cache is a no-op.
func (c *Cache) Set(key string, value []byte) {
	if !c.enabled {
		return
	}
	now := c.clock.Now()
	size := int64(len(value))

	c.mu.Lock()
	defer c.mu.Unlock()

	// Replace semantics: an overwrite must not double-count bytes.
	c.removeLocked(key)

	for c.overCapacity(size) {
		if !c.evictLRULocked() {
			break
		}
	}

	e := &entry{key: key, value: value, expiresAt: now.Add(c.ttl)}
	e.elem = c.lru.PushFront(e)
	c.entries[key] = e
	c.bytes += size

	// A single value over the whole byte budget must not be retained: drop it
	// (the cache is an optimization; the response was already served).
	if c.maxBytes > 0 && c.bytes > c.maxBytes {
		c.removeLocked(key)
	}
}

// Delete removes key from the cache if present. A disabled cache is a no-op.
// Used by callers that encounter a corrupt entry so it is not re-served (and
// re-counted) until its TTL happens to expire.
func (c *Cache) Delete(key string) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
}

// overCapacity reports whether an entry of size addBytes would exceed the
// entry-count or byte budget. Callers must hold c.mu.
func (c *Cache) overCapacity(addBytes int64) bool {
	if c.maxEntries > 0 && c.entries != nil && len(c.entries) >= c.maxEntries {
		return true
	}
	return c.maxBytes > 0 && c.bytes+addBytes > c.maxBytes
}

// evictLRULocked removes the least recently used entry. It reports whether an
// entry was removed. Callers must hold c.mu.
func (c *Cache) evictLRULocked() bool {
	back := c.lru.Back()
	if back == nil {
		return false
	}
	c.removeLocked(back.Value.(*entry).key)
	return true
}

// removeLocked deletes key from both the map and the LRU list and adjusts the
// byte accounting. It is a no-op when key is absent. Callers must hold c.mu.
func (c *Cache) removeLocked(key string) {
	e, ok := c.entries[key]
	if !ok {
		return
	}
	delete(c.entries, key)
	c.lru.Remove(e.elem)
	c.bytes -= int64(len(e.value))
	if c.bytes < 0 {
		c.bytes = 0 // defensive; should not happen
	}
}

// sweep removes all expired entries. Called by the janitor and safe to call
// directly. Callers must NOT hold c.mu.
func (c *Cache) sweep() {
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if !now.Before(e.expiresAt) {
			c.removeLocked(k)
		}
	}
}

// Len returns the number of entries currently in the cache (expired entries
// that have not yet been swept are counted).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Bytes returns the total size of the cached values in bytes.
func (c *Cache) Bytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}

// Start launches the janitor goroutine that periodically sweeps expired entries.
// It is a no-op when Janitor is zero or the cache is disabled. Stop must be
// called to release the goroutine.
func (c *Cache) Start() {
	if !c.enabled || c.janitor <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(c.janitor)
		defer ticker.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.sweep()
			}
		}
	}()
}

// Stop signals the janitor goroutine to exit. Safe to call multiple times.
func (c *Cache) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return
	}
	c.stopped = true
	close(c.stopCh)
}

// Key produces the cache key for a fetch: sha256 of the normalized URL,
// transform, auth profile, and URL-embedded credential, joined by NUL
// separators. The separators make the encoding unambiguous — without them,
// distinct tuples such as ("https://a/", "raw", "markdown") and
// ("https://a/raw", "markdown", "") hash identically and one request can be
// served another's content. The auth profile and credential are part of the
// key so content fetched under one identity never leaks to another. (None of
// the fields can contain a NUL byte.)
func Key(normalizedURL, transform, authProfile, credential string) string {
	h := sha256.Sum256([]byte(normalizedURL + "\x00" + transform + "\x00" + authProfile + "\x00" + credential))
	return hex.EncodeToString(h[:])
}
