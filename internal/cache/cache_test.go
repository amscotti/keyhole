package cache_test

import (
	"sync"
	"testing"
	"time"

	"github.com/amscotti/keyhole/internal/cache"
)

// fakeClock is an injectable, concurrency-safe Clock for deterministic TTL
// tests. The janitor goroutine calls Now() concurrently with the test mutating
// the time, so access is mutex-guarded.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

// advance moves the clock forward by d. Thread-safe for the janitor race.
func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func TestCacheSetGetHit(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	c := cache.New(cache.Options{Enabled: true, TTL: time.Minute, MaxEntries: 10, Clock: clock})
	c.Set("k1", []byte("hello"))

	got, ok := c.Get("k1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestCacheMissOnUnknownKey(t *testing.T) {
	t.Parallel()
	c := cache.New(cache.Options{Enabled: true, TTL: time.Minute, MaxEntries: 10, Clock: newFakeClock()})
	if _, ok := c.Get("nope"); ok {
		t.Fatal("expected miss for unknown key")
	}
}

func TestCacheExpiryAfterTTL(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	c := cache.New(cache.Options{Enabled: true, TTL: time.Minute, MaxEntries: 10, Clock: clock})
	c.Set("k1", []byte("data"))

	// Same time → still fresh.
	if _, ok := c.Get("k1"); !ok {
		t.Fatal("expected hit before TTL expiry")
	}

	// Advance past TTL → expired.
	clock.advance(2 * time.Minute)
	if _, ok := c.Get("k1"); ok {
		t.Fatal("expected miss after TTL expiry")
	}
}

func TestCacheEntrySurvivesJustBeforeTTL(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	c := cache.New(cache.Options{Enabled: true, TTL: time.Minute, MaxEntries: 10, Clock: clock})
	c.Set("k1", []byte("data"))
	clock.advance(time.Minute - time.Second)
	if _, ok := c.Get("k1"); !ok {
		t.Fatal("expected hit just before TTL")
	}
}

func TestCacheMaxEntriesEviction(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	c := cache.New(cache.Options{Enabled: true, TTL: time.Hour, MaxEntries: 2, Clock: clock})
	c.Set("a", []byte("1"))
	c.Set("b", []byte("2"))
	// Adding a third entry exceeds max_entries=2; the oldest is evicted.
	c.Set("c", []byte("3"))

	if _, ok := c.Get("a"); ok {
		t.Error("expected oldest entry 'a' to be evicted")
	}
	if _, ok := c.Get("b"); !ok {
		t.Error("expected 'b' to still be present")
	}
	if _, ok := c.Get("c"); !ok {
		t.Error("expected 'c' to be present")
	}
}

// TestCacheByteBudgetEvictsLRU pins the byte budget: entry count alone is not
// a memory bound when each entry can be hundreds of KB.
func TestCacheByteBudgetEvictsLRU(t *testing.T) {
	t.Parallel()
	c := cache.New(cache.Options{
		Enabled: true, TTL: time.Minute, MaxEntries: 100, MaxBytes: 10, Clock: newFakeClock(),
	})
	c.Set("a", make([]byte, 6))
	c.Set("b", make([]byte, 6)) // 12 bytes > 10: evicts the LRU entry (a)

	if _, ok := c.Get("a"); ok {
		t.Fatal("entry a should have been evicted to satisfy max_bytes")
	}
	if _, ok := c.Get("b"); !ok {
		t.Fatal("entry b should be present")
	}
	if got := c.Bytes(); got != 6 {
		t.Fatalf("Bytes() = %d, want 6", got)
	}
}

// TestCacheOversizedValueNotStored pins that a single value over the whole
// budget is dropped rather than pinning the cache over budget.
func TestCacheOversizedValueNotStored(t *testing.T) {
	t.Parallel()
	c := cache.New(cache.Options{
		Enabled: true, TTL: time.Minute, MaxEntries: 10, MaxBytes: 5, Clock: newFakeClock(),
	})
	c.Set("big", make([]byte, 6))
	if _, ok := c.Get("big"); ok {
		t.Fatal("oversized value must not be retained")
	}
	if got := c.Bytes(); got != 0 {
		t.Fatalf("Bytes() = %d, want 0", got)
	}
}

// TestCacheOverwriteDoesNotDoubleCountBytes pins the replace path: overwriting
// an existing key must subtract the old value before counting the new one.
func TestCacheOverwriteDoesNotDoubleCountBytes(t *testing.T) {
	t.Parallel()
	c := cache.New(cache.Options{
		Enabled: true, TTL: time.Minute, MaxEntries: 10, MaxBytes: 100, Clock: newFakeClock(),
	})
	c.Set("k", make([]byte, 10))
	c.Set("k", make([]byte, 30))
	if got := c.Bytes(); got != 30 {
		t.Fatalf("Bytes() = %d, want 30", got)
	}
}

func TestCacheKeyDeterministicAndIsolatesIdentity(t *testing.T) {
	t.Parallel()
	// Same URL + transform + profile → same key.
	k1 := cache.Key("https://example.com/a", "markdown", "github", "")
	k2 := cache.Key("https://example.com/a", "markdown", "github", "")
	if k1 != k2 {
		t.Fatalf("identical inputs produced different keys: %q vs %q", k1, k2)
	}

	// Different auth profile → different key (identity isolation).
	k3 := cache.Key("https://example.com/a", "markdown", "internal-sso", "")
	if k1 == k3 {
		t.Fatal("expected different keys for different auth profiles")
	}

	// Different transform → different key.
	k4 := cache.Key("https://example.com/a", "article", "github", "")
	if k1 == k4 {
		t.Fatal("expected different keys for different transforms")
	}

	// Key is a hex sha256 digest (64 chars).
	if len(k1) != 64 {
		t.Fatalf("expected 64-char hex key, got %d chars", len(k1))
	}
}

func TestCacheJanitorEvictsExpired(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	c := cache.New(cache.Options{
		Enabled:    true,
		TTL:        time.Minute,
		MaxEntries: 100,
		Clock:      clock,
		Janitor:    10 * time.Millisecond,
	})
	c.Start()
	defer c.Stop()

	c.Set("k1", []byte("data"))
	clock.advance(2 * time.Minute)

	// Give the janitor time to sweep.
	time.Sleep(100 * time.Millisecond)

	if n := c.Len(); n != 0 {
		t.Fatalf("expected janitor to evict expired entry, got %d entries", n)
	}
}

func TestCacheOverwriteUpdatesExpiry(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	c := cache.New(cache.Options{Enabled: true, TTL: time.Minute, MaxEntries: 10, Clock: clock})
	c.Set("k", []byte("v1"))

	clock.advance(30 * time.Second)
	c.Set("k", []byte("v2")) // resets expiry to now + TTL

	clock.advance(40 * time.Second) // 70s from first set, 40s from second
	got, ok := c.Get("k")
	if !ok {
		t.Fatal("expected hit: overwrite should have reset expiry")
	}
	if string(got) != "v2" {
		t.Fatalf("got %q, want %q", got, "v2")
	}
}

func TestCacheDisabledIsNoop(t *testing.T) {
	t.Parallel()
	c := cache.New(cache.Options{Enabled: false, TTL: time.Minute, MaxEntries: 10, Clock: newFakeClock()})
	c.Set("k", []byte("v"))
	if _, ok := c.Get("k"); ok {
		t.Fatal("disabled cache should never return hits")
	}
}

// TestKeyNoFieldBoundaryCollisions pins the delimiter-based encoding: two
// distinct (URL, transform, profile) tuples whose naive concatenations are
// equal must produce different keys, or one request can be served another's
// content (including content fetched under a different auth identity).
func TestKeyNoFieldBoundaryCollisions(t *testing.T) {
	t.Parallel()
	a := cache.Key("https://example.com/", "raw", "markdown", "")
	b := cache.Key("https://example.com/raw", "markdown", "", "")
	if a == b {
		t.Fatalf("field-boundary collision: %q == %q", a, b)
	}
	c := cache.Key("https://example.com/", "raw", "sso", "")
	d := cache.Key("https://example.com/raw", "sso", "", "")
	if c == d {
		t.Fatalf("field-boundary collision with profile: %q == %q", c, d)
	}
	// Identical tuples still key identically (cache correctness).
	if cache.Key("https://example.com/", "raw", "", "") != cache.Key("https://example.com"+"/", "raw", "", "") {
		t.Fatal("identical tuples must produce identical keys")
	}
}

// TestEvictionIsLRUNotFIFO pins the recency semantics: a Get refreshes an
// entry's recency, so at capacity the least-recently-USED entry (not the
// oldest-inserted one) is evicted.
func TestEvictionIsLRUNotFIFO(t *testing.T) {
	t.Parallel()
	c := cache.New(cache.Options{Enabled: true, TTL: time.Minute, MaxEntries: 2, Janitor: time.Hour})
	defer c.Stop()
	c.Start()

	c.Set("a", []byte("1"))
	c.Set("b", []byte("2"))
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should be cached")
	} // a is now the most recently used; b is the LRU
	c.Set("c", []byte("3")) // must evict b, not a

	if _, ok := c.Get("b"); ok {
		t.Error("b (least recently used) should have been evicted")
	}
	if v, ok := c.Get("a"); !ok || string(v) != "1" {
		t.Error("a (recently used) should have survived eviction")
	}
	if v, ok := c.Get("c"); !ok || string(v) != "3" {
		t.Error("c should be present")
	}
}
