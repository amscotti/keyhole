package cache_test

import (
	"testing"
	"time"

	"github.com/amscotti/keyhole/internal/cache"
)

func TestCacheDeleteRemovesEntry(t *testing.T) {
	t.Parallel()
	c := cache.New(cache.Options{Enabled: true, TTL: time.Minute, MaxEntries: 10, Clock: newFakeClock()})
	c.Set("k", []byte("v"))
	c.Delete("k")
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected miss after Delete")
	}
}

func TestCacheDeleteMissingKeyIsNoop(t *testing.T) {
	t.Parallel()
	c := cache.New(cache.Options{Enabled: true, TTL: time.Minute, MaxEntries: 10, Clock: newFakeClock()})
	c.Delete("absent") // must not panic
	c.Set("k", []byte("v"))
	c.Delete("absent")
	if _, ok := c.Get("k"); !ok {
		t.Fatal("deleting another key must not evict k")
	}
}

func TestCacheDeleteDisabledIsNoop(t *testing.T) {
	t.Parallel()
	c := cache.New(cache.Options{Enabled: false, TTL: time.Minute, MaxEntries: 10, Clock: newFakeClock()})
	c.Delete("k") // must not panic on a disabled cache
}
