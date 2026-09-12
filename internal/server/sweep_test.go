package server

import (
	"testing"
	"time"
)

// sweep must drop buckets idle longer than the TTL while keeping active ones,
// bounding memory when client IPs rotate.
func TestRateLimiterSweepRemovesIdleBuckets(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	rl := newRateLimiter(10, 5, clk)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if ok, _ := rl.allow(ip); !ok {
			t.Fatalf("setup allow for %s failed", ip)
		}
	}
	clk.Advance(time.Minute)
	// Keep one bucket fresh after the idle window starts.
	if ok, _ := rl.allow("10.0.0.3"); !ok {
		t.Fatal("setup refresh for 10.0.0.3 failed")
	}
	clk.Advance(2 * time.Minute)
	rl.sweep(2 * time.Minute)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, ok := rl.buckets["10.0.0.1"]; ok {
		t.Error("idle bucket 10.0.0.1 should have been swept")
	}
	if _, ok := rl.buckets["10.0.0.2"]; ok {
		t.Error("idle bucket 10.0.0.2 should have been swept")
	}
	if _, ok := rl.buckets["10.0.0.3"]; !ok {
		t.Error("fresh bucket 10.0.0.3 should have survived")
	}
}

func TestRateLimiterSweepEmptyIsNoop(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(10, 5, newFakeClock())
	rl.sweep(time.Minute) // must not panic on zero buckets
	if len(rl.buckets) != 0 {
		t.Fatalf("got %d buckets, want 0", len(rl.buckets))
	}
}
