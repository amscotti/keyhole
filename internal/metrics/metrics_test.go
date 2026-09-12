package metrics_test

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/amscotti/keyhole/internal/metrics"
)

func TestRecordRequest(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	c := metrics.NewCollectors()
	c.MustRegister(reg)

	c.RecordRequest("markdown", 200)
	c.RecordRequest("raw", 200)
	c.RecordRequest("markdown", 403)

	if got := testutil.ToFloat64(c.Requests.WithLabelValues("markdown", "2xx")); got != 1 {
		t.Errorf("markdown 2xx = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.Requests.WithLabelValues("raw", "2xx")); got != 1 {
		t.Errorf("raw 2xx = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.Requests.WithLabelValues("markdown", "4xx")); got != 1 {
		t.Errorf("markdown 4xx = %v, want 1", got)
	}
}

func TestCacheCounters(t *testing.T) {
	t.Parallel()
	c := metrics.NewCollectors()

	c.RecordCacheHit()
	c.RecordCacheHit()
	c.RecordCacheMiss()

	if got := testutil.ToFloat64(c.CacheHits); got != 2 {
		t.Errorf("cache hits = %v, want 2", got)
	}
	if got := testutil.ToFloat64(c.CacheMisses); got != 1 {
		t.Errorf("cache misses = %v, want 1", got)
	}
}

func TestPolicyDenialsCounter(t *testing.T) {
	t.Parallel()
	c := metrics.NewCollectors()

	c.RecordPolicyDenial()
	c.RecordPolicyDenial()

	if got := testutil.ToFloat64(c.PolicyDenials); got != 2 {
		t.Errorf("policy denials = %v, want 2", got)
	}
}

func TestDurationMetricsAcceptData(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	c := metrics.NewCollectors()
	c.MustRegister(reg)

	c.ObserveFetchDuration(200, 50_000_000)   // 50ms
	c.ObserveTransformDuration("markdown", 5) // 5ns — just exercising the API

	// Verify the metric appears in a /metrics scrape. We check that the
	// exposition output contains the metric names.
	if err := testutil.GatherAndCompare(reg, strings.NewReader(""),
		"keyhole_fetch_duration_seconds"); err == nil {
		// GatherAndCompare with empty expected always fails if the metric
		// exists, which is what we want to assert presence. A nil error
		// means the metric was absent — fail.
		t.Error("expected keyhole_fetch_duration_seconds in registry")
	}
}

func TestStatusLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status int
		want   string
	}{
		{200, "2xx"},
		{201, "2xx"},
		{301, "3xx"},
		{400, "4xx"},
		{403, "4xx"},
		{413, "4xx"},
		{500, "5xx"},
		{502, "5xx"},
		{504, "5xx"},
		{0, "other"},
	}
	for _, tc := range cases {
		if got := statusLabelViaCollectors(tc.status); got != tc.want {
			t.Errorf("statusLabel(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

// statusLabelViaCollectors records a dummy request and reads back the label
// that was used — this tests the private function indirectly.
func statusLabelViaCollectors(status int) string {
	c := metrics.NewCollectors()
	// RecordRequest calls statusLabel internally; we verify by reading back.
	c.RecordRequest("raw", status)
	// Scan all label combinations for the one that was incremented.
	for _, label := range []string{"2xx", "3xx", "4xx", "5xx", "other"} {
		if testutil.ToFloat64(c.Requests.WithLabelValues("raw", label)) == 1 {
			return label
		}
	}
	return ""
}
