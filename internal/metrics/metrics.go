// Package metrics defines the Prometheus collectors for Keyhole's observability
// surface. All instruments are registered against a single provided registry —
// no global/default Prometheus registry is used, so tests are hermetic and a
// second Keyhole instance in the same process cannot collide.
//
// The instrument set:
//
//   - keyhole_requests_total{transform,status}          — counter
//   - keyhole_fetch_duration_seconds{status}            — histogram
//   - keyhole_transform_duration_seconds{transform}     — histogram
//   - keyhole_cache_hits_total                          — counter
//   - keyhole_cache_misses_total                        — counter
//   - keyhole_policy_denials_total                      — counter
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Collectors groups every Prometheus instrument the server records against. It
// is built once at startup and registered against the process's registry.
type Collectors struct {
	Requests          *prometheus.CounterVec
	FetchDuration     *prometheus.HistogramVec
	TransformDuration *prometheus.HistogramVec
	CacheHits         prometheus.Counter
	CacheMisses       prometheus.Counter
	PolicyDenials     prometheus.Counter
}

// NewCollectors builds all instruments with their label dimensions. The
// instruments are not yet registered — call MustRegister to attach them to a
// registry.
func NewCollectors() *Collectors {
	return &Collectors{
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "keyhole_requests_total",
			Help: "Total number of fetch requests, by transform and HTTP status.",
		}, []string{"transform", "status"}),
		FetchDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "keyhole_fetch_duration_seconds",
			Help:    "Time spent on the outbound HTTP fetch, by outcome status code.",
			Buckets: prometheus.DefBuckets,
		}, []string{"status"}),
		TransformDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "keyhole_transform_duration_seconds",
			Help:    "Time spent applying a transform, by transform name.",
			Buckets: prometheus.DefBuckets,
		}, []string{"transform"}),
		CacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keyhole_cache_hits_total",
			Help: "Total number of cache hits.",
		}),
		CacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keyhole_cache_misses_total",
			Help: "Total number of cache misses.",
		}),
		PolicyDenials: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "keyhole_policy_denials_total",
			Help: "Total number of requests denied by policy.",
		}),
	}
}

// MustRegister registers every instrument against reg. It panics on a duplicate
// registration (a programming error, not a runtime condition).
func (c *Collectors) MustRegister(reg *prometheus.Registry) {
	reg.MustRegister(
		c.Requests,
		c.FetchDuration,
		c.TransformDuration,
		c.CacheHits,
		c.CacheMisses,
		c.PolicyDenials,
	)
}

// RecordRequest increments the requests counter for a transform + HTTP status.
func (c *Collectors) RecordRequest(transform string, status int) {
	c.Requests.WithLabelValues(transform, statusLabel(status)).Inc()
}

// ObserveFetchDuration records the time spent on the outbound fetch.
func (c *Collectors) ObserveFetchDuration(status int, d time.Duration) {
	c.FetchDuration.WithLabelValues(statusLabel(status)).Observe(d.Seconds())
}

// ObserveTransformDuration records the time spent applying a transform.
func (c *Collectors) ObserveTransformDuration(transform string, d time.Duration) {
	c.TransformDuration.WithLabelValues(transform).Observe(d.Seconds())
}

// RecordCacheHit increments the cache hit counter.
func (c *Collectors) RecordCacheHit() { c.CacheHits.Inc() }

// RecordCacheMiss increments the cache miss counter.
func (c *Collectors) RecordCacheMiss() { c.CacheMisses.Inc() }

// RecordPolicyDenial increments the policy denial counter.
func (c *Collectors) RecordPolicyDenial() { c.PolicyDenials.Inc() }

// statusLabel maps an HTTP status code to the label used in metrics. Non-2xx
// statuses are grouped so cardinality stays low while still distinguishing
// success from client/server errors.
func statusLabel(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500:
		return "5xx"
	default:
		return "other"
	}
}
