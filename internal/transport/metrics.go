// Package transport — in-memory Prometheus-style counters for the transport layer.
//
// The prometheus/client_golang library is not yet an approved dependency
// (manifest §0 rule 2). We maintain counters in-memory using sync/atomic and
// expose them in Prometheus text format via a FormatMetrics function that
// cmd/collector/main.go calls from its metricsHandler. When the library is
// eventually approved, these atomics can be replaced with prometheus.Counter
// registrations without changing the call sites.
package transport

import (
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
)

// dlqCounter tracks DLQ writes bucketed by HTTP status code.
// Allocated lazily; safe for concurrent access.
var (
	dlqMu       sync.Mutex
	dlqCounters = map[int]*atomic.Int64{}
)

// incDLQCounter increments the per-status-code DLQ write counter.
func incDLQCounter(statusCode int) {
	dlqMu.Lock()
	c, ok := dlqCounters[statusCode]
	if !ok {
		c = &atomic.Int64{}
		dlqCounters[statusCode] = c
	}
	dlqMu.Unlock()
	c.Add(1)
}

// WriteDLQMetrics writes the operitas_collector_dlq_writes_total counter family
// to w in Prometheus text exposition format (version 0.0.4).
// It is called by cmd/collector/main.go's metricsHandler so the metric is
// present in /metrics output as soon as the first DLQ write occurs.
func WriteDLQMetrics(w io.Writer) {
	fmt.Fprintln(w, `# HELP operitas_collector_dlq_writes_total Total number of batches routed to the dead-letter queue, by HTTP status code.`)
	fmt.Fprintln(w, `# TYPE operitas_collector_dlq_writes_total counter`)

	dlqMu.Lock()
	// Snapshot under lock; write outside to avoid holding the lock while doing I/O.
	type kv struct {
		code  int
		value int64
	}
	snapshot := make([]kv, 0, len(dlqCounters))
	for code, c := range dlqCounters {
		snapshot = append(snapshot, kv{code: code, value: c.Load()})
	}
	dlqMu.Unlock()

	for _, s := range snapshot {
		fmt.Fprintf(w, "operitas_collector_dlq_writes_total{status_code=%q} %s\n",
			strconv.Itoa(s.code), strconv.FormatInt(s.value, 10))
	}
}
