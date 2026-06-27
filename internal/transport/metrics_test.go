package transport

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetWALCounters zeroes the package-level WAL counters between tests so a
// test that asserts an exact value isn't polluted by a previous test's
// writes. The counters are global atomics, mirroring the operational reality
// (one collector process), so tests cannot run in parallel against them —
// hence no t.Parallel() in this file.
func resetWALCounters() {
	walWritesTotal.Store(0)
	walDeletesTotal.Store(0)
	walReplaysTotal.Store(0)
	walPrunedByAge.Store(0)
	walPrunedBySize.Store(0)
}

func TestWALMetrics_WriteIncrementsOnSuccess(t *testing.T) {
	resetWALCounters()
	dir := t.TempDir()

	if err := walWrite(dir, "abc", []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("walWrite: %v", err)
	}
	if got := walWritesTotal.Load(); got != 1 {
		t.Fatalf("walWritesTotal = %d, want 1", got)
	}

	// A second successful write bumps the counter again.
	if err := walWrite(dir, "def", []byte(`{}`)); err != nil {
		t.Fatalf("walWrite: %v", err)
	}
	if got := walWritesTotal.Load(); got != 2 {
		t.Fatalf("walWritesTotal = %d, want 2", got)
	}
}

func TestWALMetrics_DeleteOnlyCountsActualRemovals(t *testing.T) {
	resetWALCounters()
	dir := t.TempDir()

	if err := walWrite(dir, "abc", []byte(`{}`)); err != nil {
		t.Fatalf("walWrite: %v", err)
	}
	// First delete actually removes the file → counter bumps to 1.
	if err := walDelete(dir, "abc"); err != nil {
		t.Fatalf("walDelete: %v", err)
	}
	if got := walDeletesTotal.Load(); got != 1 {
		t.Fatalf("walDeletesTotal after real delete = %d, want 1", got)
	}
	// A second delete on the same key is a no-op — the file is gone, the
	// counter must NOT double-count. This matters because callers
	// (deliverWithRetry, replayWAL, batch split) may call delete on an
	// entry walPrune already evicted, and we want each spool entry to
	// contribute at most one delete event to the counter.
	if err := walDelete(dir, "abc"); err != nil {
		t.Fatalf("walDelete idempotent: %v", err)
	}
	if got := walDeletesTotal.Load(); got != 1 {
		t.Fatalf("walDeletesTotal after no-op delete = %d, want still 1", got)
	}
}

func TestWALMetrics_PruneBucketsByReason(t *testing.T) {
	resetWALCounters()
	dir := t.TempDir()

	// One entry that will be pruned by age, one that survives age but
	// trips the size cap.
	mustWrite := func(key, body string) string {
		t.Helper()
		if err := walWrite(dir, key, []byte(body)); err != nil {
			t.Fatalf("walWrite %s: %v", key, err)
		}
		return filepath.Join(dir, key+walExt)
	}

	// walWrite requires valid JSON because the on-disk record wraps the
	// payload as json.RawMessage. Build a JSON object whose body is large
	// enough to trip the size cap.
	bigJSON := func(filler string) string {
		return `{"filler":"` + strings.Repeat(filler, 500) + `"}`
	}
	oldPath := mustWrite("old", `{"x":1}`)
	mustWrite("new1", bigJSON("a"))
	mustWrite("new2", bigJSON("b"))

	// Backdate the "old" entry past the prune cutoff.
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldPath, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// maxAge=24h evicts "old"; maxBytes=600 evicts the older surviving
	// entry to bring total below cap. Counters split accordingly.
	if _, err := walPrune(dir, 24*time.Hour, 600); err != nil {
		t.Fatalf("walPrune: %v", err)
	}
	if got := walPrunedByAge.Load(); got != 1 {
		t.Fatalf("walPrunedByAge = %d, want 1", got)
	}
	if got := walPrunedBySize.Load(); got < 1 {
		t.Fatalf("walPrunedBySize = %d, want >= 1", got)
	}
}

func TestWALMetrics_ReplayIncrementsPerEntry(t *testing.T) {
	resetWALCounters()
	dir := t.TempDir()

	// Seed the spool with three recoverable entries.
	for _, k := range []string{"a", "b", "c"} {
		if err := walWrite(dir, k, []byte(`{"k":"`+k+`"}`)); err != nil {
			t.Fatalf("walWrite %s: %v", k, err)
		}
	}
	// walRecover doesn't bump the counter (it's a read operation); the
	// replay loop in client.go calls incWALReplays() per entry. Simulate
	// that loop here to keep this test in package transport without
	// requiring a fully-wired Client + ingest stub.
	entries, err := walRecover(dir)
	if err != nil {
		t.Fatalf("walRecover: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("walRecover returned %d entries, want 3", len(entries))
	}
	for range entries {
		incWALReplays()
	}
	if got := walReplaysTotal.Load(); got != 3 {
		t.Fatalf("walReplaysTotal = %d, want 3", got)
	}
}

func TestWriteWALMetrics_ProducesExpectedFamilies(t *testing.T) {
	resetWALCounters()
	walWritesTotal.Store(7)
	walDeletesTotal.Store(5)
	walReplaysTotal.Store(2)
	walPrunedByAge.Store(1)
	walPrunedBySize.Store(3)

	var buf bytes.Buffer
	WriteWALMetrics(&buf)
	out := buf.String()

	mustContain := []string{
		"# TYPE operitas_collector_wal_writes_total counter",
		"operitas_collector_wal_writes_total 7",
		"# TYPE operitas_collector_wal_deletes_total counter",
		"operitas_collector_wal_deletes_total 5",
		"# TYPE operitas_collector_wal_replays_total counter",
		"operitas_collector_wal_replays_total 2",
		"# TYPE operitas_collector_wal_pruned_total counter",
		`operitas_collector_wal_pruned_total{reason="age"} 1`,
		`operitas_collector_wal_pruned_total{reason="size"} 3`,
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("WriteWALMetrics output missing %q\n--- full output ---\n%s", want, out)
		}
	}
}
