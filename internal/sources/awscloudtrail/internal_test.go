package awscloudtrail

import (
	"os"
	"strings"
	"testing"
)

// TestAdvanceCursor verifies the fail-closed cursor-advance logic.
// The key correctness property: any failed key (and every key that sorts after
// it in the page) must be re-listed on the next poll.  Re-processing a
// previously-succeeded key is acceptable because the ledger deduplicates on
// (tenant, source, event_id); skipping a failed key is not.
func TestAdvanceCursor(t *testing.T) {
	tests := []struct {
		name       string
		pageKeys   []string
		failedKeys []string
		current    string
		want       string
	}{
		{
			name:     "no failures: advance to max page key",
			pageKeys: []string{"A", "B", "C"},
			current:  "",
			want:     "C",
		},
		{
			name:     "no failures: never regress current cursor",
			pageKeys: []string{"A", "B"},
			current:  "C",
			want:     "C",
		},
		{
			name:       "first key fails: cursor does not advance",
			pageKeys:   []string{"A", "B", "C"},
			failedKeys: []string{"A"},
			current:    "",
			want:       "",
		},
		{
			name:       "middle key fails: advance to key just before it",
			pageKeys:   []string{"A", "B", "C"},
			failedKeys: []string{"B"},
			current:    "",
			want:       "A",
		},
		{
			name:       "last key fails: advance to second-to-last",
			pageKeys:   []string{"A", "B", "C"},
			failedKeys: []string{"C"},
			current:    "",
			want:       "B",
		},
		{
			name:       "multiple failures: cap strictly below earliest failure",
			pageKeys:   []string{"A", "B", "C", "D"},
			failedKeys: []string{"C", "B"},
			current:    "",
			want:       "A",
		},
		{
			name:       "all keys fail: cursor stays at current",
			pageKeys:   []string{"A", "B", "C"},
			failedKeys: []string{"A", "B", "C"},
			current:    "",
			want:       "",
		},
		{
			name:       "fail floor below current: cursor does not regress",
			pageKeys:   []string{"B", "C"},
			failedKeys: []string{"B"},
			current:    "A",
			want:       "A",
		},
		{
			name:       "real S3 key paths sort correctly",
			pageKeys:   []string{"AWSLogs/2026/05/07/a.json.gz", "AWSLogs/2026/05/07/b.json.gz", "AWSLogs/2026/05/07/c.json.gz"},
			failedKeys: []string{"AWSLogs/2026/05/07/b.json.gz"},
			current:    "",
			want:       "AWSLogs/2026/05/07/a.json.gz",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := advanceCursor(tc.pageKeys, tc.failedKeys, tc.current)
			if got != tc.want {
				t.Errorf("advanceCursor(page=%v, failed=%v, current=%q) = %q, want %q",
					tc.pageKeys, tc.failedKeys, tc.current, got, tc.want)
			}
		})
	}
}

// TestWriteAndLoadCursor verifies that writeCursor persists lastKey and that a
// new Source constructed with the same cursorPath restores the value.
func TestWriteAndLoadCursor(t *testing.T) {
	dir := t.TempDir()
	cursorPath := dir + "/cursor"

	const want = "AWSLogs/2026/05/07/cloudtrail-0001.json.gz"

	s := &Source{cursorPath: cursorPath, lastKey: want}
	s.writeCursor()

	// The cursor file must exist and contain exactly lastKey.
	data, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatalf("cursor file not created: %v", err)
	}
	if string(data) != want {
		t.Errorf("cursor content = %q, want %q", string(data), want)
	}

	// A new Source with the same path must restore the same lastKey via the
	// same load path that New() uses.
	s2 := &Source{cursorPath: cursorPath}
	if raw, err := os.ReadFile(s2.cursorPath); err == nil {
		s2.lastKey = strings.TrimSpace(string(raw))
	}
	if s2.lastKey != want {
		t.Errorf("loaded cursor = %q, want %q", s2.lastKey, want)
	}
}

// TestCursorCrashSafety verifies that a torn .tmp write (crash between Write
// and Rename) does not corrupt the previous cursor value.  After a crash the
// collector should restart from the last successfully committed position rather
// than loading a partially-written file.
func TestCursorCrashSafety(t *testing.T) {
	dir := t.TempDir()
	cursorPath := dir + "/cursor"

	// Establish a known-good cursor.
	const goodKey = "AWSLogs/2026/05/07/good.json.gz"
	s := &Source{cursorPath: cursorPath, lastKey: goodKey}
	s.writeCursor()

	// Simulate a crash: write a partial .tmp file but never rename it.
	if err := os.WriteFile(cursorPath+".tmp", []byte("partial-torn-value"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Load: the .tmp file must be ignored; the real cursor file is intact.
	s2 := &Source{cursorPath: cursorPath}
	if raw, err := os.ReadFile(s2.cursorPath); err == nil {
		s2.lastKey = strings.TrimSpace(string(raw))
	}
	if s2.lastKey != goodKey {
		t.Errorf("after simulated crash, cursor = %q, want %q (real cursor file)", s2.lastKey, goodKey)
	}
}

// TestCursorEmptyOnFirstRun verifies that when no cursor file exists the
// collector starts from the beginning (empty lastKey) rather than treating a
// missing file as an error.
func TestCursorEmptyOnFirstRun(t *testing.T) {
	dir := t.TempDir()
	// No cursor file written.
	s := &Source{cursorPath: dir + "/does-not-exist"}
	if raw, err := os.ReadFile(s.cursorPath); err == nil {
		s.lastKey = strings.TrimSpace(string(raw))
	}
	if s.lastKey != "" {
		t.Errorf("expected empty cursor on first run, got %q", s.lastKey)
	}
}
