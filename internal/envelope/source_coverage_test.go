package envelope

// TestSourceFixtureCoverage asserts that every source registered in validSources
// has a dedicated fixture file in testdata/fixtures/valid/.
//
// This test is in package envelope (not envelope_test) so it can range over the
// unexported validSources map directly. That makes validSources the single source
// of truth: add a Source* constant + validSources entry and the coverage guard
// fires automatically — no hand-maintained list to forget.
//
// Naming convention: dots in the source string are replaced by underscores,
// so "k8s.audit" expects "k8s_audit.json". A legacy fallback also accepts the
// dots-removed form (e.g. "awscloudtrail.json" for "aws.cloudtrail").
//
// Multi-source fixtures such as full.json do NOT satisfy this guard — each source
// must own one named file.
//
// When a new Source* constant is added to validSources, the failure message names
// the expected file so the remediation step is immediately clear.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sourceFixtureName returns the canonical fixture filename for a source:
// dots replaced by underscores, e.g. "k8s.audit" → "k8s_audit.json".
func sourceFixtureName(src EventSource) string {
	return strings.ReplaceAll(string(src), ".", "_") + ".json"
}

// sourceHasFixture returns true if a dedicated fixture exists for src.
// It tries the canonical (dots→underscores) form first, then the legacy
// dots-removed form (handles "awscloudtrail.json" for "aws.cloudtrail").
func sourceHasFixture(dir string, src EventSource) bool {
	canonical := sourceFixtureName(src)
	if _, err := os.Stat(filepath.Join(dir, canonical)); err == nil {
		return true
	}
	legacy := strings.ReplaceAll(string(src), ".", "") + ".json"
	if legacy != canonical {
		if _, err := os.Stat(filepath.Join(dir, legacy)); err == nil {
			return true
		}
	}
	return false
}

func TestSourceFixtureCoverage(t *testing.T) {
	validDir, err := filepath.Abs(filepath.Join("testdata", "fixtures", "valid"))
	if err != nil {
		t.Fatalf("resolve fixture dir: %v", err)
	}
	if _, err := os.Stat(validDir); err != nil {
		t.Fatalf("fixture dir %s not found: %v — run from internal/envelope/", validDir, err)
	}

	var missing []string
	for src := range validSources {
		if !sourceHasFixture(validDir, src) {
			missing = append(missing, sourceFixtureName(src))
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing) // deterministic output regardless of map iteration order
		t.Logf("registered sources missing a dedicated fixture file (%d):", len(missing))
		for _, f := range missing {
			t.Logf("  add: testdata/fixtures/valid/%s", f)
		}
		t.Fatalf("add the %d missing fixture file(s) listed above, then regenerate FIXTURES.lock", len(missing))
	}
}
