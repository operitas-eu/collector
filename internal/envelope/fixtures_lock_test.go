package envelope_test

// FIXTURES.lock guards the collector's checked-in envelope fixture copy against
// silent drift from the canonical set.
//
// The collector cannot read the canonical fixture tree (it lives in the private
// operitas-eu/operitas monorepo at infra/schemas/fixtures/envelope/), so it
// self-checks against a committed sha256 manifest. Any fixture add/remove/edit
// changes the manifest, so the lock must be regenerated — which turns the change
// into a visible FIXTURES.lock diff in the PR. That diff is the signal that the
// same change has to land in the monorepo in lock-step (manifest §0).
//
// This is the left-shift: before, a fixture change here was only caught later,
// on the monorepo side, by the envelope-contract-mirror CI job (which remains
// the hard cross-repo gate and diffs the real fixtures). Now the collector's own
// CI fails immediately and names the lock-step obligation at change time —
// important because this repo is public and may take contributions from people
// who cannot see the monorepo's CI.
//
// Regenerate after an intentional fixture change:
//
//	UPDATE_FIXTURES_LOCK=1 go test ./internal/envelope/ -run TestFixturesMatchLock
//
// The manifest is sorted "<sha256hex>  <relpath>" lines, relpath relative to
// testdata/fixtures with forward slashes. Only *.json fixtures are hashed; the
// .expect.txt companions and FIXTURES.lock itself are not part of the manifest.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const fixturesLockName = "FIXTURES.lock"

// fixturesManifest walks the fixture tree under root and returns the canonical
// sha256 manifest: sorted "<hex>  <relpath>" lines, one per *.json fixture.
func fixturesManifest(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		sum := sha256.Sum256(b)
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	if len(lines) == 0 {
		t.Fatalf("no *.json fixtures found under %s", root)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func TestFixturesMatchLock(t *testing.T) {
	root := fixtureRoot(t)
	lockPath := filepath.Join(root, fixturesLockName)
	got := fixturesManifest(t, root)

	if os.Getenv("UPDATE_FIXTURES_LOCK") == "1" {
		if err := os.WriteFile(lockPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write %s: %v", fixturesLockName, err)
		}
		t.Logf("wrote %s (%d fixtures)", fixturesLockName, strings.Count(got, "\n"))
		return
	}

	want, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read %s: %v\nregenerate with: UPDATE_FIXTURES_LOCK=1 go test ./internal/envelope/ -run TestFixturesMatchLock",
			fixturesLockName, err)
	}
	if string(want) != got {
		t.Fatalf("envelope fixtures have drifted from %s.\n\n"+
			"If this change is intentional:\n"+
			"  1. regenerate: UPDATE_FIXTURES_LOCK=1 go test ./internal/envelope/ -run TestFixturesMatchLock\n"+
			"  2. land the SAME fixture change in the monorepo's infra/schemas/fixtures/envelope/ in lock-step (manifest §0).\n\n"+
			"committed %s:\n%s\ncurrent fixtures:\n%s",
			fixturesLockName, fixturesLockName, string(want), got)
	}
}
