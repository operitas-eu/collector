package envelope_test

// Cross-repo wire-contract tests for evidence_envelope.json v1.0.0.
//
// Walks the fixture tree at internal/envelope/testdata/fixtures/envelope/{valid,invalid}
// and asserts:
//
//   - every valid/*.json passes DecodeAndValidate (strict JSON decode + ValidateBatch).
//   - every invalid/*.json is rejected, AND the error contains every substring
//     listed in the companion *.expect.txt — so we assert *why* it was rejected,
//     not just that it was.
//
// Manifest §0 makes these fixtures the single source of truth for what the wire
// format accepts. The ingest service at services/ingest/internal/api/ in the
// operitas-eu/operitas monorepo carries a sibling test that runs against the
// same fixtures with its own validator. Lock-step discipline is enforced by
// humans across the two PRs; this test enforces it on the collector side.
//
// The 1000-event happy case and the 1001-event unhappy case are generated in
// memory rather than checked in — a 1000-element JSON literal is not practical.
// See generateMaxEventsBody below.
//
// TODO: when infra/schemas/ is published as a versioned module or submodule,
// replace the checked-in fixture copy with a vendored reference. See
// internal/envelope/testdata/fixtures/README.md.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"operitas.eu/collector/internal/envelope"
)

// fixtureRoot resolves to the envelope subdirectory of the checked-in fixture
// copy. The test binary runs in internal/envelope, so the path is relative to
// that package directory.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("testdata", "fixtures"))
	if err != nil {
		t.Fatalf("resolve fixture root: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture root %s not found: %v — run from internal/envelope/", root, err)
	}
	return root
}

func TestEnvelopeFixtures_Valid(t *testing.T) {
	root := fixtureRoot(t)
	dir := filepath.Join(root, "valid")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read valid dir: %v", err)
	}
	saw := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		saw++
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if err := envelope.DecodeAndValidate(body); err != nil {
				t.Fatalf("expected accept, got error: %v", err)
			}
		})
	}
	if saw == 0 {
		t.Fatalf("no valid fixtures found under %s", dir)
	}
}

func TestEnvelopeFixtures_Invalid(t *testing.T) {
	root := fixtureRoot(t)
	dir := filepath.Join(root, "invalid")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read invalid dir: %v", err)
	}
	saw := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		saw++
		name := e.Name()
		base := strings.TrimSuffix(name, ".json")
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			gotErr := envelope.DecodeAndValidate(body)
			if gotErr == nil {
				t.Fatalf("expected reject, got accept")
			}

			// Companion .expect.txt: each non-empty, non-comment line is a
			// substring that must appear in the error message.
			expectPath := filepath.Join(dir, base+".expect.txt")
			raw, readErr := os.ReadFile(expectPath)
			if readErr != nil {
				t.Fatalf("missing companion %s: %v", expectPath, readErr)
			}
			gotMsg := gotErr.Error()
			for _, line := range strings.Split(string(raw), "\n") {
				want := strings.TrimSpace(line)
				if want == "" || strings.HasPrefix(want, "#") {
					continue
				}
				if !strings.Contains(gotMsg, want) {
					t.Errorf("error message missing expected substring %q\nfull error: %s", want, gotMsg)
				}
			}
		})
	}
	if saw == 0 {
		t.Fatalf("no invalid fixtures found under %s", dir)
	}
}

// generateMaxEventsBody builds a valid envelope body with exactly n events.
// Used to exercise the maxItems=1000 boundary without checking in a 1000-line
// JSON file. The generation rule must match the monorepo counterpart in
// services/ingest/internal/api/envelope_contract_test.go so both sides agree
// at the exact boundary.
func generateMaxEventsBody(t *testing.T, n int) []byte {
	t.Helper()
	events := make([]map[string]any, n)
	for i := range n {
		events[i] = map[string]any{
			"occurred_at":  fmt.Sprintf("2026-05-07T08:14:%02d.%09dZ", i%60, i),
			"event_type":   "deploy.completed",
			"event_source": "argocd",
			"payload":      map[string]any{"i": i},
		}
	}
	body, err := json.Marshal(map[string]any{
		"collector_id":     "11111111-1111-1111-1111-111111111111",
		"tenant_id":        "22222222-2222-2222-2222-222222222222",
		"envelope_version": "1.0.0",
		"events":           events,
	})
	if err != nil {
		t.Fatalf("generateMaxEventsBody marshal: %v", err)
	}
	return body
}

func TestEnvelopeFixtures_MaxEventsBoundary(t *testing.T) {
	// Exactly 1000 events — must accept (boundary inclusive per maxItems).
	body := generateMaxEventsBody(t, 1000)
	if err := envelope.DecodeAndValidate(body); err != nil {
		t.Fatalf("1000 events should be accepted: %v", err)
	}
}

func TestEnvelopeFixtures_TooManyEvents(t *testing.T) {
	// 1001 events — must reject with a maxItems-shaped error.
	body := generateMaxEventsBody(t, 1001)
	err := envelope.DecodeAndValidate(body)
	if err == nil {
		t.Fatalf("1001 events should be rejected")
	}
	for _, want := range []string{"events", "maxItems"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}
