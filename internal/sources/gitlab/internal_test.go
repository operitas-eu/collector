package gitlab

import (
	"os"
	"testing"
	"time"

	"operitas.eu/collector/internal/config"
)

func TestDeployEventType(t *testing.T) {
	tests := map[string]string{
		"success":  "deploy.completed",
		"failed":   "deploy.failed",
		"canceled": "deploy.failed",
		"running":  "deploy.started",
		"created":  "deploy.started",
		"blocked":  "deploy.started",
		"":         "deploy.started",
	}
	for status, want := range tests {
		t.Run(status, func(t *testing.T) {
			if got := deployEventType(status); got != want {
				t.Errorf("deployEventType(%q)=%q want %q", status, got, want)
			}
		})
	}
}

func TestParseGitLabTime(t *testing.T) {
	rfc, err := parseGitLabTime("2026-05-13T10:11:12Z")
	if err != nil {
		t.Fatalf("rfc3339: %v", err)
	}
	want := time.Date(2026, 5, 13, 10, 11, 12, 0, time.UTC)
	if !rfc.Equal(want) {
		t.Errorf("rfc3339 parsed=%v want %v", rfc, want)
	}

	wh, err := parseGitLabTime("2026-05-13 10:11:12 UTC")
	if err != nil {
		t.Fatalf("webhook fmt: %v", err)
	}
	if !wh.Equal(want) {
		t.Errorf("webhook fmt parsed=%v want %v", wh, want)
	}

	if _, err := parseGitLabTime("not a time"); err == nil {
		t.Error("expected error for unrecognized format")
	}
}

func TestIntFromAny(t *testing.T) {
	if got := intFromAny(float64(42)); got != 42 {
		t.Errorf("float64 -> %d want 42", got)
	}
	if got := intFromAny(7); got != 7 {
		t.Errorf("int -> %d want 7", got)
	}
	if got := intFromAny("nope"); got != 0 {
		t.Errorf("string -> %d want 0", got)
	}
	if got := intFromAny(nil); got != 0 {
		t.Errorf("nil -> %d want 0", got)
	}
}

func TestProjectPathFallback(t *testing.T) {
	if got := (project{ID: 99}).path(); got != "99" {
		t.Errorf("ID-only path=%q want \"99\"", got)
	}
	if got := (project{ID: 99, PathWithNamespace: "g/r"}).path(); got != "g/r" {
		t.Errorf("with path=%q want g/r", got)
	}
}

// TestWebhookActive verifies the mutex between webhook receiver and poller.
func TestWebhookActive(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   bool
	}{
		{"secret set: webhook active, poller suppressed", "s3cr3t", true},
		{"no secret: webhook inactive, poller allowed", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Source{cfg: config.GitLabConfig{WebhookSecret: tc.secret}}
			if got := s.WebhookActive(); got != tc.want {
				t.Errorf("WebhookActive() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestGitLabCursorRoundTrip writes a cursor timestamp and reads it back via
// loadCursor to confirm the durable write path and the parse path agree.
func TestGitLabCursorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cursorPath := dir + "/cursor"

	want := time.Date(2026, 5, 13, 10, 11, 12, 999000000, time.UTC)
	s := &Source{cursorPath: cursorPath, lastPollAt: want}
	s.writeCursor()

	raw, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatalf("cursor file not created: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("cursor file is empty")
	}

	s2 := &Source{cursorPath: cursorPath}
	s2.loadCursor()
	if !s2.lastPollAt.Equal(want) {
		t.Errorf("loaded cursor = %v, want %v", s2.lastPollAt, want)
	}
}

// TestGitLabCursorCrashSafety confirms that a torn .tmp file does not clobber
// a previously committed cursor value.
func TestGitLabCursorCrashSafety(t *testing.T) {
	dir := t.TempDir()
	cursorPath := dir + "/cursor"

	good := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Source{cursorPath: cursorPath, lastPollAt: good}
	s.writeCursor()

	if err := os.WriteFile(cursorPath+".tmp", []byte("torn-partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2 := &Source{cursorPath: cursorPath}
	s2.loadCursor()
	if !s2.lastPollAt.Equal(good) {
		t.Errorf("post-crash cursor = %v, want %v", s2.lastPollAt, good)
	}
}

// TestGitLabCursorMissingIsFirstRun confirms a missing cursor file starts
// from zero time (first-run condition) with no error logged.
func TestGitLabCursorMissingIsFirstRun(t *testing.T) {
	s := &Source{cursorPath: t.TempDir() + "/does-not-exist"}
	s.loadCursor()
	if !s.lastPollAt.IsZero() {
		t.Errorf("expected zero lastPollAt on first run, got %v", s.lastPollAt)
	}
}
