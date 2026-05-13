package gitlab

import (
	"testing"
	"time"
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
