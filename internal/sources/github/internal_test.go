package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	gogithub "github.com/google/go-github/v63/github"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
)

// TestWebhookActive verifies the mutex between webhook receiver and poller.
// When WebhookSecret is set, WebhookActive() must return true so main.go
// skips starting the poller and prevents duplicate ledger rows.
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
			s := &Source{cfg: config.GitHubConfig{WebhookSecret: tc.secret}}
			if got := s.WebhookActive(); got != tc.want {
				t.Errorf("WebhookActive() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestLoadCursorMissing verifies that a missing cursor file is treated as a
// first-run condition (zero time) rather than an error.
func TestLoadCursorMissing(t *testing.T) {
	s := &Source{cursorPath: t.TempDir() + "/no-such-cursor"}
	s.loadCursor()
	if !s.lastPollAt.IsZero() {
		t.Errorf("expected zero lastPollAt on missing cursor, got %v", s.lastPollAt)
	}
}

// TestCursorRoundTrip writes a cursor and reads it back via loadCursor to
// confirm the durable write path and the parse path agree.
func TestCursorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cursorPath := dir + "/cursor"

	want := time.Date(2026, 5, 13, 10, 11, 12, 999000000, time.UTC)

	s := &Source{cursorPath: cursorPath, lastPollAt: want}
	s.writeCursor()

	// Verify the file was actually created.
	raw, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatalf("cursor file not created: %v", err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		t.Fatal("cursor file is empty")
	}

	// Load via a fresh Source and verify the parsed time equals what we wrote.
	s2 := &Source{cursorPath: cursorPath}
	s2.loadCursor()
	if !s2.lastPollAt.Equal(want) {
		t.Errorf("loaded cursor = %v, want %v", s2.lastPollAt, want)
	}
}

// TestCursorCrashSafety confirms that a torn .tmp file (crash between Write
// and Rename) does not overwrite a previously committed cursor value.
func TestCursorCrashSafety(t *testing.T) {
	dir := t.TempDir()
	cursorPath := dir + "/cursor"

	good := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Source{cursorPath: cursorPath, lastPollAt: good}
	s.writeCursor()

	// Simulate crash: leave a partial .tmp but never rename it.
	if err := os.WriteFile(cursorPath+".tmp", []byte("torn-partial-data"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2 := &Source{cursorPath: cursorPath}
	s2.loadCursor()
	if !s2.lastPollAt.Equal(good) {
		t.Errorf("post-crash cursor = %v, want %v (committed value)", s2.lastPollAt, good)
	}
}

// TestWriteCursorNoPath verifies that writeCursor is a no-op when cursorPath
// is empty, rather than panicking or writing to the working directory.
func TestWriteCursorNoPath(t *testing.T) {
	s := &Source{cursorPath: "", lastPollAt: time.Now()}
	s.writeCursor() // must not panic or create any file
}

// newTestGHClient returns a go-github client wired to srv so we can exercise
// poll() against a controlled HTTP server without real network access.
func newTestGHClient(srv *httptest.Server) *gogithub.Client {
	baseURL, _ := url.Parse(srv.URL + "/")
	gh := gogithub.NewClient(nil)
	gh.BaseURL = baseURL
	return gh
}

// TestPollCursorNotAdvancedOnFailure is the core fail-closed regression test.
// When any per-repo sub-fetch errors, poll() must return a non-nil error and
// must NOT advance or persist the cursor so PollLoop retries the same window.
func TestPollCursorNotAdvancedOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a transient upstream outage.
		http.Error(w, `{"message":"upstream error"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	s := &Source{
		cfg: config.GitHubConfig{
			Org:          "test-org",
			Repos:        []string{"test-repo"}, // skip org-level repo listing
			PollInterval: time.Minute,
		},
		client:     newTestGHClient(srv),
		emit:       func(envelope.Event) {},
		cursorPath: dir + "/cursor",
	}

	if err := s.poll(context.Background()); err == nil {
		t.Fatal("poll() must return a non-nil error when a sub-fetch fails")
	}
	if !s.lastPollAt.IsZero() {
		t.Errorf("cursor advanced on failure: lastPollAt = %v (want zero)", s.lastPollAt)
	}
	if _, statErr := os.Stat(dir + "/cursor"); !os.IsNotExist(statErr) {
		t.Error("cursor file written despite poll failure — would cause evidence gap on next restart")
	}
}

// TestPollCursorAdvancedOnSuccess verifies that a fully-successful poll cycle
// advances the in-memory cursor and writes the durable cursor file.
func TestPollCursorAdvancedOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return an empty JSON array for every call (no PRs or deployments).
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]")) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	before := time.Now()
	s := &Source{
		cfg: config.GitHubConfig{
			Org:          "test-org",
			Repos:        []string{"test-repo"},
			PollInterval: time.Minute,
		},
		client:     newTestGHClient(srv),
		emit:       func(envelope.Event) {},
		cursorPath: dir + "/cursor",
	}

	if err := s.poll(context.Background()); err != nil {
		t.Fatalf("unexpected poll error: %v", err)
	}
	if s.lastPollAt.IsZero() || s.lastPollAt.Before(before) {
		t.Errorf("cursor not advanced after successful poll: lastPollAt=%v (want > %v)", s.lastPollAt, before)
	}
	if _, statErr := os.Stat(dir + "/cursor"); statErr != nil {
		t.Errorf("cursor file not written after successful poll: %v", statErr)
	}
}
