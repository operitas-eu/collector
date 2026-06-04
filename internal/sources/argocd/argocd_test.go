package argocd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/argocd"
)

// newTestRedactor returns a hard-redact Redactor suitable for unit tests.
func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

// newTestSource builds a Source with a no-op emit and an in-memory event sink.
func newTestSource(t *testing.T, secret string) (*argocd.Source, *[]envelope.Event) {
	t.Helper()
	r := newTestRedactor(t)
	cfg := config.ArgoCDConfig{
		Enabled:       true,
		BaseURL:       "https://argocd.example.eu",
		WebhookSecret: secret,
		Namespace:     "argocd",
		PollInterval:  60 * time.Second,
		CursorPath:    filepath.Join(t.TempDir(), "argocd_cursor"),
	}
	var emitted []envelope.Event
	src := argocd.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })
	return src, &emitted
}

// -------------------------------------------------------------------
// Event type mapping — sync status / health / operation phase
// -------------------------------------------------------------------

func TestMapWebhookEventType(t *testing.T) {
	tests := []struct {
		name           string
		syncStatus     string
		healthStatus   string
		operationPhase string
		want           string
	}{
		// Operation phase is checked first (most specific signal).
		{"op running", "OutOfSync", "Progressing", "Running", "deploy.started"},
		{"op succeeded", "Synced", "Healthy", "Succeeded", "deploy.completed"},
		{"op failed", "Synced", "Healthy", "Failed", "deploy.failed"},
		{"op error", "Synced", "Degraded", "Error", "deploy.failed"},
		{"op terminating", "Synced", "Degraded", "Terminating", "deploy.rolled_back"},
		// No operation phase — fall back to sync+health.
		{"synced healthy no op", "Synced", "Healthy", "", "deploy.completed"},
		{"synced degraded no op", "Synced", "Degraded", "", "deploy.failed"},
		{"synced missing no op", "Synced", "Missing", "", "deploy.failed"},
		{"synced unknown no op", "Synced", "Unknown", "", "deploy.failed"},
		{"synced progressing no op", "Synced", "Progressing", "", "deploy.completed"},
		{"outofsync progressing no op", "OutOfSync", "Progressing", "", "change.iac_applied"},
		{"outofsync healthy no op", "OutOfSync", "Healthy", "", "change.iac_applied"},
		{"unknown sync status", "Unknown", "", "", "deploy.failed"},
		// Case insensitivity.
		{"op succeeded uppercase", "synced", "healthy", "SUCCEEDED", "deploy.completed"},
		{"outofsync mixed case", "OutOfSync", "Healthy", "", "change.iac_applied"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := argocd.MapWebhookEventType(tc.syncStatus, tc.healthStatus, tc.operationPhase)
			if got != tc.want {
				t.Errorf("MapWebhookEventType(%q, %q, %q) = %q, want %q",
					tc.syncStatus, tc.healthStatus, tc.operationPhase, got, tc.want)
			}
		})
	}
}

func TestMapApplicationEventType(t *testing.T) {
	tests := []struct {
		name         string
		syncStatus   string
		healthStatus string
		opState      *argocd.ArgoOperationState
		want         string
	}{
		{
			name:         "nil opstate synced healthy",
			syncStatus:   "Synced",
			healthStatus: "Healthy",
			opState:      nil,
			want:         "deploy.completed",
		},
		{
			name:         "nil opstate outofsync",
			syncStatus:   "OutOfSync",
			healthStatus: "Progressing",
			opState:      nil,
			want:         "change.iac_applied",
		},
		{
			name:         "op succeeded",
			syncStatus:   "Synced",
			healthStatus: "Healthy",
			opState:      &argocd.ArgoOperationState{Phase: "Succeeded"},
			want:         "deploy.completed",
		},
		{
			name:         "op running",
			syncStatus:   "Synced",
			healthStatus: "Progressing",
			opState:      &argocd.ArgoOperationState{Phase: "Running"},
			want:         "deploy.started",
		},
		{
			name:         "op failed",
			syncStatus:   "Synced",
			healthStatus: "Degraded",
			opState:      &argocd.ArgoOperationState{Phase: "Failed"},
			want:         "deploy.failed",
		},
		{
			name:         "op error",
			syncStatus:   "Synced",
			healthStatus: "Degraded",
			opState:      &argocd.ArgoOperationState{Phase: "Error"},
			want:         "deploy.failed",
		},
		{
			name:         "op terminating is rolled back",
			syncStatus:   "Synced",
			healthStatus: "Progressing",
			opState:      &argocd.ArgoOperationState{Phase: "Terminating"},
			want:         "deploy.rolled_back",
		},
		{
			name:         "rollback op succeeded",
			syncStatus:   "Synced",
			healthStatus: "Healthy",
			opState: &argocd.ArgoOperationState{
				Phase: "Succeeded",
				Operation: argocd.ArgoOperation{
					Info: []argocd.ArgoInfo{{Name: "rollback", Value: "true"}},
				},
			},
			want: "deploy.rolled_back",
		},
		{
			name:         "rollback op running",
			syncStatus:   "OutOfSync",
			healthStatus: "Progressing",
			opState: &argocd.ArgoOperationState{
				Phase: "Running",
				Operation: argocd.ArgoOperation{
					Info: []argocd.ArgoInfo{{Name: "Rollback", Value: "v1.2.0"}},
				},
			},
			want: "deploy.started",
		},
		{
			name:         "rollback op failed",
			syncStatus:   "Synced",
			healthStatus: "Degraded",
			opState: &argocd.ArgoOperationState{
				Phase: "Failed",
				Operation: argocd.ArgoOperation{
					Info: []argocd.ArgoInfo{{Name: "rollback", Value: "1"}},
				},
			},
			want: "deploy.failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := argocd.MapApplicationEventType(tc.syncStatus, tc.healthStatus, tc.opState)
			if got != tc.want {
				t.Errorf("MapApplicationEventType(%q, %q, opState) = %q, want %q",
					tc.syncStatus, tc.healthStatus, got, tc.want)
			}
		})
	}
}

// -------------------------------------------------------------------
// Webhook token verification
// -------------------------------------------------------------------

func TestVerifyWebhookToken(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		headerValue string
		want        bool
	}{
		{"valid token", "my-secret-token", "my-secret-token", true},
		{"wrong token", "my-secret-token", "wrong-token", false},
		{"empty both", "", "", false},
		{"empty secret rejects", "", "sometoken", false},
		{"empty header rejects", "my-secret-token", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := argocd.VerifyWebhookToken(tc.secret, tc.headerValue)
			if got != tc.want {
				t.Errorf("VerifyWebhookToken(%q, %q) = %v, want %v",
					tc.secret, tc.headerValue, got, tc.want)
			}
		})
	}
}

// -------------------------------------------------------------------
// HTTP handler: method-not-allowed
// -------------------------------------------------------------------

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	src, _ := newTestSource(t, "secret")
	req := httptest.NewRequest(http.MethodGet, "/webhook/argocd", nil)
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// -------------------------------------------------------------------
// HTTP handler: auth rejection on wrong X-ArgoCD-Token
// -------------------------------------------------------------------

func TestWebhookHandler_AuthRejection(t *testing.T) {
	src, emitted := newTestSource(t, "correct-secret")

	body, _ := json.Marshal(map[string]any{
		"app":             "myapp",
		"sync_status":     "Synced",
		"health_status":   "Healthy",
		"operation_phase": "Succeeded",
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/argocd", bytes.NewReader(body))
	req.Header.Set("X-ArgoCD-Token", "wrong-secret")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if len(*emitted) != 0 {
		t.Errorf("expected no events on auth failure, got %d", len(*emitted))
	}
}

// -------------------------------------------------------------------
// HTTP handler: valid payload from testdata fixture (webhook)
// -------------------------------------------------------------------

func TestWebhookHandler_ValidPayload_Fixture(t *testing.T) {
	src, emitted := newTestSource(t, "test-token")

	body, err := os.ReadFile(filepath.Join("testdata", "webhook_sync_succeeded.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook/argocd", bytes.NewReader(body))
	req.Header.Set("X-ArgoCD-Token", "test-token")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if len(*emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(*emitted))
	}

	ev := (*emitted)[0]

	if ev.EventSource != envelope.SourceArgoCD {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceArgoCD)
	}
	if ev.EventType != "deploy.completed" {
		t.Errorf("event_type = %q, want deploy.completed", ev.EventType)
	}
	if ev.OccurredAt.IsZero() {
		t.Error("occurred_at must not be zero")
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at must be UTC, got %v", ev.OccurredAt.Location())
	}
	// Timestamp from fixture: 2026-06-01T14:22:00Z
	wantTime := time.Date(2026, 6, 1, 14, 22, 0, 0, time.UTC)
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("occurred_at = %v, want %v", ev.OccurredAt, wantTime)
	}
	// Actor: alice@example.eu contains "@" so the redactor replaces it.
	if ev.Actor == nil {
		t.Error("expected non-nil actor")
	} else if *ev.Actor != "[redacted]" {
		t.Errorf("actor = %q, want [redacted]", *ev.Actor)
	}
	// Resource: namespace/app from fixture.
	if ev.Resource == nil {
		t.Error("expected non-nil resource")
	} else if *ev.Resource != "production/platform-api" {
		t.Errorf("resource = %q, want production/platform-api", *ev.Resource)
	}
	if ev.Payload == nil {
		t.Error("payload must not be nil")
	}
	// Must pass envelope schema validation.
	if err := ev.Validate(); err != nil {
		t.Errorf("Validate() error: %v", err)
	}
}

// -------------------------------------------------------------------
// HTTP handler: no secret configured — request passes through
// -------------------------------------------------------------------

func TestWebhookHandler_NoSecret_AllowsThrough(t *testing.T) {
	// When WebhookSecret is empty the auth check is skipped (operator explicitly
	// chose to run without token verification, e.g. behind a private network).
	src, emitted := newTestSource(t, "")

	body, _ := json.Marshal(map[string]any{
		"app":             "myapp",
		"namespace":       "staging",
		"sync_status":     "Synced",
		"health_status":   "Healthy",
		"operation_phase": "Succeeded",
		"timestamp":       "2026-06-01T10:00:00Z",
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/argocd", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if len(*emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(*emitted))
	}
	if (*emitted)[0].EventType != "deploy.completed" {
		t.Errorf("event_type = %q, want deploy.completed", (*emitted)[0].EventType)
	}
}

// -------------------------------------------------------------------
// Poller normalization from API fixture
// -------------------------------------------------------------------

// TestPollerNormalizationFromFixture exercises the full poller path by pointing
// the Source at a fake Argo CD API server that serves testdata/api_application.json.
// It verifies that the polled event is correctly normalized and emitted.
func TestPollerNormalizationFromFixture(t *testing.T) {
	fixtureBody, err := os.ReadFile(filepath.Join("testdata", "api_application.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// Validate fixture is structurally correct for the fields we test below.
	var probeFixture struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Sync struct {
					Status string `json:"status"`
				} `json:"sync"`
				Health struct {
					Status string `json:"status"`
				} `json:"health"`
				OperationState struct {
					Phase       string    `json:"phase"`
					FinishedAt  time.Time `json:"finishedAt"`
					InitiatedBy struct {
						Username string `json:"username"`
					} `json:"initiatedBy"`
				} `json:"operationState"`
			} `json:"status"`
		} `json:"items"`
	}
	if jsonErr := json.Unmarshal(fixtureBody, &probeFixture); jsonErr != nil {
		t.Fatalf("fixture parse error: %v", jsonErr)
	}
	if len(probeFixture.Items) == 0 {
		t.Fatal("fixture has no items")
	}
	item := probeFixture.Items[0]
	if item.Metadata.Name != "payment-service" {
		t.Errorf("fixture app name = %q, want payment-service", item.Metadata.Name)
	}
	if item.Status.Sync.Status != "Synced" {
		t.Errorf("fixture sync.status = %q, want Synced", item.Status.Sync.Status)
	}
	if item.Status.OperationState.Phase != "Succeeded" {
		t.Errorf("fixture op phase = %q, want Succeeded", item.Status.OperationState.Phase)
	}

	// Serve the fixture from a fake Argo CD API server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("poller made non-GET request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/api/v1/applications" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-poll-token" {
			t.Errorf("Authorization = %q, want Bearer test-poll-token", auth)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixtureBody)
	}))
	defer srv.Close()

	r := newTestRedactor(t)
	cfg := config.ArgoCDConfig{
		Enabled:      true,
		BaseURL:      srv.URL,
		Token:        "test-poll-token",
		Namespace:    "production",
		PollInterval: time.Hour, // long enough that the ticker never fires in the test
		CursorPath:   filepath.Join(t.TempDir(), "argocd_cursor"),
	}

	var emitted []envelope.Event
	// emitted in a goroutine — use a channel to signal completion so we can
	// cancel the poller after the first (and only) event arrives.
	emitDone := make(chan struct{})
	src := argocd.New(cfg, r, func(e envelope.Event) {
		emitted = append(emitted, e)
		// Signal after the first event so the test can cancel the poller.
		select {
		case emitDone <- struct{}{}:
		default:
		}
	})

	// PollLoop fires once immediately, then waits on the ticker (1h interval).
	// We cancel the context as soon as the first poll completes so RunPoller exits.
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- src.RunPoller(ctx)
	}()

	// Wait for the first emission, then cancel.
	select {
	case <-emitDone:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timeout waiting for poller to emit first event")
	}

	// Wait for RunPoller to return.
	select {
	case pollErr := <-runDone:
		if pollErr != nil {
			t.Fatalf("RunPoller returned unexpected error: %v", pollErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunPoller did not return after context cancel")
	}

	if len(emitted) != 1 {
		t.Fatalf("expected 1 event from poller, got %d", len(emitted))
	}

	ev := emitted[0]

	if ev.EventSource != envelope.SourceArgoCD {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceArgoCD)
	}
	if ev.EventType != "deploy.completed" {
		t.Errorf("event_type = %q, want deploy.completed", ev.EventType)
	}
	if ev.OccurredAt.IsZero() {
		t.Error("occurred_at must not be zero")
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at must be UTC, got %v", ev.OccurredAt.Location())
	}
	// FinishedAt from fixture: 2026-06-01T15:00:00Z
	wantTime := time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC)
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("occurred_at = %v, want %v", ev.OccurredAt, wantTime)
	}
	// Actor: bob@example.eu should be redacted because it contains "@".
	if ev.Actor == nil {
		t.Error("expected non-nil actor for polled event")
	} else if *ev.Actor != "[redacted]" {
		t.Errorf("actor = %q, want [redacted] (PII redaction)", *ev.Actor)
	}
	// Resource: namespace/name
	if ev.Resource == nil {
		t.Error("expected non-nil resource")
	} else if *ev.Resource != "production/payment-service" {
		t.Errorf("resource = %q, want production/payment-service", *ev.Resource)
	}
	if ev.Payload == nil {
		t.Error("payload must not be nil")
	}
	// Verify the event passes schema validation.
	if err := ev.Validate(); err != nil {
		t.Errorf("Validate() error: %v", err)
	}
}
