package spacelift_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	"operitas.eu/collector/internal/sources/spacelift"
)

// newTestRedactor creates a plain-redact (no hash) Redactor for test use.
func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

// signBody computes the "sha256=<hex>" HMAC-SHA256 signature Spacelift attaches
// to the X-Signature-256 header.
func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// makeSource constructs a Source with the provided config, accumulating emitted
// events into the returned slice pointer.
func makeSource(t *testing.T, cfg config.SpaceliftConfig) (*spacelift.Source, *[]envelope.Event) {
	t.Helper()
	r := newTestRedactor(t)
	var events []envelope.Event
	src := spacelift.New(cfg, r, func(e envelope.Event) { events = append(events, e) })
	return src, &events
}

// ----- Run-state -> event_type mapping -----

func TestMapRunState(t *testing.T) {
	tests := []struct {
		state   string
		outcome string
		want    string
	}{
		// In-flight states map to deploy.started.
		{"TRIGGERED", "", "deploy.started"},
		{"PREPARING", "", "deploy.started"},
		{"PLANNING", "", "deploy.started"},
		{"APPLYING", "", "deploy.started"},
		// Case-insensitive input.
		{"applying", "", "deploy.started"},
		{"triggered", "", "deploy.started"},
		// FINISHED with success (or no outcome) -> deploy.completed.
		{"FINISHED", "", "deploy.completed"},
		{"FINISHED", "success", "deploy.completed"},
		// FINISHED with explicit failure outcome -> deploy.failed.
		{"FINISHED", "failure", "deploy.failed"},
		{"FINISHED", "FAILURE", "deploy.failed"},
		// Terminal error states.
		{"FAILED", "", "deploy.failed"},
		{"STOPPED", "", "deploy.failed"},
		// Operator-cancelled states.
		{"DISCARDED", "", "deploy.failed"},
		{"CANCELED", "", "deploy.failed"},
		// Manual approval / IaC change applied.
		{"CONFIRMED", "", "change.iac_applied"},
		{"confirmed", "", "change.iac_applied"},
		// Unknown state falls back gracefully.
		{"QUEUED", "", "deploy.started"},
		{"", "", "deploy.started"},
	}

	for _, tc := range tests {
		name := tc.state
		if tc.outcome != "" {
			name += "/" + tc.outcome
		}
		t.Run(name, func(t *testing.T) {
			got := spacelift.MapRunState(tc.state, tc.outcome)
			if got != tc.want {
				t.Errorf("MapRunState(%q, %q) = %q, want %q",
					tc.state, tc.outcome, got, tc.want)
			}
		})
	}
}

// ----- Signature verification -----

func TestSignatureVerification(t *testing.T) {
	secret := "test-webhook-secret"
	cfg := config.SpaceliftConfig{
		Enabled:       true,
		WebhookSecret: secret,
	}
	src, events := makeSource(t, cfg)

	body := makePayloadJSON(t, "FINISHED", "", "run-001", "my-stack", "My Stack",
		"alice@example.com", 1715077200)

	t.Run("valid signature accepted", func(t *testing.T) {
		*events = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift", bytes.NewReader(body))
		req.Header.Set("X-Signature-256", signBody(secret, body))
		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
		}
		if len(*events) != 1 {
			t.Errorf("expected 1 event, got %d", len(*events))
		}
	})

	t.Run("wrong signature rejected with 401", func(t *testing.T) {
		*events = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift", bytes.NewReader(body))
		req.Header.Set("X-Signature-256", signBody("wrong-secret", body))
		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
		if len(*events) != 0 {
			t.Errorf("expected no events on auth failure, got %d", len(*events))
		}
	})

	t.Run("missing signature rejected with 401", func(t *testing.T) {
		*events = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift", bytes.NewReader(body))
		// No X-Signature-256 header set.
		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
		if len(*events) != 0 {
			t.Errorf("expected no events, got %d", len(*events))
		}
	})

	t.Run("malformed prefix rejected with 401", func(t *testing.T) {
		*events = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift", bytes.NewReader(body))
		// Signature without required "sha256=" prefix.
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-Signature-256", hex.EncodeToString(mac.Sum(nil)))
		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 (prefix missing), got %d", w.Code)
		}
	})
}

// TestNoSecretConfigured verifies that when no webhook secret is configured,
// signature verification is skipped entirely (allows deployment without secret
// in internal-only network segments, equivalent to auth_scheme=none).
func TestNoSecretConfigured(t *testing.T) {
	cfg := config.SpaceliftConfig{Enabled: true}
	src, events := makeSource(t, cfg)

	body := makePayloadJSON(t, "FINISHED", "success", "run-002", "stack-x", "Stack X",
		"bob", 1715077200)

	req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift", bytes.NewReader(body))
	// No signature header — should pass because secret is unconfigured.
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if len(*events) != 1 {
		t.Errorf("expected 1 event, got %d", len(*events))
	}
}

// ----- HTTP method gate -----

func TestMethodNotAllowed(t *testing.T) {
	cfg := config.SpaceliftConfig{Enabled: true}
	src, _ := makeSource(t, cfg)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/webhook/spacelift", nil)
		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", method, w.Code)
		}
	}
}

// ----- Normalization from fixture -----

func TestNormalizationFromFixture(t *testing.T) {
	fixtureBody, err := os.ReadFile(filepath.Join("testdata", "run_state_change.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	cfg := config.SpaceliftConfig{Enabled: true}
	src, events := makeSource(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift",
		bytes.NewReader(fixtureBody))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if len(*events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(*events))
	}

	ev := (*events)[0]

	// EventSource must be SourceSpacelift.
	if ev.EventSource != envelope.SourceSpacelift {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceSpacelift)
	}

	// Fixture state=FINISHED, outcome=success -> deploy.completed.
	if ev.EventType != "deploy.completed" {
		t.Errorf("event_type = %q, want deploy.completed", ev.EventType)
	}

	// OccurredAt must be in UTC and match the fixture timestamp 1715077200.
	wantTime := time.Unix(1715077200, 0).UTC()
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("occurred_at = %v, want %v", ev.OccurredAt, wantTime)
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at timezone = %v, want UTC", ev.OccurredAt.Location())
	}

	// Actor: fixture triggeredBy is "alice@example.com" — an email address.
	// redact.Apply replaces email addresses with "[redacted]".
	if ev.Actor == nil {
		t.Fatal("actor should not be nil")
	}
	if *ev.Actor != "[redacted]" {
		t.Errorf("actor = %q, want [redacted] (PII email should be redacted)", *ev.Actor)
	}

	// Resource must contain stack and run identifiers.
	if ev.Resource == nil {
		t.Fatal("resource should not be nil")
	}
	const wantResourcePrefix = "Platform Infrastructure/"
	if len(*ev.Resource) < len(wantResourcePrefix) ||
		(*ev.Resource)[:len(wantResourcePrefix)] != wantResourcePrefix {
		t.Errorf("resource = %q, want prefix %q", *ev.Resource, wantResourcePrefix)
	}

	// Payload must be present and be a map.
	if ev.Payload == nil {
		t.Fatal("payload must not be nil")
	}

	// Payload must contain stack_name and run_id but not commit message (PII risk).
	if _, ok := ev.Payload["stack_name"]; !ok {
		t.Error("payload missing stack_name")
	}
	if _, ok := ev.Payload["run_id"]; !ok {
		t.Error("payload missing run_id")
	}
	// commit_message must NOT be in the payload (may contain PII).
	if _, ok := ev.Payload["commit_message"]; ok {
		t.Error("payload must not include commit_message (PII risk)")
	}

	// Validate the event against the envelope schema.
	if err := ev.Validate(); err != nil {
		t.Errorf("envelope validation failed: %v", err)
	}
}

// ----- Normalization for each event type -----

func TestEventTypeNormalization(t *testing.T) {
	tests := []struct {
		name         string
		state        string
		outcome      string
		wantType     string
		wantActorNil bool
	}{
		{
			name:     "deploy.started for TRIGGERED",
			state:    "TRIGGERED",
			wantType: "deploy.started",
		},
		{
			name:     "deploy.started for APPLYING",
			state:    "APPLYING",
			wantType: "deploy.started",
		},
		{
			name:     "deploy.completed for FINISHED success",
			state:    "FINISHED",
			outcome:  "success",
			wantType: "deploy.completed",
		},
		{
			name:     "deploy.failed for FINISHED failure",
			state:    "FINISHED",
			outcome:  "failure",
			wantType: "deploy.failed",
		},
		{
			name:     "deploy.failed for FAILED",
			state:    "FAILED",
			wantType: "deploy.failed",
		},
		{
			name:     "deploy.failed for STOPPED",
			state:    "STOPPED",
			wantType: "deploy.failed",
		},
		{
			name:     "deploy.failed for DISCARDED",
			state:    "DISCARDED",
			wantType: "deploy.failed",
		},
		{
			name:     "change.iac_applied for CONFIRMED",
			state:    "CONFIRMED",
			wantType: "change.iac_applied",
		},
		{
			name:         "nil actor when triggeredBy is empty",
			state:        "FINISHED",
			wantType:     "deploy.completed",
			wantActorNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.SpaceliftConfig{Enabled: true}
			src, events := makeSource(t, cfg)

			actor := "operator"
			if tc.wantActorNil {
				actor = "" // empty triggered-by -> nil actor
			}

			body := makePayloadJSON(t, tc.state, tc.outcome, "run-xyz", "stack-abc",
				"Infra Stack", actor, 1715077200)

			req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift",
				bytes.NewReader(body))
			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)

			if w.Code != http.StatusNoContent {
				t.Errorf("expected 204, got %d", w.Code)
				return
			}
			if len(*events) != 1 {
				t.Fatalf("expected 1 event, got %d", len(*events))
			}
			ev := (*events)[0]
			if ev.EventType != tc.wantType {
				t.Errorf("event_type = %q, want %q", ev.EventType, tc.wantType)
			}
			if ev.EventSource != envelope.SourceSpacelift {
				t.Errorf("event_source = %q, want spacelift", ev.EventSource)
			}
			if tc.wantActorNil && ev.Actor != nil {
				t.Errorf("actor = %q, want nil", *ev.Actor)
			}
			if !tc.wantActorNil && actor != "" && ev.Actor == nil {
				t.Error("actor should not be nil")
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("envelope validation: %v", err)
			}
		})
	}
}

// ----- Actor fallback chain -----

func TestActorFallbackChain(t *testing.T) {
	tests := []struct {
		name        string
		triggeredBy string
		authorLogin string
		authorName  string
		wantNil     bool
		wantContain string // non-empty: actor must not be nil and must equal this value
	}{
		{
			name:        "triggeredBy takes precedence",
			triggeredBy: "operator",
			authorLogin: "alice",
			authorName:  "Alice Smith",
			wantContain: "operator",
		},
		{
			name:        "authorLogin used when triggeredBy absent",
			triggeredBy: "",
			authorLogin: "alice",
			authorName:  "Alice Smith",
			wantContain: "alice",
		},
		{
			name:        "authorName used when triggeredBy and authorLogin absent",
			triggeredBy: "",
			authorLogin: "",
			authorName:  "Alice Smith",
			wantContain: "Alice Smith",
		},
		{
			name:        "nil when all actor fields absent",
			triggeredBy: "",
			authorLogin: "",
			authorName:  "",
			wantNil:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.SpaceliftConfig{Enabled: true}
			r := newTestRedactor(t)
			var events []envelope.Event
			src := spacelift.New(cfg, r, func(e envelope.Event) { events = append(events, e) })

			body, _ := json.Marshal(map[string]any{
				"state":     "FINISHED",
				"outcome":   "success",
				"timestamp": 1715077200,
				"run": map[string]any{
					"id":          "run-001",
					"type":        "TRACKED",
					"triggeredBy": tc.triggeredBy,
					"commit": map[string]any{
						"authorName":  tc.authorName,
						"authorLogin": tc.authorLogin,
						"hash":        "deadbeef",
					},
				},
				"stack": map[string]any{
					"id":   "stack-1",
					"name": "Stack One",
				},
			})

			req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift",
				bytes.NewReader(body))
			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)

			if w.Code != http.StatusNoContent {
				t.Fatalf("expected 204, got %d", w.Code)
			}
			if len(events) != 1 {
				t.Fatalf("expected 1 event, got %d", len(events))
			}

			ev := events[0]
			if tc.wantNil {
				if ev.Actor != nil {
					t.Errorf("actor = %q, want nil", *ev.Actor)
				}
				return
			}
			if ev.Actor == nil {
				t.Fatal("actor should not be nil")
			}
			if *ev.Actor != tc.wantContain {
				t.Errorf("actor = %q, want %q", *ev.Actor, tc.wantContain)
			}
		})
	}
}

// ----- OccurredAt fallback to now when timestamp is zero -----

func TestOccurredAtFallsBackToNow(t *testing.T) {
	cfg := config.SpaceliftConfig{Enabled: true}
	src, events := makeSource(t, cfg)

	body, _ := json.Marshal(map[string]any{
		"state":     "FINISHED",
		"outcome":   "success",
		"timestamp": 0, // zero -> fall back to now
		"run": map[string]any{
			"id":   "run-001",
			"type": "TRACKED",
		},
		"stack": map[string]any{
			"id":   "stack-1",
			"name": "Stack One",
		},
	})

	before := time.Now().UTC().Add(-time.Second)
	req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	after := time.Now().UTC().Add(time.Second)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if len(*events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(*events))
	}

	ev := (*events)[0]
	if ev.OccurredAt.Before(before) || ev.OccurredAt.After(after) {
		t.Errorf("occurred_at %v not in expected range [%v, %v]",
			ev.OccurredAt, before, after)
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at timezone = %v, want UTC", ev.OccurredAt.Location())
	}
}

// ----- Malformed JSON returns 500 -----

func TestMalformedJSON(t *testing.T) {
	cfg := config.SpaceliftConfig{Enabled: true}
	src, events := makeSource(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift",
		bytes.NewReader([]byte("{not valid json")))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for malformed JSON, got %d", w.Code)
	}
	if len(*events) != 0 {
		t.Errorf("expected no events on parse error, got %d", len(*events))
	}
}

// ----- Resource identifier construction -----

func TestResourceIDWithAndWithoutStack(t *testing.T) {
	tests := []struct {
		name      string
		stackName string
		stackID   string
		runID     string
		want      string
	}{
		{"full", "Platform Infra", "plat-infra", "run-001", "Platform Infra/run-001"},
		{"no stack name falls back to id", "", "plat-infra", "run-001", "plat-infra/run-001"},
		{"no stack at all", "", "", "run-001", "run-001"},
		{"no run id", "My Stack", "my-stack", "", "My Stack"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.SpaceliftConfig{Enabled: true}
			src, events := makeSource(t, cfg)

			body, _ := json.Marshal(map[string]any{
				"state":     "FINISHED",
				"outcome":   "success",
				"timestamp": 1715077200,
				"run": map[string]any{
					"id":   tc.runID,
					"type": "TRACKED",
				},
				"stack": map[string]any{
					"id":   tc.stackID,
					"name": tc.stackName,
				},
			})

			req := httptest.NewRequest(http.MethodPost, "/webhook/spacelift",
				bytes.NewReader(body))
			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)

			if w.Code != http.StatusNoContent {
				t.Fatalf("expected 204, got %d", w.Code)
			}
			if len(*events) == 0 {
				t.Fatal("expected event to be emitted")
			}
			ev := (*events)[0]
			if tc.want == "" {
				// Resource should be nil when both are empty.
				if ev.Resource != nil {
					t.Errorf("resource = %q, want nil", *ev.Resource)
				}
				return
			}
			if ev.Resource == nil {
				t.Fatal("resource should not be nil")
			}
			if *ev.Resource != tc.want {
				t.Errorf("resource = %q, want %q", *ev.Resource, tc.want)
			}
		})
	}
}

// makePayloadJSON is a test helper that constructs a minimal valid Spacelift
// run state-change JSON payload from the given fields.
func makePayloadJSON(
	t *testing.T,
	state, outcome, runID, stackID, stackName, triggeredBy string,
	timestamp int64,
) []byte {
	t.Helper()
	m := map[string]any{
		"state":        state,
		"stateVersion": 1,
		"timestamp":    timestamp,
		"outcome":      outcome,
		"run": map[string]any{
			"id":          runID,
			"type":        "TRACKED",
			"triggeredBy": triggeredBy,
			"commit": map[string]any{
				"authorName":  "",
				"authorLogin": "",
				"hash":        "deadbeef",
			},
		},
		"stack": map[string]any{
			"id":   stackID,
			"name": stackName,
		},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("makePayloadJSON: marshal: %v", err)
	}
	return b
}
