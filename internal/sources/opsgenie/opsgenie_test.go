package opsgenie_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/opsgenie"
)

// newTestRedactor returns a Redactor with the default hard-redact posture
// (hash_pii=false). The zero-value hashKeyHex is valid for this mode.
func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

// --- MapAction table tests ----------------------------------------------------

func TestMapAction(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{"Create", "incident.opened"},
		{"Acknowledge", "incident.acknowledged"},
		{"Close", "incident.resolved"},
		{"Escalate", "incident.escalated"},
		{"Assign", "incident.acknowledged"},
		{"AddNote", "incident.acknowledged"},
		{"UnAcknowledge", "incident.opened"},
		{"Snooze", "incident.acknowledged"},
		// Unknown actions fall back to monitor.alert so events are not silently dropped.
		{"Delete", "monitor.alert"},
		{"", "monitor.alert"},
		{"custom_action", "monitor.alert"},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := opsgenie.MapAction(tc.action)
			if got != tc.want {
				t.Errorf("MapAction(%q) = %q, want %q", tc.action, got, tc.want)
			}
		})
	}
}

// --- Webhook secret verification tests ---------------------------------------

func TestWebhookHandler_SecretVerification(t *testing.T) {
	tests := []struct {
		name           string
		configSecret   string
		headerValue    string
		wantStatusCode int
		wantEmitCount  int
	}{
		{
			name:           "valid secret emits event",
			configSecret:   "supersecret",
			headerValue:    "supersecret",
			wantStatusCode: http.StatusNoContent,
			wantEmitCount:  1,
		},
		{
			name:           "wrong secret returns 401",
			configSecret:   "supersecret",
			headerValue:    "wrongsecret",
			wantStatusCode: http.StatusUnauthorized,
			wantEmitCount:  0,
		},
		{
			name:           "empty header returns 401 when secret is configured",
			configSecret:   "supersecret",
			headerValue:    "",
			wantStatusCode: http.StatusUnauthorized,
			wantEmitCount:  0,
		},
		{
			// When no secret is configured, any request is accepted.
			name:           "no secret configured accepts any request",
			configSecret:   "",
			headerValue:    "",
			wantStatusCode: http.StatusNoContent,
			wantEmitCount:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRedactor(t)
			cfg := config.OpsgenieConfig{
				Enabled:       true,
				WebhookSecret: tc.configSecret,
				APIBaseURL:    "https://api.eu.opsgenie.com/v2",
			}

			var emitted []envelope.Event
			src := opsgenie.New(cfg, r, func(e envelope.Event) {
				emitted = append(emitted, e)
			})

			payload := makeWebhookPayload("Create", "alert-001", "cpu-high", "42")
			body, _ := json.Marshal(payload)

			req := httptest.NewRequest(http.MethodPost, "/webhook/opsgenie",
				bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tc.headerValue != "" {
				req.Header.Set("X-OG-Webhook-Secret", tc.headerValue)
			}

			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)

			if w.Code != tc.wantStatusCode {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatusCode)
			}
			if len(emitted) != tc.wantEmitCount {
				t.Errorf("emit count = %d, want %d", len(emitted), tc.wantEmitCount)
			}
		})
	}
}

// --- Method enforcement -------------------------------------------------------

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.OpsgenieConfig{Enabled: true, WebhookSecret: "s"}
	src := opsgenie.New(cfg, r, func(e envelope.Event) {})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/webhook/opsgenie", nil)
			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: expected 405, got %d", method, w.Code)
			}
		})
	}
}

// --- Action -> event_type + normalization tests -------------------------------

func TestWebhookPayloadNormalization(t *testing.T) {
	tests := []struct {
		name          string
		action        string
		alertID       string
		alias         string
		tinyID        string
		owner         string
		sourceName    string
		wantEventType string
		wantResource  string // expected *Resource value (empty = expect nil)
		wantActorNil  bool
	}{
		{
			name:          "Create maps to incident.opened with alias as resource",
			action:        "Create",
			alertID:       "og-001",
			alias:         "cpu-high-web",
			tinyID:        "1",
			owner:         "ops-team",
			wantEventType: "incident.opened",
			wantResource:  "cpu-high-web",
		},
		{
			name:          "Acknowledge maps to incident.acknowledged",
			action:        "Acknowledge",
			alertID:       "og-002",
			alias:         "disk-full",
			tinyID:        "2",
			owner:         "sre-alice",
			wantEventType: "incident.acknowledged",
			wantResource:  "disk-full",
		},
		{
			name:          "Close maps to incident.resolved",
			action:        "Close",
			alertID:       "og-003",
			alias:         "db-latency",
			tinyID:        "3",
			owner:         "sre-bob",
			wantEventType: "incident.resolved",
			wantResource:  "db-latency",
		},
		{
			name:          "Escalate maps to incident.escalated",
			action:        "Escalate",
			alertID:       "og-004",
			alias:         "p1-incident",
			tinyID:        "4",
			owner:         "on-call",
			wantEventType: "incident.escalated",
			wantResource:  "p1-incident",
		},
		{
			name:          "Assign maps to incident.acknowledged",
			action:        "Assign",
			alertID:       "og-005",
			alias:         "mem-pressure",
			tinyID:        "5",
			wantEventType: "incident.acknowledged",
			wantResource:  "mem-pressure",
		},
		{
			name:          "falls back to tinyId when alias is empty",
			action:        "Create",
			alertID:       "og-006",
			alias:         "",
			tinyID:        "6",
			owner:         "ops",
			wantEventType: "incident.opened",
			wantResource:  "6",
		},
		{
			name:          "falls back to alertId when alias and tinyId are both empty",
			action:        "Create",
			alertID:       "og-007-uuid",
			alias:         "",
			tinyID:        "",
			owner:         "ops",
			wantEventType: "incident.opened",
			wantResource:  "og-007-uuid",
		},
		{
			name:          "actor falls back to source.name when owner is empty",
			action:        "Create",
			alertID:       "og-008",
			alias:         "net-flap",
			tinyID:        "8",
			owner:         "",
			sourceName:    "prometheus-integration",
			wantEventType: "incident.opened",
			wantResource:  "net-flap",
		},
		{
			name:          "no actor when both owner and source name are empty",
			action:        "Create",
			alertID:       "og-009",
			alias:         "timeout",
			tinyID:        "9",
			owner:         "",
			sourceName:    "",
			wantEventType: "incident.opened",
			wantResource:  "timeout",
			wantActorNil:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRedactor(t)
			cfg := config.OpsgenieConfig{
				Enabled:    true,
				APIBaseURL: "https://api.eu.opsgenie.com/v2",
			}

			var emitted []envelope.Event
			src := opsgenie.New(cfg, r, func(e envelope.Event) {
				emitted = append(emitted, e)
			})

			payload := makeWebhookPayloadFull(tc.action, tc.alertID, tc.alias,
				tc.tinyID, tc.owner, tc.sourceName)
			body, _ := json.Marshal(payload)

			req := httptest.NewRequest(http.MethodPost, "/webhook/opsgenie",
				bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)

			if w.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", w.Code)
			}
			if len(emitted) != 1 {
				t.Fatalf("expected 1 event, got %d", len(emitted))
			}

			ev := emitted[0]

			if ev.EventType != tc.wantEventType {
				t.Errorf("event_type = %q, want %q", ev.EventType, tc.wantEventType)
			}
			if ev.EventSource != envelope.SourceOpsgenie {
				t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceOpsgenie)
			}
			if ev.OccurredAt.IsZero() {
				t.Error("occurred_at is zero")
			}
			if ev.OccurredAt.Location() != time.UTC {
				t.Errorf("occurred_at not UTC: %v", ev.OccurredAt.Location())
			}

			if tc.wantResource != "" {
				if ev.Resource == nil {
					t.Errorf("resource is nil, want %q", tc.wantResource)
				} else if *ev.Resource != tc.wantResource {
					t.Errorf("resource = %q, want %q", *ev.Resource, tc.wantResource)
				}
			}

			if tc.wantActorNil && ev.Actor != nil {
				t.Errorf("actor = %q, want nil", *ev.Actor)
			}
			if !tc.wantActorNil && ev.Actor == nil && (tc.owner != "" || tc.sourceName != "") {
				t.Error("actor is nil, expected a value")
			}

			if ev.Payload == nil {
				t.Error("payload is nil")
			}
			// Verify required payload keys are present.
			for _, key := range []string{"alert_id", "action", "priority", "status"} {
				if _, ok := ev.Payload[key]; !ok {
					t.Errorf("payload missing key %q", key)
				}
			}

			// The event must pass the envelope contract validator.
			if err := ev.Validate(); err != nil {
				t.Errorf("Validate() error: %v", err)
			}
		})
	}
}

// --- PII redaction test -------------------------------------------------------

// TestWebhookHandler_PII_Redaction verifies that an email address in the owner
// field is stripped (replaced with "[redacted]") before the event is emitted.
func TestWebhookHandler_PII_Redaction(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.OpsgenieConfig{
		Enabled:    true,
		APIBaseURL: "https://api.eu.opsgenie.com/v2",
	}

	var emitted []envelope.Event
	src := opsgenie.New(cfg, r, func(e envelope.Event) {
		emitted = append(emitted, e)
	})

	rawEmail := "alice@example.eu"
	payload := makeWebhookPayloadFull("Acknowledge", "og-pii", "pii-alert", "99",
		rawEmail, "")
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/webhook/opsgenie",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	ev := emitted[0]
	if ev.Actor != nil && strings.Contains(*ev.Actor, rawEmail) {
		t.Errorf("actor contains raw PII email %q: %q", rawEmail, *ev.Actor)
	}
}

// --- Fixture-based normalization test ----------------------------------------

// TestWebhookFixture_AlertCreate loads the testdata fixture and validates that
// the normalized event passes the envelope contract.
func TestWebhookFixture_AlertCreate(t *testing.T) {
	fixturePath := filepath.Join("testdata", "fixtures", "alert_create.json")
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	r := newTestRedactor(t)
	cfg := config.OpsgenieConfig{
		Enabled:    true,
		APIBaseURL: "https://api.eu.opsgenie.com/v2",
	}

	var emitted []envelope.Event
	src := opsgenie.New(cfg, r, func(e envelope.Event) {
		emitted = append(emitted, e)
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/opsgenie",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	ev := emitted[0]

	if ev.EventSource != envelope.SourceOpsgenie {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceOpsgenie)
	}
	if ev.EventType != "incident.opened" {
		t.Errorf("event_type = %q, want incident.opened", ev.EventType)
	}
	if ev.OccurredAt.IsZero() {
		t.Error("occurred_at is zero")
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at not UTC: %v", ev.OccurredAt.Location())
	}
	if ev.Resource == nil || *ev.Resource != "cpu-alert-web-eu-1" {
		t.Errorf("resource = %v, want \"cpu-alert-web-eu-1\"", ev.Resource)
	}
	if ev.Payload == nil {
		t.Error("payload is nil")
	}

	// Full envelope contract validation.
	batch := envelope.NewBatch(
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222",
		emitted,
	)
	if err := envelope.ValidateBatch(batch); err != nil {
		t.Errorf("ValidateBatch failed: %v", err)
	}
}

// --- helpers ------------------------------------------------------------------

// makeWebhookPayload constructs a minimal Opsgenie webhook payload map.
func makeWebhookPayload(action, alertID, alias, tinyID string) map[string]any {
	return makeWebhookPayloadFull(action, alertID, alias, tinyID, "ops-team", "monitor-bot")
}

// makeWebhookPayloadFull constructs a complete Opsgenie webhook payload map.
func makeWebhookPayloadFull(action, alertID, alias, tinyID, owner, sourceName string) map[string]any {
	now := time.Now().UnixMilli()
	return map[string]any{
		"action": action,
		"alert": map[string]any{
			"alertId":   alertID,
			"message":   "Test alert: " + alertID,
			"alias":     alias,
			"tinyId":    tinyID,
			"priority":  "P3",
			"status":    "open",
			"owner":     owner,
			"tags":      []string{"env:test"},
			"source":    "test-integration",
			"createdAt": now,
			"updatedAt": now,
		},
		"source": map[string]any{
			"name": sourceName,
			"type": "integration",
		},
	}
}
