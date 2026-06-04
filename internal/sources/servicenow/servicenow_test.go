package servicenow_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/servicenow"
)

// newTestRedactor constructs a plain (non-hashing) redactor for tests.
func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

// newTestSource constructs a Source with a minimal test config.
func newTestSource(t *testing.T, secret string, emitted *[]envelope.Event) *servicenow.Source {
	t.Helper()
	cfg := config.ServiceNowConfig{
		Enabled:       true,
		WebhookSecret: secret,
		BaseURL:       "https://example.service-now.com",
		BasicUser:     "collector",
		Tables:        []string{"change_request", "incident"},
		PollInterval:  60 * time.Second,
		PollLookback:  1 * time.Hour,
	}
	return servicenow.New(cfg, newTestRedactor(t), func(e envelope.Event) {
		*emitted = append(*emitted, e)
	})
}

// TestMapRecordEventType verifies the state -> event_type mapping for all
// documented ServiceNow OOTB state values.
func TestMapRecordEventType(t *testing.T) {
	tests := []struct {
		table string
		state string
		want  string
	}{
		// change_request: opened states
		{"change_request", "-5", "change.opened"},
		{"change_request", "1", "change.opened"},
		{"change_request", "2", "change.opened"},
		{"change_request", "3", "change.opened"},
		// change_request: merged (scheduled/implement)
		{"change_request", "4", "change.merged"},
		{"change_request", "0", "change.merged"},
		// change_request: closed/canceled
		{"change_request", "-1", "change.closed"},
		{"change_request", "7", "change.closed"},
		{"change_request", "-2", "change.closed"},
		// change_request: unknown state defaults to change.opened
		{"change_request", "99", "change.opened"},
		// incident: opened states
		{"incident", "1", "incident.opened"},
		{"incident", "2", "incident.opened"},
		{"incident", "3", "incident.opened"},
		// incident: resolved states
		{"incident", "6", "incident.resolved"},
		{"incident", "7", "incident.resolved"},
		// incident: unknown state defaults to incident.opened
		{"incident", "99", "incident.opened"},
		// unknown table defaults to change.opened
		{"problem", "1", "change.opened"},
	}

	for _, tc := range tests {
		name := tc.table + "/" + tc.state
		t.Run(name, func(t *testing.T) {
			got := servicenow.MapRecordEventType(tc.table, tc.state)
			if got != tc.want {
				t.Errorf("MapRecordEventType(%q, %q) = %q, want %q",
					tc.table, tc.state, got, tc.want)
			}
		})
	}
}

// TestVerifyWebhookSecret verifies constant-time plain-secret comparison.
func TestVerifyWebhookSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		header string
		want   bool
	}{
		{"valid", "supersecret", "supersecret", true},
		{"wrong secret", "supersecret", "wrongsecret", false},
		{"empty secret rejects", "supersecret", "", false},
		{"empty want rejects", "", "supersecret", false},
		{"both empty rejects", "", "", false},
		{"case sensitive", "Secret", "secret", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := servicenow.VerifyWebhookSecret(tc.secret, tc.header)
			if got != tc.want {
				t.Errorf("VerifyWebhookSecret(%q, %q) = %v, want %v",
					tc.secret, tc.header, got, tc.want)
			}
		})
	}
}

// TestWebhookHandler_MethodNotAllowed ensures non-POST requests are rejected.
func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	var emitted []envelope.Event
	src := newTestSource(t, "s", &emitted)

	req := httptest.NewRequest(http.MethodGet, "/webhook/servicenow", nil)
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestWebhookHandler_AuthRejection ensures an incorrect secret returns 401
// and emits no events.
func TestWebhookHandler_AuthRejection(t *testing.T) {
	var emitted []envelope.Event
	src := newTestSource(t, "correct-secret", &emitted)

	body, _ := json.Marshal(map[string]any{
		"table": "change_request",
		"record": map[string]any{
			"number":         "CHG0001",
			"sys_class_name": "change_request",
			"state":          "1",
			"sys_updated_on": "2026-05-20 14:00:00",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/servicenow",
		bytes.NewReader(body))
	req.Header.Set("X-ServiceNow-Webhook-Secret", "wrong-secret")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if len(emitted) != 0 {
		t.Errorf("expected no events on auth failure, got %d", len(emitted))
	}
}

// TestWebhookHandler_ValidChangeRequest verifies a complete change_request
// webhook produces a correctly normalized event.
func TestWebhookHandler_ValidChangeRequest(t *testing.T) {
	var emitted []envelope.Event
	src := newTestSource(t, "correct-secret", &emitted)

	body, _ := json.Marshal(map[string]any{
		"table": "change_request",
		"record": map[string]any{
			"sys_id":            "abc123",
			"number":            "CHG0030001",
			"sys_class_name":    "change_request",
			"state":             "2",
			"short_description": "Deploy new API version",
			"sys_updated_on":    "2026-05-20 14:32:00",
			"opened_by":         map[string]any{"display_value": "jane.doe@example.com", "link": ""},
			"assigned_to":       map[string]any{"display_value": "john.smith@example.com", "link": ""},
			"priority":          "2",
			"category":          "Software",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/servicenow",
		bytes.NewReader(body))
	req.Header.Set("X-ServiceNow-Webhook-Secret", "correct-secret")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}
	ev := emitted[0]
	if ev.EventSource != envelope.SourceServiceNow {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceServiceNow)
	}
	if ev.EventType != "change.opened" {
		t.Errorf("event_type = %q, want change.opened", ev.EventType)
	}
	if ev.Resource == nil || *ev.Resource != "change_request/CHG0030001" {
		t.Errorf("resource = %v, want change_request/CHG0030001", ev.Resource)
	}
	// Actor must be redacted — email addresses are replaced with [redacted].
	if ev.Actor == nil {
		t.Error("actor should not be nil for record with opened_by")
	}
	if ev.Actor != nil && *ev.Actor != "[redacted]" {
		t.Errorf("actor = %q, want [redacted] (email should be redacted)", *ev.Actor)
	}
	if ev.OccurredAt.IsZero() {
		t.Error("occurred_at should not be zero")
	}
	wantTime := time.Date(2026, 5, 20, 14, 32, 0, 0, time.UTC)
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("occurred_at = %v, want %v", ev.OccurredAt, wantTime)
	}
}

// TestWebhookHandler_ValidIncident verifies a complete incident webhook
// produces a correctly normalized event.
func TestWebhookHandler_ValidIncident(t *testing.T) {
	var emitted []envelope.Event
	src := newTestSource(t, "correct-secret", &emitted)

	body, _ := json.Marshal(map[string]any{
		"table": "incident",
		"record": map[string]any{
			"sys_id":            "inc987",
			"number":            "INC0010042",
			"sys_class_name":    "incident",
			"state":             "1",
			"short_description": "Production API returning 500 errors",
			"sys_updated_on":    "2026-05-20 09:15:00",
			"opened_by":         map[string]any{"display_value": "alice.martin@example.com", "link": ""},
			"assigned_to":       map[string]any{"display_value": "bob.jones@example.com", "link": ""},
			"priority":          "1",
			"category":          "Software",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/servicenow",
		bytes.NewReader(body))
	req.Header.Set("X-ServiceNow-Webhook-Secret", "correct-secret")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}
	ev := emitted[0]
	if ev.EventSource != envelope.SourceServiceNow {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceServiceNow)
	}
	if ev.EventType != "incident.opened" {
		t.Errorf("event_type = %q, want incident.opened", ev.EventType)
	}
	if ev.Resource == nil || *ev.Resource != "incident/INC0010042" {
		t.Errorf("resource = %v, want incident/INC0010042", ev.Resource)
	}
	wantTime := time.Date(2026, 5, 20, 9, 15, 0, 0, time.UTC)
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("occurred_at = %v, want %v", ev.OccurredAt, wantTime)
	}
}

// TestNormalizationFromFixture loads the canonical testdata fixtures and
// verifies the normalizeRecord path for both change_request and incident.
func TestNormalizationFromFixture(t *testing.T) {
	tests := []struct {
		name          string
		fixturePath   string
		table         string
		wantEventType string
		wantResource  string
		wantTimeUTC   time.Time
	}{
		{
			name:          "change_request fixture",
			fixturePath:   filepath.Join("testdata", "change_request.json"),
			table:         "change_request",
			wantEventType: "change.opened",
			wantResource:  "change_request/CHG0030001",
			wantTimeUTC:   time.Date(2026, 5, 20, 14, 32, 0, 0, time.UTC),
		},
		{
			name:          "incident fixture",
			fixturePath:   filepath.Join("testdata", "incident.json"),
			table:         "incident",
			wantEventType: "incident.opened",
			wantResource:  "incident/INC0010042",
			wantTimeUTC:   time.Date(2026, 5, 20, 9, 15, 0, 0, time.UTC),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(tc.fixturePath)
			if err != nil {
				t.Fatalf("read fixture %s: %v", tc.fixturePath, err)
			}

			// Wrap fixture record in a webhook envelope.
			var record map[string]any
			if err := json.Unmarshal(raw, &record); err != nil {
				t.Fatalf("unmarshal fixture: %v", err)
			}
			payload, err := json.Marshal(map[string]any{
				"table":  tc.table,
				"record": record,
			})
			if err != nil {
				t.Fatalf("marshal wrapped payload: %v", err)
			}

			var emitted []envelope.Event
			src := newTestSource(t, "test-secret", &emitted)

			req := httptest.NewRequest(http.MethodPost, "/webhook/servicenow",
				bytes.NewReader(payload))
			req.Header.Set("X-ServiceNow-Webhook-Secret", "test-secret")
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)

			if w.Code != http.StatusNoContent {
				t.Errorf("expected 204, got %d (body: %s)", w.Code,
					readBody(t, w.Result()))
			}
			if len(emitted) != 1 {
				t.Fatalf("expected 1 event, got %d", len(emitted))
			}
			ev := emitted[0]

			if ev.EventSource != envelope.SourceServiceNow {
				t.Errorf("event_source = %q, want servicenow", ev.EventSource)
			}
			if ev.EventType != tc.wantEventType {
				t.Errorf("event_type = %q, want %q", ev.EventType, tc.wantEventType)
			}
			if ev.Resource == nil || *ev.Resource != tc.wantResource {
				t.Errorf("resource = %v, want %q", ev.Resource, tc.wantResource)
			}
			if !ev.OccurredAt.Equal(tc.wantTimeUTC) {
				t.Errorf("occurred_at = %v, want %v", ev.OccurredAt, tc.wantTimeUTC)
			}
			if ev.Payload == nil {
				t.Error("payload must not be nil")
			}
			// Actor must be present and redacted (fixture has email addresses).
			if ev.Actor == nil {
				t.Error("actor should not be nil — fixture has opened_by")
			}
			if ev.Actor != nil && *ev.Actor != "[redacted]" {
				t.Errorf("actor = %q, want [redacted] (email must be redacted)", *ev.Actor)
			}
		})
	}
}

// readBody drains the response body as a string for error messages.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "<read error>"
	}
	return string(b)
}
