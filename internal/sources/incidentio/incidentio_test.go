package incidentio_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/incidentio"
)

func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

// signBody returns a "sha256=<hex>" HMAC-SHA256 signature over body using secret.
func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// --- Event-type mapping ---

func TestMapWebhookEventType(t *testing.T) {
	tests := []struct {
		name           string
		webhookEvent   string
		incidentStatus string
		wantType       string
		wantOK         bool
	}{
		{
			name:           "created maps to incident.opened",
			webhookEvent:   "public_incident.incident_created_v2",
			incidentStatus: "triage",
			wantType:       "incident.opened",
			wantOK:         true,
		},
		{
			name:           "updated with investigating status",
			webhookEvent:   "public_incident.incident_updated_v2",
			incidentStatus: "investigating",
			wantType:       "incident.opened",
			wantOK:         true,
		},
		{
			name:           "updated with identified status",
			webhookEvent:   "public_incident.incident_updated_v2",
			incidentStatus: "identified",
			wantType:       "incident.acknowledged",
			wantOK:         true,
		},
		{
			name:           "updated with monitoring status",
			webhookEvent:   "public_incident.incident_updated_v2",
			incidentStatus: "monitoring",
			wantType:       "incident.acknowledged",
			wantOK:         true,
		},
		{
			name:           "updated with resolved status",
			webhookEvent:   "public_incident.incident_updated_v2",
			incidentStatus: "resolved",
			wantType:       "incident.resolved",
			wantOK:         true,
		},
		{
			name:           "updated with closed status",
			webhookEvent:   "public_incident.incident_updated_v2",
			incidentStatus: "closed",
			wantType:       "incident.resolved",
			wantOK:         true,
		},
		{
			name:           "unknown event type returns false",
			webhookEvent:   "public_incident.action_created_v1",
			incidentStatus: "",
			wantType:       "",
			wantOK:         false,
		},
		{
			name:           "empty event type returns false",
			webhookEvent:   "",
			incidentStatus: "",
			wantType:       "",
			wantOK:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := incidentio.MapWebhookEventType(tc.webhookEvent, tc.incidentStatus)
			if ok != tc.wantOK {
				t.Errorf("MapWebhookEventType(%q, %q) ok=%v, want ok=%v",
					tc.webhookEvent, tc.incidentStatus, ok, tc.wantOK)
			}
			if ok && got != tc.wantType {
				t.Errorf("MapWebhookEventType(%q, %q) = %q, want %q",
					tc.webhookEvent, tc.incidentStatus, got, tc.wantType)
			}
		})
	}
}

func TestMapIncidentStatus(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"triage", "incident.opened"},
		{"investigating", "incident.opened"},
		{"TRIAGE", "incident.opened"},
		{"identified", "incident.acknowledged"},
		{"monitoring", "incident.acknowledged"},
		{"watching", "incident.acknowledged"},
		{"live", "incident.acknowledged"},
		{"resolved", "incident.resolved"},
		{"post-incident", "incident.resolved"},
		{"learning", "incident.resolved"},
		{"closed", "incident.resolved"},
		{"cancelled", "incident.resolved"},
		{"escalated", "incident.escalated"},
		{"unknown_status", "incident.acknowledged"},
		{"", "incident.acknowledged"},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			got := incidentio.MapIncidentStatus(tc.status)
			if got != tc.want {
				t.Errorf("MapIncidentStatus(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

// --- Signature verification ---

func TestVerifyWebhookSignature(t *testing.T) {
	secret := "my-webhook-secret"
	body := []byte(`{"event_type":"public_incident.incident_created_v2"}`)
	validSig := signBody(secret, body)

	tests := []struct {
		name   string
		secret string
		body   []byte
		sig    string
		want   bool
	}{
		{
			name:   "valid signature",
			secret: secret,
			body:   body,
			sig:    validSig,
			want:   true,
		},
		{
			name:   "wrong secret",
			secret: "different-secret",
			body:   body,
			sig:    validSig,
			want:   false,
		},
		{
			name:   "tampered body",
			secret: secret,
			body:   []byte(`{"event_type":"tampered"}`),
			sig:    validSig,
			want:   false,
		},
		{
			name:   "missing sha256= prefix",
			secret: secret,
			body:   body,
			sig:    validSig[len("sha256="):], // bare hex, no prefix
			want:   false,
		},
		{
			name:   "empty signature",
			secret: secret,
			body:   body,
			sig:    "",
			want:   false,
		},
		{
			name:   "wrong prefix scheme",
			secret: secret,
			body:   body,
			sig:    "v1=" + validSig[len("sha256="):],
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := incidentio.VerifyWebhookSignature(tc.secret, tc.body, tc.sig)
			if got != tc.want {
				t.Errorf("VerifyWebhookSignature(%q, body, %q) = %v, want %v",
					tc.secret, tc.sig, got, tc.want)
			}
		})
	}
}

// --- HTTP webhook handler ---

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.IncidentIOConfig{Enabled: true, WebhookSecret: "s"}
	src := incidentio.New(cfg, r, func(e envelope.Event) {})

	req := httptest.NewRequest(http.MethodGet, "/webhook/incidentio", nil)
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestWebhookHandler_AuthRejection(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.IncidentIOConfig{
		Enabled:       true,
		WebhookSecret: "correct-secret",
		APIBaseURL:    "https://api.incident.io",
	}

	var emitted []envelope.Event
	src := incidentio.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body, _ := json.Marshal(map[string]any{
		"event_type": "public_incident.incident_created_v2",
	})

	// Wrong signature.
	req := httptest.NewRequest(http.MethodPost, "/webhook/incidentio",
		bytes.NewReader(body))
	req.Header.Set("X-Signature-256", "sha256=deadbeef")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if len(emitted) != 0 {
		t.Errorf("expected no events emitted on auth failure, got %d", len(emitted))
	}
}

func TestWebhookHandler_SkipsUnknownEventType(t *testing.T) {
	r := newTestRedactor(t)
	secret := "test-secret"
	cfg := config.IncidentIOConfig{
		Enabled:       true,
		WebhookSecret: secret,
		APIBaseURL:    "https://api.incident.io",
	}

	var emitted []envelope.Event
	src := incidentio.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body, _ := json.Marshal(map[string]any{
		"event_type": "public_incident.action_created_v1",
		"incident":   map[string]any{"id": "01INC001", "status": "triage"},
	})
	sig := signBody(secret, body)

	req := httptest.NewRequest(http.MethodPost, "/webhook/incidentio",
		bytes.NewReader(body))
	req.Header.Set("X-Signature-256", sig)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 on silently-skipped event, got %d", w.Code)
	}
	if len(emitted) != 0 {
		t.Errorf("expected no events emitted for unsupported type, got %d", len(emitted))
	}
}

func TestWebhookHandler_ValidCreatedPayload(t *testing.T) {
	r := newTestRedactor(t)
	secret := "test-webhook-secret"
	cfg := config.IncidentIOConfig{
		Enabled:       true,
		WebhookSecret: secret,
		APIBaseURL:    "https://api.incident.io",
	}

	var emitted []envelope.Event
	src := incidentio.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	// Load the fixture file.
	body, err := os.ReadFile("testdata/incident_created.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sig := signBody(secret, body)

	req := httptest.NewRequest(http.MethodPost, "/webhook/incidentio",
		bytes.NewReader(body))
	req.Header.Set("X-Signature-256", sig)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: body=%s", w.Code, w.Body.String())
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	ev := emitted[0]
	if ev.EventSource != envelope.SourceIncidentIO {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceIncidentIO)
	}
	if ev.EventType != "incident.opened" {
		t.Errorf("event_type = %q, want incident.opened", ev.EventType)
	}
	if ev.Resource == nil || *ev.Resource != "INC-42" {
		r := "<nil>"
		if ev.Resource != nil {
			r = *ev.Resource
		}
		t.Errorf("resource = %q, want INC-42", r)
	}
	// Actor must be redacted since it contains an email address.
	if ev.Actor == nil {
		t.Error("actor is nil, want redacted actor")
	} else if *ev.Actor == "alice@example.com" {
		t.Error("actor contains raw email — redaction failed")
	}
	if ev.OccurredAt.IsZero() {
		t.Error("occurred_at is zero")
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at timezone = %v, want UTC", ev.OccurredAt.Location())
	}
	// Validate the event passes the envelope schema.
	if err := ev.Validate(); err != nil {
		t.Errorf("envelope.Event.Validate() failed: %v", err)
	}
}

func TestWebhookHandler_ValidUpdatedResolved(t *testing.T) {
	r := newTestRedactor(t)
	secret := "my-secret"
	cfg := config.IncidentIOConfig{
		Enabled:       true,
		WebhookSecret: secret,
		APIBaseURL:    "https://api.incident.io",
	}

	var emitted []envelope.Event
	src := incidentio.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	now := time.Now().UTC().Truncate(time.Second)
	payload := map[string]any{
		"event_type": "public_incident.incident_updated_v2",
		"event":      map[string]any{"id": "01EVT002"},
		"incident": map[string]any{
			"id":         "01INC002",
			"reference":  "INC-100",
			"name":       "Payment service outage",
			"status":     "resolved",
			"updated_at": now.Format(time.RFC3339),
		},
	}
	body, _ := json.Marshal(payload)
	sig := signBody(secret, body)

	req := httptest.NewRequest(http.MethodPost, "/webhook/incidentio",
		bytes.NewReader(body))
	req.Header.Set("X-Signature-256", sig)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}
	ev := emitted[0]
	if ev.EventType != "incident.resolved" {
		t.Errorf("event_type = %q, want incident.resolved", ev.EventType)
	}
	if ev.EventSource != envelope.SourceIncidentIO {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceIncidentIO)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("envelope.Event.Validate() failed: %v", err)
	}
}

// TestNormalization verifies the normalization path for the full fixture with
// all required fields populated.
func TestNormalization_FixtureFields(t *testing.T) {
	r := newTestRedactor(t)
	secret := "test-webhook-secret"
	cfg := config.IncidentIOConfig{
		Enabled:       true,
		WebhookSecret: secret,
		APIBaseURL:    "https://api.incident.io",
	}

	var emitted []envelope.Event
	src := incidentio.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body, err := os.ReadFile("testdata/incident_created.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sig := signBody(secret, body)

	req := httptest.NewRequest(http.MethodPost, "/webhook/incidentio",
		bytes.NewReader(body))
	req.Header.Set("X-Signature-256", sig)

	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}
	ev := emitted[0]

	// Check all envelope contract fields.
	checks := []struct {
		name string
		fn   func() bool
		msg  string
	}{
		{"event_source", func() bool { return ev.EventSource == envelope.SourceIncidentIO }, "event_source must be incident.io"},
		{"event_type", func() bool { return ev.EventType == "incident.opened" }, "event_type must be incident.opened for created_v2"},
		{"occurred_at not zero", func() bool { return !ev.OccurredAt.IsZero() }, "occurred_at is zero"},
		{"occurred_at UTC", func() bool { return ev.OccurredAt.Location() == time.UTC }, "occurred_at not UTC"},
		{"resource set", func() bool { return ev.Resource != nil && *ev.Resource != "" }, "resource is nil or empty"},
		{"payload set", func() bool { return ev.Payload != nil }, "payload is nil"},
		{"incident_id in payload", func() bool {
			_, ok := ev.Payload["incident_id"]
			return ok
		}, "incident_id missing from payload"},
		{"no raw email in actor", func() bool {
			if ev.Actor == nil {
				return false
			}
			return *ev.Actor != "alice@example.com"
		}, "actor contains raw email"},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if !c.fn() {
				t.Error(c.msg)
			}
		})
	}
}
