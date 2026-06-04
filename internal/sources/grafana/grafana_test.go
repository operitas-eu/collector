package grafana_test

import (
	"bytes"
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
	"operitas.eu/collector/internal/sources/grafana"
)

// newTestRedactor constructs a redactor with hard-redact mode (no hashing).
func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

// loadFixture reads a JSON fixture from testdata/fixtures/<name>.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("loadFixture(%q): %v", name, err)
	}
	return data
}

// TestMapAlertStatus verifies that every alert status maps to "monitor.alert".
func TestMapAlertStatus(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"firing", "monitor.alert"},
		{"resolved", "monitor.alert"},
		{"FIRING", "monitor.alert"},
		{"RESOLVED", "monitor.alert"},
		{"no_data", "monitor.alert"},
		{"paused", "monitor.alert"},
		{"", "monitor.alert"},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			got := grafana.MapAlertStatus(tc.status)
			if got != tc.want {
				t.Errorf("MapAlertStatus(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

// TestVerifyBearer exercises the bearer auth helper.
func TestVerifyBearer(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		authHeader string
		want       bool
	}{
		{"valid bearer", "mysecret", "Bearer mysecret", true},
		{"wrong token", "mysecret", "Bearer wrongtoken", false},
		{"empty secret", "", "Bearer mysecret", false},
		{"no bearer prefix — bare token", "mysecret", "mysecret", false},
		{"no bearer prefix — Token keyword", "mysecret", "Token mysecret", false},
		{"empty header", "mysecret", "", false},
		{"bearer prefix only", "mysecret", "Bearer ", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := grafana.VerifyBearer(tc.secret, tc.authHeader)
			if got != tc.want {
				t.Errorf("VerifyBearer(secret=%q, header=%q) = %v, want %v",
					tc.secret, tc.authHeader, got, tc.want)
			}
		})
	}
}

// TestWebhookHandler_BearerAuth exercises the HTTP handler auth path.
func TestWebhookHandler_BearerAuth(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.GrafanaConfig{
		Enabled:       true,
		WebhookSecret: "correct-secret",
	}

	var emitted []envelope.Event
	src := grafana.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload := loadFixture(t, "alert_firing.json")

	t.Run("valid bearer", func(t *testing.T) {
		emitted = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer correct-secret")
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("expected 204, got %d (body: %s)", w.Code, w.Body.String())
		}
		if len(emitted) != 1 {
			t.Errorf("expected 1 event, got %d", len(emitted))
		}
	})

	t.Run("invalid bearer", func(t *testing.T) {
		emitted = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer wrong-secret")

		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
		if len(emitted) != 0 {
			t.Errorf("expected 0 events on auth failure, got %d", len(emitted))
		}
	})

	t.Run("missing bearer prefix", func(t *testing.T) {
		emitted = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(payload))
		// Token sent without the "Bearer " prefix — must be rejected.
		req.Header.Set("Authorization", "correct-secret")

		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for bare token, got %d", w.Code)
		}
		if len(emitted) != 0 {
			t.Errorf("expected 0 events on auth failure, got %d", len(emitted))
		}
	})

	t.Run("no authorization header", func(t *testing.T) {
		emitted = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(payload))

		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for missing header, got %d", w.Code)
		}
		if len(emitted) != 0 {
			t.Errorf("expected 0 events on auth failure, got %d", len(emitted))
		}
	})
}

// TestWebhookHandler_NoAuth verifies that auth is skipped when WebhookSecret
// is empty (trusted-network-only deployment).
func TestWebhookHandler_NoAuth(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.GrafanaConfig{
		Enabled:       true,
		WebhookSecret: "", // no secret configured
	}

	var emitted []envelope.Event
	src := grafana.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload := loadFixture(t, "alert_firing.json")

	req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Errorf("expected 1 event, got %d", len(emitted))
	}
	if emitted[0].EventSource != envelope.SourceGrafana {
		t.Errorf("event_source = %q, want %q", emitted[0].EventSource, envelope.SourceGrafana)
	}
}

// TestWebhookHandler_MethodNotAllowed verifies that non-POST methods are rejected.
func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.GrafanaConfig{Enabled: true}
	src := grafana.New(cfg, r, func(e envelope.Event) {})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/webhook/grafana", nil)
			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405 for %s, got %d", method, w.Code)
			}
		})
	}
}

// TestNormalization_FiringFixture verifies full normalization from the firing fixture.
func TestNormalization_FiringFixture(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.GrafanaConfig{Enabled: true}

	var emitted []envelope.Event
	src := grafana.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload := loadFixture(t, "alert_firing.json")
	req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body: %s)", w.Code, w.Body.String())
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	ev := emitted[0]

	if ev.EventType != "monitor.alert" {
		t.Errorf("event_type = %q, want monitor.alert", ev.EventType)
	}
	if ev.EventSource != envelope.SourceGrafana {
		t.Errorf("event_source = %q, want grafana", ev.EventSource)
	}
	if ev.Actor != nil {
		t.Errorf("actor should be nil for Grafana Alerting events, got %v", *ev.Actor)
	}

	wantOccurredAt := time.Date(2026, 5, 7, 8, 14, 2, 0, time.UTC)
	if !ev.OccurredAt.Equal(wantOccurredAt) {
		t.Errorf("occurred_at = %v, want %v", ev.OccurredAt, wantOccurredAt)
	}

	// Resource should be "Prod/HighErrorRate" (folder/alertname).
	if ev.Resource == nil {
		t.Fatal("resource is nil")
	}
	if *ev.Resource != "Prod/HighErrorRate" {
		t.Errorf("resource = %q, want %q", *ev.Resource, "Prod/HighErrorRate")
	}

	// Payload must exist and contain labels but NOT annotations.
	if ev.Payload == nil {
		t.Fatal("payload is nil")
	}
	if _, ok := ev.Payload["description"]; ok {
		t.Error("payload must not contain 'description' annotation (PII risk)")
	}
	if _, ok := ev.Payload["summary"]; ok {
		t.Error("payload must not contain 'summary' annotation")
	}
	if ev.Payload["status"] != "firing" {
		t.Errorf("payload status = %v, want firing", ev.Payload["status"])
	}
	if ev.Payload["fingerprint"] != "d1e2f3a4b5c67890" {
		t.Errorf("payload fingerprint = %v, want d1e2f3a4b5c67890", ev.Payload["fingerprint"])
	}
	if ev.Payload["alertname"] != "HighErrorRate" {
		t.Errorf("payload alertname = %v, want HighErrorRate", ev.Payload["alertname"])
	}
}

// TestNormalization_ResolvedFixture verifies normalization of a resolved alert,
// including that ended_at is present in the payload.
func TestNormalization_ResolvedFixture(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.GrafanaConfig{Enabled: true}

	var emitted []envelope.Event
	src := grafana.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload := loadFixture(t, "alert_resolved.json")
	req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	ev := emitted[0]

	if ev.EventType != "monitor.alert" {
		t.Errorf("event_type = %q, want monitor.alert", ev.EventType)
	}
	if ev.Payload["status"] != "resolved" {
		t.Errorf("payload status = %v, want resolved", ev.Payload["status"])
	}
	// ended_at must be set for resolved alerts with a non-zero endsAt.
	if _, ok := ev.Payload["ended_at"]; !ok {
		t.Error("payload missing ended_at for resolved alert")
	}
}

// TestNormalization_RedactsEmailInLabel verifies that an email address in a label
// value is redacted before it reaches the payload.
func TestNormalization_RedactsEmailInLabel(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.GrafanaConfig{Enabled: true}

	var emitted []envelope.Event
	src := grafana.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body, err := json.Marshal(map[string]any{
		"version": "1",
		"status":  "firing",
		"state":   "alerting",
		"alerts": []map[string]any{
			{
				"status": "firing",
				"labels": map[string]string{
					"alertname": "SlowQuery",
					"owner":     "user@example.com",
				},
				"annotations": map[string]string{},
				"startsAt":    "2026-05-07T08:14:02Z",
				"endsAt":      "0001-01-01T00:00:00Z",
				"fingerprint": "aabbccdd",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(body))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	owner, _ := emitted[0].Payload["owner"].(string)
	if owner == "user@example.com" {
		t.Error("raw email address must not appear in payload after redaction")
	}
	if owner != "[redacted]" {
		t.Errorf("owner = %q, want [redacted]", owner)
	}
}

// TestNormalization_MultipleAlerts verifies one event is emitted per alert.
func TestNormalization_MultipleAlerts(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.GrafanaConfig{Enabled: true}

	var emitted []envelope.Event
	src := grafana.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body, err := json.Marshal(map[string]any{
		"version": "1",
		"status":  "firing",
		"state":   "alerting",
		"alerts": []map[string]any{
			{
				"status":      "firing",
				"labels":      map[string]string{"alertname": "HighCPU"},
				"annotations": map[string]string{},
				"startsAt":    "2026-05-07T08:00:00Z",
				"endsAt":      "0001-01-01T00:00:00Z",
				"fingerprint": "aa11",
			},
			{
				"status":      "resolved",
				"labels":      map[string]string{"alertname": "HighMemory"},
				"annotations": map[string]string{},
				"startsAt":    "2026-05-07T07:00:00Z",
				"endsAt":      "2026-05-07T08:00:00Z",
				"fingerprint": "bb22",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(body))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 2 {
		t.Fatalf("expected 2 events, got %d", len(emitted))
	}
	for _, ev := range emitted {
		if ev.EventType != "monitor.alert" {
			t.Errorf("event_type = %q, want monitor.alert", ev.EventType)
		}
		if ev.EventSource != envelope.SourceGrafana {
			t.Errorf("event_source = %q, want grafana", ev.EventSource)
		}
		if ev.Actor != nil {
			t.Errorf("actor should be nil for Grafana Alerting events")
		}
	}
}

// TestNormalization_MissingAlertName falls back to fingerprint as resource.
func TestNormalization_MissingAlertName(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.GrafanaConfig{Enabled: true}

	var emitted []envelope.Event
	src := grafana.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body, err := json.Marshal(map[string]any{
		"version": "1",
		"status":  "firing",
		"state":   "alerting",
		"alerts": []map[string]any{
			{
				"status":      "firing",
				"labels":      map[string]string{"severity": "warning"},
				"annotations": map[string]string{},
				"startsAt":    "2026-05-07T08:00:00Z",
				"endsAt":      "0001-01-01T00:00:00Z",
				"fingerprint": "fallback123",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(body))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}
	if emitted[0].Resource == nil || *emitted[0].Resource != "fallback123" {
		resource := "<nil>"
		if emitted[0].Resource != nil {
			resource = *emitted[0].Resource
		}
		t.Errorf("resource = %q, want fallback123", resource)
	}
}

// TestNormalization_EnvelopeValidation checks that emitted events pass the
// envelope.Validate() contract check.
func TestNormalization_EnvelopeValidation(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.GrafanaConfig{Enabled: true}

	var emitted []envelope.Event
	src := grafana.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload := loadFixture(t, "alert_firing.json")
	req := httptest.NewRequest(http.MethodPost, "/webhook/grafana", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	for i, ev := range emitted {
		if err := ev.Validate(); err != nil {
			t.Errorf("emitted[%d].Validate() = %v", i, err)
		}
	}
}
