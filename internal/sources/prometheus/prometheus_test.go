package prometheus_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/prometheus"
)

func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

func TestMapAlertStatus(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"firing", "monitor.alert"},
		{"resolved", "monitor.alert"},
		{"FIRING", "monitor.alert"},
		{"", "monitor.alert"},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			got := prometheus.MapAlertStatus(tc.status)
			if got != tc.want {
				t.Errorf("MapAlertStatus(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestVerifyBearer(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		authHeader string
		want       bool
	}{
		{"valid", "mysecret", "Bearer mysecret", true},
		{"wrong", "mysecret", "Bearer wrong", false},
		{"empty secret", "", "Bearer mysecret", false},
		{"no bearer prefix", "mysecret", "mysecret", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := prometheus.VerifyBearer(tc.secret, tc.authHeader)
			if got != tc.want {
				t.Errorf("VerifyBearer(%q, %q) = %v, want %v",
					tc.secret, tc.authHeader, got, tc.want)
			}
		})
	}
}

func TestVerifyBasic(t *testing.T) {
	encode := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}

	tests := []struct {
		name       string
		user       string
		pass       string
		authHeader string
		want       bool
	}{
		{"valid", "alice", "secret", encode("alice", "secret"), true},
		{"wrong pass", "alice", "secret", encode("alice", "wrongpass"), false},
		{"wrong user", "alice", "secret", encode("bob", "secret"), false},
		{"no basic prefix", "alice", "secret", "alice:secret", false},
		{"invalid base64", "alice", "secret", "Basic !!!", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := prometheus.VerifyBasic(tc.user, tc.pass, tc.authHeader)
			if got != tc.want {
				t.Errorf("VerifyBasic(%q, %q, %q) = %v, want %v",
					tc.user, tc.pass, tc.authHeader, got, tc.want)
			}
		})
	}
}

func TestWebhookHandler_BearerAuth(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.PrometheusConfig{
		Enabled:       true,
		WebhookSecret: "correct-secret",
		AuthScheme:    "bearer",
	}

	var emitted []envelope.Event
	src := prometheus.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload := makeAlertmanagerPayload(t)

	t.Run("valid bearer", func(t *testing.T) {
		emitted = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/prometheus",
			bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer correct-secret")
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("expected 204, got %d", w.Code)
		}
		if len(emitted) != 1 {
			t.Errorf("expected 1 event, got %d", len(emitted))
		}
	})

	t.Run("invalid bearer", func(t *testing.T) {
		emitted = nil
		req := httptest.NewRequest(http.MethodPost, "/webhook/prometheus",
			bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer wrong-secret")

		w := httptest.NewRecorder()
		src.HandleWebhookForTest(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
		if len(emitted) != 0 {
			t.Errorf("expected no events on auth failure, got %d", len(emitted))
		}
	})
}

func TestWebhookHandler_NoAuth(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.PrometheusConfig{
		Enabled:    true,
		AuthScheme: "none",
	}

	var emitted []envelope.Event
	src := prometheus.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload := makeAlertmanagerPayload(t)

	req := httptest.NewRequest(http.MethodPost, "/webhook/prometheus",
		bytes.NewReader(payload))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Errorf("expected 1 event, got %d", len(emitted))
	}
	if emitted[0].EventSource != envelope.SourcePrometheus {
		t.Errorf("event_source = %q, want prometheus", emitted[0].EventSource)
	}
}

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.PrometheusConfig{Enabled: true, AuthScheme: "none"}
	src := prometheus.New(cfg, r, func(e envelope.Event) {})

	req := httptest.NewRequest(http.MethodGet, "/webhook/prometheus", nil)
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestNormalization_MultipleAlerts(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.PrometheusConfig{
		Enabled:    true,
		AuthScheme: "none",
	}

	var emitted []envelope.Event
	src := prometheus.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	type alert struct {
		Status   string            `json:"status"`
		Labels   map[string]string `json:"labels"`
		StartsAt time.Time         `json:"startsAt"`
	}
	payload, _ := json.Marshal(map[string]any{
		"version":  "4",
		"status":   "firing",
		"receiver": "webhook",
		"alerts": []alert{
			{
				Status:   "firing",
				Labels:   map[string]string{"alertname": "HighCPU", "severity": "warning"},
				StartsAt: time.Date(2026, 5, 7, 8, 0, 0, 0, time.UTC),
			},
			{
				Status:   "resolved",
				Labels:   map[string]string{"alertname": "HighMemory", "severity": "critical"},
				StartsAt: time.Date(2026, 5, 7, 9, 0, 0, 0, time.UTC),
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/prometheus",
		bytes.NewReader(payload))
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
		if ev.EventSource != envelope.SourcePrometheus {
			t.Errorf("event_source = %q, want prometheus", ev.EventSource)
		}
		if ev.Actor != nil {
			t.Errorf("actor should be nil for alertmanager events, got %v", ev.Actor)
		}
	}
}

// makeAlertmanagerPayload builds a minimal valid Alertmanager webhook payload.
func makeAlertmanagerPayload(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"version":  "4",
		"status":   "firing",
		"receiver": "webhook",
		"groupLabels": map[string]string{
			"alertname": "HighErrorRate",
		},
		"commonLabels": map[string]string{
			"alertname": "HighErrorRate",
			"severity":  "critical",
		},
		"alerts": []map[string]any{
			{
				"status": "firing",
				"labels": map[string]string{
					"alertname": "HighErrorRate",
					"severity":  "critical",
					"job":       "api",
				},
				"startsAt":    "2026-05-07T08:14:02Z",
				"endsAt":      "0001-01-01T00:00:00Z",
				"fingerprint": "abc123",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}
