package datadog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/datadog"
)

func bytesReader(b []byte) io.Reader {
	return bytes.NewReader(b)
}

func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

func TestMapAlertType(t *testing.T) {
	tests := []struct {
		alertType string
		want      string
	}{
		{"error", "monitor.alert"},
		{"alert", "monitor.alert"},
		{"warning", "monitor.alert"},
		{"success", "monitor.alert"},
		{"info", "monitor.alert"},
		{"", "monitor.alert"},
		{"ALERT", "monitor.alert"},
	}

	for _, tc := range tests {
		t.Run(tc.alertType, func(t *testing.T) {
			got := datadog.MapAlertType(tc.alertType)
			if got != tc.want {
				t.Errorf("MapAlertType(%q) = %q, want %q", tc.alertType, got, tc.want)
			}
		})
	}
}

func TestVerifyAPIKeyHeader(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		headerValue string
		want        bool
	}{
		{"valid", "mykey", "mykey", true},
		{"wrong key", "mykey", "wrongkey", false},
		{"empty both", "", "", false},
		{"empty secret", "", "somekey", false},
		{"empty header", "mykey", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := datadog.VerifyAPIKeyHeader(tc.secret, tc.headerValue)
			if got != tc.want {
				t.Errorf("VerifyAPIKeyHeader(%q, %q) = %v, want %v",
					tc.secret, tc.headerValue, got, tc.want)
			}
		})
	}
}

func TestWebhookHandler_AuthRejection(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.DatadogConfig{
		Enabled:       true,
		WebhookSecret: "correct-secret",
		APIBaseURL:    "https://api.datadoghq.eu",
	}

	var emitted []envelope.Event
	src := datadog.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload, _ := json.Marshal(map[string]any{
		"alert_id":   42,
		"alert_type": "error",
	})

	// Wrong key — should be 401.
	req := httptest.NewRequest(http.MethodPost, "/webhook/datadog", nil)
	req.Body = http.NoBody
	req.Header.Set("DD-API-KEY", "wrong-secret")
	req.Header.Set("Content-Type", "application/json")
	_ = payload

	w := httptest.NewRecorder()
	// Access the handler via the exported test helper.
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if len(emitted) != 0 {
		t.Errorf("expected no events emitted on auth failure, got %d", len(emitted))
	}
}

func TestWebhookHandler_ValidPayload(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.DatadogConfig{
		Enabled:       true,
		WebhookSecret: "correct-secret",
		APIBaseURL:    "https://api.datadoghq.eu",
	}

	var emitted []envelope.Event
	src := datadog.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload, _ := json.Marshal(map[string]any{
		"id":               "evt-001",
		"alert_id":         int64(42),
		"alert_title":      "High error rate",
		"alert_type":       "error",
		"alert_transition": "Triggered",
		"priority":         "normal",
		"hostname":         "web-1",
		"tags":             "env:prod,team:platform",
		"last_updated":     "2026-05-07T08:14:02Z",
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/datadog",
		bytesReader(payload))
	req.Header.Set("DD-API-KEY", "correct-secret")
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
	if ev.EventSource != envelope.SourceDatadog {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceDatadog)
	}
	if ev.EventType != "monitor.alert" {
		t.Errorf("event_type = %q, want monitor.alert", ev.EventType)
	}
}

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.DatadogConfig{Enabled: true, WebhookSecret: "s"}
	src := datadog.New(cfg, r, func(e envelope.Event) {})

	req := httptest.NewRequest(http.MethodGet, "/webhook/datadog", nil)
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestPollRedirectNotFollowed verifies that the Datadog REST poller does NOT
// follow a 302 redirect and does NOT send credential headers (DD-API-KEY,
// DD-APPLICATION-KEY) to the redirect target. This exercises security-1:
// CheckRedirect = http.ErrUseLastResponse on the source's http.Client.
func TestPollRedirectNotFollowed(t *testing.T) {
	// redirectTarget counts hits and records any DD-API-KEY header it receives.
	var targetHits atomic.Int64
	var targetAPIKey atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		targetAPIKey.Store(r.Header.Get("DD-API-KEY"))
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// primary always returns 302 pointing at target.
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/events", http.StatusFound)
	}))
	defer primary.Close()

	r, err := redact.New(false, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DatadogConfig{
		Enabled:      true,
		APIBaseURL:   primary.URL,
		APIKey:       "secret-api-key",
		AppKey:       "secret-app-key",
		PollLookback: time.Hour,
		PollInterval: 5 * time.Minute,
	}
	var emitted []envelope.Event
	src := datadog.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	// PollForTest executes exactly one poll cycle against primary, which
	// returns 302. With CheckRedirect = http.ErrUseLastResponse the client
	// must stop at the 3xx and return an error to the poller (non-2xx status).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// poll() returns an error on non-2xx; we only care that no redirect hit target.
	_ = src.PollForTest(ctx)

	if got := targetHits.Load(); got != 0 {
		t.Errorf("redirect was followed: redirect target received %d request(s)", got)
	}
	if key, _ := targetAPIKey.Load().(string); key != "" {
		t.Errorf("DD-API-KEY credential reached redirect target: %q", key)
	}
	// No events should be emitted from a redirect response.
	if len(emitted) != 0 {
		t.Errorf("expected 0 events from a redirect response, got %d", len(emitted))
	}
}
