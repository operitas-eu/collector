// Package grafana receives Grafana Alerting webhook notifications and normalizes
// them into canonical envelope events.
//
// The collector is a purely passive webhook receiver — it makes no outbound API
// calls to Grafana. Grafana Alerting is configured with a contact point of type
// "webhook" that POSTs to the collector endpoint when alert rules change state.
//
// Authentication: the Authorization header must carry "Bearer <WebhookSecret>".
// The "Bearer " prefix is checked first; the token is then compared in constant
// time via sigverify.SecretEqual. Auth is skipped only when WebhookSecret is
// empty (not recommended outside of fully private network segments).
//
// Reference: https://grafana.com/docs/grafana/latest/alerting/configure-notifications/webhook-notifier/
//
// Payload shape (Grafana v9+ unified alerting):
//
//	{
//	  "version":  "1",
//	  "groupKey": "{}:{alertname=\"HighErrorRate\"}",
//	  "status":   "firing",     // or "resolved"
//	  "orgId":    1,
//	  "title":    "[FIRING:1] HighErrorRate ...",
//	  "state":    "alerting",   // "alerting", "ok", "no_data", "paused"
//	  "message":  "...",        // may contain PII — never placed in payload
//	  "alerts": [
//	    {
//	      "status":       "firing",   // or "resolved"
//	      "labels":       {"alertname":"HighErrorRate","grafana_folder":"Prod"},
//	      "annotations":  {"description":"...","summary":"..."},
//	      "startsAt":     "2026-05-07T08:14:02Z",
//	      "endsAt":       "0001-01-01T00:00:00Z",
//	      "dashboardURL": "https://grafana.example.com/...",
//	      "panelURL":     "https://grafana.example.com/...",
//	      "generatorURL": "https://grafana.example.com/...",
//	      "fingerprint":  "abc123",
//	      "silenceURL":   "https://grafana.example.com/...",
//	      "imageURL":     ""
//	    }
//	  ]
//	}
//
// Each alert in the alerts array becomes one envelope.Event. Annotations are
// dropped entirely — they frequently contain free-text that may include PII.
// Labels pass through redact.Apply before payload construction.
//
// All alert events map to event_type "monitor.alert" regardless of
// firing/resolved status, mirroring the Prometheus source convention.
//
// EU compliance: no outbound HTTP calls are made by this source. The webhook
// receiver is inbound-only; customer traffic flows in, nothing flows out.
//
// PII handling: all payload labels pass through redact.Apply. The message and
// annotations fields are excluded entirely. Actor is always nil because Grafana
// Alerting webhook payloads do not carry a user principal.
package grafana

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/ptrs"
	"operitas.eu/collector/internal/redact"
	internalrt "operitas.eu/collector/internal/runtime"
	"operitas.eu/collector/internal/sigverify"
)

// Source receives Grafana Alerting webhook notifications.
type Source struct {
	cfg    config.GrafanaConfig
	redact *redact.Redactor
	emit   func(envelope.Event)
}

// New constructs a Grafana source. The constructor makes no network calls and
// starts no goroutines — per CONTRACT.md §2.
func New(cfg config.GrafanaConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
	return &Source{cfg: cfg, redact: r, emit: emit}
}

// Register adds the Grafana webhook handler to the shared router at /webhook/grafana.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/grafana", s.handleWebhook)
}

// Run is a no-op for the Grafana source — it is webhook-only. The method
// exists to satisfy the common source interface used in main.go for consistency.
func (s *Source) Run(_ context.Context) error {
	// Webhook-only source: nothing to start here. The handler was registered
	// on the shared router before this point.
	return nil
}

// handleWebhook is the HTTP handler for POST /webhook/grafana.
func (s *Source) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 5*1024*1024))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	if s.cfg.WebhookSecret != "" {
		if !verifyBearer(s.cfg.WebhookSecret, r.Header.Get("Authorization")) {
			slog.Warn("grafana webhook: authentication failed")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processPayload(body); err != nil {
		slog.Error("grafana webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// grafanaWebhookPayload is the on-wire shape of a Grafana Alerting webhook POST.
// Reference: https://grafana.com/docs/grafana/latest/alerting/configure-notifications/webhook-notifier/
type grafanaWebhookPayload struct {
	Version  string         `json:"version"`
	GroupKey string         `json:"groupKey"`
	Status   string         `json:"status"` // "firing" or "resolved" (group-level)
	OrgID    int64          `json:"orgId"`
	Title    string         `json:"title"`
	State    string         `json:"state"`   // "alerting", "ok", "no_data", "paused"
	Message  string         `json:"message"` // free text, may contain PII — never emitted
	Alerts   []grafanaAlert `json:"alerts"`
}

// grafanaAlert is one member of the alerts array.
type grafanaAlert struct {
	Status       string            `json:"status"`      // "firing" or "resolved"
	Labels       map[string]string `json:"labels"`      // alertname, grafana_folder, job, …
	Annotations  map[string]string `json:"annotations"` // excluded from payload (PII risk)
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	DashboardURL string            `json:"dashboardURL"`
	PanelURL     string            `json:"panelURL"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
	SilenceURL   string            `json:"silenceURL"`
	ImageURL     string            `json:"imageURL"`
}

// processPayload unmarshals the Grafana webhook body and emits one event per
// alert contained in the payload. Mirroring the Prometheus source: each alert
// in the group becomes a separate envelope.Event.
func (s *Source) processPayload(body []byte) error {
	var wh grafanaWebhookPayload
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal grafana payload: %w", err)
	}

	for _, alert := range wh.Alerts {
		ev := s.normalizeAlert(wh, alert)
		s.emit(ev)
	}
	return nil
}

// normalizeAlert converts one grafanaAlert into a canonical envelope.Event.
func (s *Source) normalizeAlert(wh grafanaWebhookPayload, alert grafanaAlert) envelope.Event {
	// Timestamp: use alert-level StartsAt in UTC; fall back to now.
	t := alert.StartsAt.UTC()
	if t.IsZero() {
		t = time.Now().UTC()
	}

	// Resource: prefer alertname label, then grafana_folder/alertname compound,
	// then fingerprint as a last resort.
	alertName := alert.Labels["alertname"]
	folder := alert.Labels["grafana_folder"]
	resource := buildResource(alertName, folder, alert.Fingerprint)

	// Build payload from labels only; annotations are excluded (PII risk).
	// Include status and fingerprint for downstream correlation.
	labelCopy := make(map[string]any, len(alert.Labels)+3)
	for k, v := range alert.Labels {
		labelCopy[k] = v
	}
	labelCopy["status"] = alert.Status
	labelCopy["fingerprint"] = alert.Fingerprint
	if !alert.EndsAt.IsZero() && alert.Status == "resolved" {
		labelCopy["ended_at"] = alert.EndsAt.UTC().Format(time.RFC3339)
	}
	// Preserve the group-level state field when it adds information not in the
	// per-alert status (e.g., "no_data", "paused").
	if wh.State != "" && wh.State != alert.Status {
		labelCopy["group_state"] = wh.State
	}

	payload := s.redact.Apply(labelCopy)

	return envelope.Event{
		OccurredAt:  t,
		EventType:   MapAlertStatus(alert.Status),
		EventSource: envelope.SourceGrafana,
		Actor:       nil, // Grafana Alerting webhooks carry no user principal
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}
}

// buildResource composes the resource identifier from available label fields.
// Priority: "folder/alertname" when both present, bare alertname, fingerprint.
func buildResource(alertName, folder, fingerprint string) string {
	switch {
	case alertName != "" && folder != "":
		return folder + "/" + alertName
	case alertName != "":
		return alertName
	case fingerprint != "":
		return fingerprint
	default:
		return "unknown"
	}
}

// verifyBearer checks that the Authorization header is "Bearer <token>" and that
// the token equals the configured secret in constant time.
// The "Bearer " prefix is mandatory; a bare value is rejected.
func verifyBearer(secret, authHeader string) bool {
	if secret == "" {
		return false
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	return sigverify.SecretEqual(secret, token)
}

// MapAlertStatus maps a Grafana alert status string to the canonical event type.
// Both "firing" and "resolved" map to "monitor.alert" — the status is preserved
// in the event payload under the "status" key for downstream consumers.
// Exported for testing.
func MapAlertStatus(status string) string {
	// All Grafana alert events use monitor.alert regardless of firing/resolved,
	// consistent with the Prometheus source and CONTRACT.md §8.
	return "monitor.alert"
}

// VerifyBearer exposes the bearer-auth check for external test packages.
// The header must carry the "Bearer " prefix; a bare token value is rejected.
// Returns false when secret is empty so a misconfigured collector cannot
// accidentally accept any request.
// Exported for testing.
func VerifyBearer(secret, authHeader string) bool {
	return verifyBearer(secret, authHeader)
}

// HandleWebhookForTest exposes the internal webhook handler for external test packages.
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
