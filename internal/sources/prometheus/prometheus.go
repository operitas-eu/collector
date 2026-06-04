// Package prometheus receives Alertmanager webhook notifications from Prometheus
// and normalizes them into canonical envelope events.
//
// The collector is a purely passive webhook receiver — it makes no outbound API
// calls to Prometheus or Alertmanager. Alertmanager is configured to POST to the
// collector's HTTP endpoint when alert states change (firing/resolved).
//
// Authentication: the collector supports three schemes, controlled by
// PrometheusConfig.AuthScheme:
//
//   - "bearer": the Authorization header must be "Bearer <WebhookSecret>"
//   - "basic":  the Authorization header must be "Basic base64(<BasicUser>:<WebhookSecret>)"
//   - "none":   no auth check — suitable only for fully private network segments
//
// Reference: https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
//
// EU compliance: no outbound HTTP calls are made by this source. The webhook
// receiver is inbound-only (EU-resident customer traffic flows in; no data
// flows out through this source).
//
// PII handling: all payload labels and annotations pass through redact.Apply
// before envelope construction. Actor is always nil for Alertmanager events
// because Alertmanager does not include a user principal in its webhook payloads.
package prometheus

import (
	"context"
	"encoding/base64"
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

// Source receives Alertmanager webhook notifications.
type Source struct {
	cfg    config.PrometheusConfig
	redact *redact.Redactor
	emit   func(envelope.Event)
}

// New constructs a Prometheus source.
func New(cfg config.PrometheusConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
	return &Source{cfg: cfg, redact: r, emit: emit}
}

// Register adds the Prometheus/Alertmanager webhook handler to the shared router
// at /webhook/prometheus.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/prometheus", s.handleWebhook)
}

// Run is a no-op for the Prometheus source — it is webhook-only. The method
// exists to satisfy the common source interface used in main.go for consistency.
// Pass this source to the shared router's Register method instead.
func (s *Source) Run(_ context.Context) error {
	// Webhook-only source: nothing to start here. The handler was registered
	// on the shared router in main.go before this point.
	return nil
}

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

	if !s.verifyAuth(r) {
		slog.Warn("prometheus webhook: authentication failed")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := s.processPayload(body); err != nil {
		slog.Error("prometheus webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// verifyAuth checks the Authorization header against the configured scheme.
func (s *Source) verifyAuth(r *http.Request) bool {
	switch s.cfg.AuthScheme {
	case "none":
		return true
	case "basic":
		return s.verifyBasic(r)
	default: // "bearer"
		return s.verifyBearer(r)
	}
}

func (s *Source) verifyBearer(r *http.Request) bool {
	if s.cfg.WebhookSecret == "" {
		return false
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	return sigverify.SecretEqual(s.cfg.WebhookSecret, token)
}

func (s *Source) verifyBasic(r *http.Request) bool {
	if s.cfg.WebhookSecret == "" {
		return false
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return false
	}
	// decoded is "user:password"
	idx := strings.IndexByte(string(decoded), ':')
	if idx < 0 {
		return false
	}
	user := string(decoded[:idx])
	pass := string(decoded[idx+1:])
	userOK := sigverify.SecretEqual(s.cfg.BasicUser, user)
	passOK := sigverify.SecretEqual(s.cfg.WebhookSecret, pass)
	return userOK && passOK
}

// amWebhookPayload is the Alertmanager webhook payload shape.
// Reference: https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
type amWebhookPayload struct {
	Version           string    `json:"version"`
	GroupKey          string    `json:"groupKey"`
	TruncatedAlerts   int       `json:"truncatedAlerts"`
	Status            string    `json:"status"` // "firing" or "resolved"
	Receiver          string    `json:"receiver"`
	GroupLabels       amKVMap   `json:"groupLabels"`
	CommonLabels      amKVMap   `json:"commonLabels"`
	CommonAnnotations amKVMap   `json:"commonAnnotations"`
	ExternalURL       string    `json:"externalURL"`
	Alerts            []amAlert `json:"alerts"`
}

type amAlert struct {
	Status       string    `json:"status"` // "firing" or "resolved"
	Labels       amKVMap   `json:"labels"`
	Annotations  amKVMap   `json:"annotations"`
	StartsAt     time.Time `json:"startsAt"`
	EndsAt       time.Time `json:"endsAt"`
	GeneratorURL string    `json:"generatorURL"`
	Fingerprint  string    `json:"fingerprint"`
}

// amKVMap is a label/annotation set — a simple string-to-string map.
type amKVMap map[string]string

func (s *Source) processPayload(body []byte) error {
	var wh amWebhookPayload
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal alertmanager payload: %w", err)
	}

	for _, alert := range wh.Alerts {
		ev := s.normalizeAlert(wh, alert)
		s.emit(ev)
	}
	return nil
}

func (s *Source) normalizeAlert(wh amWebhookPayload, alert amAlert) envelope.Event {
	evType := mapAlertStatus(alert.Status)

	// Use StartsAt as the event timestamp; fall back to now.
	t := alert.StartsAt.UTC()
	if t.IsZero() {
		t = time.Now().UTC()
	}

	alertName := alert.Labels["alertname"]
	if alertName == "" {
		alertName = wh.CommonLabels["alertname"]
	}

	// Build payload from labels (no raw annotation text which may contain PII).
	labelCopy := make(map[string]any, len(alert.Labels))
	for k, v := range alert.Labels {
		labelCopy[k] = v
	}
	labelCopy["status"] = alert.Status
	labelCopy["fingerprint"] = alert.Fingerprint
	// Backfill severity from the group's common labels when the per-alert label
	// is absent, so the classifier always sees a severity signal.
	if alert.Labels["severity"] == "" {
		if common := wh.CommonLabels["severity"]; common != "" {
			labelCopy["severity"] = common
		}
	}
	if !alert.EndsAt.IsZero() && alert.Status == "resolved" {
		labelCopy["ended_at"] = alert.EndsAt.UTC().Format(time.RFC3339)
	}

	payload := s.redact.Apply(labelCopy)

	resource := alertName
	if resource == "" {
		resource = alert.Fingerprint
	}

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourcePrometheus,
		Actor:       nil, // Alertmanager events have no user principal
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}
}

// MapAlertStatus maps an Alertmanager alert status to a canonical event type.
// Exported for testing.
func MapAlertStatus(status string) string {
	return mapAlertStatus(status)
}

func mapAlertStatus(status string) string {
	switch strings.ToLower(status) {
	case "resolved":
		return "monitor.alert"
	default:
		// "firing" and any unknown status.
		return "monitor.alert"
	}
}

// VerifyBearer checks the Authorization: Bearer header for testing.
// The header must have the "Bearer " prefix; a bare value is rejected.
// Exported for testing.
func VerifyBearer(secret, authHeader string) bool {
	if secret == "" {
		return false
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	return sigverify.SecretEqual(secret, token)
}

// VerifyBasic checks the Authorization: Basic header for testing.
// Exported for testing.
func VerifyBasic(user, pass, authHeader string) bool {
	if !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
	if err != nil {
		return false
	}
	idx := strings.IndexByte(string(decoded), ':')
	if idx < 0 {
		return false
	}
	u := string(decoded[:idx])
	p := string(decoded[idx+1:])
	return sigverify.SecretEqual(user, u) && sigverify.SecretEqual(pass, p)
}

// HandleWebhookForTest exposes the internal webhook handler for external test packages.
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
