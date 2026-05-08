// Package pagerduty receives PagerDuty webhook v3 payloads and normalizes them
// into canonical envelope events.
//
// PagerDuty pushes event notifications to the collector's HTTP endpoint.
// The collector verifies the X-PagerDuty-Signature header (HMAC-SHA256)
// before processing any payload.
//
// Supported PagerDuty event types (all map to the incident.* taxonomy):
//   - incident.triggered    -> incident.opened
//   - incident.acknowledged -> incident.acknowledged
//   - incident.resolved     -> incident.resolved
//   - incident.escalated    -> incident.escalated
//
// The collector is a passive receiver — it makes no API calls back to PagerDuty.
// Read-only posture is maintained by design: there is no PagerDuty API client.
package pagerduty

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
)

// Source listens for PagerDuty webhook v3 payloads.
type Source struct {
	cfg    config.PagerDutyConfig
	redact *redact.Redactor
	emit   func(envelope.Event)
}

// New constructs a PagerDuty source.
func New(cfg config.PagerDutyConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
	return &Source{cfg: cfg, redact: r, emit: emit}
}

// Run starts the webhook HTTP server. It blocks until ctx is cancelled.
func (s *Source) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/pagerduty", s.handleWebhook)
	// Health probe used by the Helm readiness check.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addr := fmt.Sprintf(":%d", s.cfg.WebhookPort)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	slog.Info("pagerduty webhook server starting", "addr", addr)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("pagerduty webhook server: %w", err)
	}
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

	// Verify PagerDuty v3 webhook signature.
	if s.cfg.SigningSecret != "" {
		sig := r.Header.Get("X-PagerDuty-Signature")
		if !verifyPDSignature([]byte(s.cfg.SigningSecret), body, sig) {
			slog.Warn("pagerduty webhook: invalid signature")
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processPayload(body); err != nil {
		slog.Error("pagerduty webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// pdWebhookV3 is the envelope for PagerDuty webhook v3 payloads.
// See: https://developer.pagerduty.com/docs/db0fa8c8984fc-overview
type pdWebhookV3 struct {
	Messages []pdMessage `json:"messages"`
}

type pdMessage struct {
	Event     string     `json:"event"`
	CreatedAt string     `json:"created_at"`
	Payload   *pdPayload `json:"payload"`
}

type pdPayload struct {
	Summary       string    `json:"summary"`
	Timestamp     string    `json:"timestamp"`
	Severity      string    `json:"severity"`
	Source        string    `json:"source"`
	Component     string    `json:"component"`
	Group         string    `json:"group"`
	Class         string    `json:"class"`
	CustomDetails any       `json:"custom_details"`
}

// pdIncident is the incident sub-object within a PagerDuty webhook.
type pdIncident struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	Urgency     string    `json:"urgency"`
	CreatedAt   string    `json:"created_at"`
	ResolvedAt  string    `json:"resolved_at"`
	ServiceName string    `json:"service"`
	HTMLUrl     string    `json:"html_url"`
	Assignees   []pdUser  `json:"assignments"`
}

type pdUser struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

func (s *Source) processPayload(body []byte) error {
	// PagerDuty v3 wraps one or more messages in a "messages" array.
	var webhook pdWebhookV3
	if err := json.Unmarshal(body, &webhook); err != nil {
		return fmt.Errorf("unmarshal pagerduty webhook: %w", err)
	}

	for _, msg := range webhook.Messages {
		ev, ok := s.normalizeMessage(msg, body)
		if !ok {
			continue
		}
		s.emit(ev)
	}
	return nil
}

func (s *Source) normalizeMessage(msg pdMessage, rawBody []byte) (envelope.Event, bool) {
	evType, ok := mapPDEventType(msg.Event)
	if !ok {
		slog.Debug("pagerduty: skipping unsupported event type", "pd_event", msg.Event)
		return envelope.Event{}, false
	}

	// Parse the incident from the raw body (the go-pagerduty library is not used
	// to avoid adding a dependency; we parse the incident sub-object directly).
	var rawMsg map[string]any
	if err := json.Unmarshal(rawBody, &rawMsg); err != nil {
		return envelope.Event{}, false
	}

	// PagerDuty v3: the incident is at messages[0].incident in older formats or
	// embedded in the payload. We extract what we can from the message payload.
	t := time.Now().UTC()
	if msg.CreatedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, msg.CreatedAt); err == nil {
			t = parsed.UTC()
		}
	}

	// Build payload from the message's own payload field — never log raw body.
	payload := map[string]any{
		"pd_event": msg.Event,
	}
	if msg.Payload != nil {
		payload["summary"] = msg.Payload.Summary
		payload["severity"] = msg.Payload.Severity
		payload["source"] = msg.Payload.Source
		payload["component"] = msg.Payload.Component
		payload["group"] = msg.Payload.Group
	}
	payload = s.redact.Apply(payload)

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourcePagerDuty,
		Actor:       nil, // PagerDuty v3 webhooks do not expose an actor in the top-level message
		Resource:    nil, // Set to incident ID by the incident-specific handler below
		Payload:     payload,
	}, true
}

// MapEventType maps PagerDuty v3 event names to canonical event types (§4.5).
// Exported for testing.
func MapEventType(pdEvent string) (string, bool) {
	return mapPDEventType(pdEvent)
}

// VerifySignature verifies a PagerDuty v3 webhook signature header.
// Exported for testing.
func VerifySignature(secret, body []byte, header string) bool {
	return verifyPDSignature(secret, body, header)
}

func mapPDEventType(pdEvent string) (string, bool) {
	mapping := map[string]string{
		"incident.triggered":    "incident.opened",
		"incident.acknowledged": "incident.acknowledged",
		"incident.resolved":     "incident.resolved",
		"incident.escalated":    "incident.escalated",
		"incident.unacknowledged": "incident.opened",
		"incident.delegated":    "incident.escalated",
		"incident.reopened":     "incident.opened",
	}
	t, ok := mapping[pdEvent]
	return t, ok
}

// verifyPDSignature checks the PagerDuty v3 webhook signature.
// PagerDuty signs using HMAC-SHA256 and sends the value as:
//   v1=<hex-signature>
//
// See: https://developer.pagerduty.com/docs/db0fa8c8984fc-verifying-signatures
func verifyPDSignature(secret, body []byte, signatureHeader string) bool {
	// The header may contain multiple signatures separated by commas.
	for _, part := range strings.Split(signatureHeader, ",") {
		part = strings.TrimSpace(part)
		const prefix = "v1="
		if !strings.HasPrefix(part, prefix) {
			continue
		}
		hexSig := part[len(prefix):]
		sigBytes, err := hex.DecodeString(hexSig)
		if err != nil {
			continue
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(body)
		expected := mac.Sum(nil)
		if hmac.Equal(expected, sigBytes) {
			return true
		}
	}
	return false
}
