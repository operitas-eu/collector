// Package flux receives Flux CD notification-controller webhook events and
// normalizes them into canonical envelope events.
//
// The collector is a purely passive webhook receiver — it makes no outbound API
// calls to any Flux component or Kubernetes API. The Flux notification-controller
// is configured with a Receiver and Alert object whose spec.address points to
// this endpoint; it POSTs an Event object whenever a reconciliation transition
// occurs on a tracked Kustomization, HelmRelease, or GitRepository.
//
// Authentication: the Gotk-Webhook-Secret header is checked with constant-time
// equality via sigverify.SecretEqual. The shared secret must match the value
// in the Flux Receiver object's spec.secretRef. Set via OPERITAS_FLUX_WEBHOOK_SECRET.
// When WebhookSecret is empty the secret check is skipped (for fully private
// network segments where network isolation is the auth boundary).
//
// Supported Flux notification-controller reason values and their mappings:
//
//   - ReconciliationSucceeded -> deploy.completed
//   - ReconciliationFailed    -> deploy.failed
//   - ProgressingWithRetry    -> deploy.started
//   - Progressing             -> deploy.started
//   - ArtifactUpToDate        -> deploy.completed
//   - BuildFailed             -> deploy.failed
//   - HealthCheckFailed       -> deploy.failed
//   - DependencyNotReady      -> deploy.failed
//   - Suspended               -> change.iac_applied
//   - Resumed                 -> change.iac_applied
//
// Payload fields: reason, severity, message, controller, kind, namespace,
// revision (from metadata.revision when present).
//
// EU compliance: no outbound HTTP calls are made by this source. The webhook
// receiver is inbound-only (EU-resident customer traffic flows in; no data
// flows out through this source).
//
// PII handling: all payload fields pass through redact.Apply before envelope
// construction. Actor is derived from reportingController/reportingInstance
// which are controller identifiers, not user principals — they are passed
// through redact.RedactActor as a precaution.
package flux

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

// Source receives Flux CD notification-controller webhook events.
type Source struct {
	cfg    config.FluxConfig
	redact *redact.Redactor
	emit   func(envelope.Event)
}

// New constructs a Flux source.
func New(cfg config.FluxConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
	return &Source{cfg: cfg, redact: r, emit: emit}
}

// Register adds the Flux webhook handler to the shared router at /webhook/flux.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/flux", s.handleWebhook)
}

// Run is a no-op for the Flux source — it is webhook-only. The method exists
// to satisfy the common source interface used in main.go. The actual event
// ingestion happens in the HTTP handler registered via Register.
func (s *Source) Run(_ context.Context) error {
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

	if s.cfg.WebhookSecret != "" {
		got := r.Header.Get("Gotk-Webhook-Secret")
		if !sigverify.SecretEqual(s.cfg.WebhookSecret, got) {
			slog.Warn("flux webhook: invalid secret")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processPayload(body); err != nil {
		slog.Error("flux webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// fluxEvent is the notification-controller "generic" provider Event object shape.
// Reference: https://fluxcd.io/flux/components/notification/providers/#generic
type fluxEvent struct {
	// InvolvedObject identifies the Flux resource that triggered the event.
	InvolvedObject struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
	} `json:"involvedObject"`

	// Severity is "info" or "error" from the notification-controller.
	Severity string `json:"severity"`

	// Timestamp is the event creation time in RFC3339 format.
	Timestamp string `json:"timestamp"`

	// Message is the human-readable description of the event.
	Message string `json:"message"`

	// Reason is the machine-readable event reason (e.g. ReconciliationSucceeded).
	Reason string `json:"reason"`

	// Metadata holds optional key-value pairs. The "revision" key carries the
	// source revision (e.g. "main@sha1:<hash>") when present.
	Metadata map[string]string `json:"metadata"`

	// ReportingController is the name of the Flux controller that emitted the event
	// (e.g. "kustomize-controller", "helm-controller").
	ReportingController string `json:"reportingController"`

	// ReportingInstance is the pod name of the reporting controller.
	ReportingInstance string `json:"reportingInstance"`
}

func (s *Source) processPayload(body []byte) error {
	var ev fluxEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return fmt.Errorf("unmarshal flux event: %w", err)
	}

	normalized := s.normalizeEvent(ev)
	s.emit(normalized)
	return nil
}

func (s *Source) normalizeEvent(ev fluxEvent) envelope.Event {
	evType := MapReason(ev.Reason)

	// Parse the timestamp; fall back to now when absent or malformed.
	var occurredAt time.Time
	if ev.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
			occurredAt = t.UTC()
		}
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	// Actor is the controller identity, not a human principal. Pass through
	// redact.RedactActor as a precaution against non-standard deployments that
	// might rename controllers with values that look like email addresses.
	rawActor := ev.ReportingController
	if rawActor == "" {
		rawActor = ev.ReportingInstance
	}
	actor := s.redact.RedactActor(ptrs.String(rawActor))

	// Resource is namespace/kind/name — unambiguous across clusters.
	resource := buildResource(ev.InvolvedObject.Namespace, ev.InvolvedObject.Kind, ev.InvolvedObject.Name)

	// Build payload from normalized event fields. The raw message may contain
	// path info or user-supplied text — pass the full map through redact.Apply.
	payloadRaw := map[string]any{
		"reason":     ev.Reason,
		"severity":   ev.Severity,
		"message":    ev.Message,
		"kind":       ev.InvolvedObject.Kind,
		"namespace":  ev.InvolvedObject.Namespace,
		"name":       ev.InvolvedObject.Name,
		"controller": ev.ReportingController,
	}
	if rev, ok := ev.Metadata["revision"]; ok && rev != "" {
		payloadRaw["revision"] = rev
	}
	if summary, ok := ev.Metadata["summary"]; ok && summary != "" {
		payloadRaw["summary"] = summary
	}
	payload := s.redact.Apply(payloadRaw)

	return envelope.Event{
		OccurredAt:  occurredAt,
		EventType:   evType,
		EventSource: envelope.SourceFlux,
		Actor:       actor,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}
}

// buildResource constructs a "namespace/kind/name" resource identifier.
// Any empty component is omitted so partial information does not produce
// leading or trailing slashes.
func buildResource(namespace, kind, name string) string {
	parts := make([]string, 0, 3)
	if namespace != "" {
		parts = append(parts, namespace)
	}
	if kind != "" {
		parts = append(parts, kind)
	}
	if name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, "/")
}

// MapReason maps a Flux notification-controller reason string to a canonical
// event_type. Exported for testing.
func MapReason(reason string) string {
	return mapReason(reason)
}

func mapReason(reason string) string {
	switch reason {
	case "ReconciliationSucceeded", "ArtifactUpToDate":
		return "deploy.completed"
	case "ReconciliationFailed", "BuildFailed", "HealthCheckFailed", "DependencyNotReady":
		return "deploy.failed"
	case "Progressing", "ProgressingWithRetry":
		return "deploy.started"
	case "Suspended", "Resumed":
		return "change.iac_applied"
	default:
		// Unknown reasons are treated as informational completions to avoid
		// false deploy.failed noise for future Flux controller versions.
		return "deploy.completed"
	}
}

// HandleWebhookForTest exposes the internal webhook handler for external test packages.
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
