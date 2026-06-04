// Package spacelift receives Spacelift named-webhook run state-change
// notifications and normalizes them into canonical envelope events.
//
// Spacelift delivers a POST to the configured receiver URL whenever a stack
// run transitions to a new state. The collector is a purely passive webhook
// receiver — it makes no outbound API calls to Spacelift.
//
// Authentication: the payload body is signed with HMAC-SHA256 using the
// shared secret configured on the Spacelift webhook. The signature is carried
// in the X-Signature-256 header with a "sha256=" prefix. Verification uses
// sigverify.HexHMACPrefixed which performs a constant-time comparison
// (manifest §9 / CONTRACT.md §9).
//
// Reference: https://docs.spacelift.io/integrations/webhooks
//
// Run state to canonical event type mapping (CONTRACT.md §8, taxonomy §4.5):
//
//   - TRIGGERED / PREPARING / PLANNING / APPLYING   -> deploy.started
//   - FINISHED (outcome: success)                   -> deploy.completed
//   - FAILED / STOPPED                              -> deploy.failed
//   - CONFIRMED                                     -> change.iac_applied
//   - DISCARDED / CANCELED                          -> deploy.failed
//
// For FINISHED runs the "outcome" field is used to distinguish success (no
// outcome, or "success") from failure ("failure"). If the outcome is
// explicitly "failure" the event is mapped to deploy.failed instead.
//
// EU compliance: no outbound HTTP calls are made by this source. The webhook
// receiver is inbound-only (EU-resident customer traffic flows in; no data
// flows out through this source).
//
// PII handling: all payload fields pass through redact.Apply before envelope
// construction. The triggered-by field passes through redact.RedactActor.
// Raw payloads are never logged at INFO level (manifest §12.13).
package spacelift

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

// Source receives Spacelift named-webhook run state-change notifications.
type Source struct {
	cfg    config.SpaceliftConfig
	redact *redact.Redactor
	emit   func(envelope.Event)
}

// New constructs a Spacelift source. It does not start goroutines or make
// network calls (CONTRACT.md §2).
func New(cfg config.SpaceliftConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
	return &Source{cfg: cfg, redact: r, emit: emit}
}

// Register adds the Spacelift webhook handler to the shared router at
// /webhook/spacelift (CONTRACT.md §3).
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/spacelift", s.handleWebhook)
}

// Run is a no-op for the Spacelift source — it is webhook-only (CONTRACT.md §5).
// The method exists so main.go can treat all sources uniformly.
func (s *Source) Run(_ context.Context) error {
	return nil
}

// handleWebhook is the HTTP handler for Spacelift run state-change notifications.
//
// Contract:
//   - POST only; returns 405 for any other method.
//   - Reads body up to 5 MiB (consistent with all other sources).
//   - Verifies X-Signature-256 ("sha256=" prefix, HMAC-SHA256) when
//     cfg.WebhookSecret is non-empty; returns 401 on mismatch.
//   - Processes the payload, emitting one event per call.
//   - Returns 204 on success, 400 on read error, 500 on processing error.
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

	// Verify signature when a secret is configured (CONTRACT.md §9).
	if s.cfg.WebhookSecret != "" {
		sig := r.Header.Get("X-Signature-256")
		if !sigverify.HexHMACPrefixed([]byte(s.cfg.WebhookSecret), body, sig, "sha256=") {
			slog.Warn("spacelift webhook: invalid X-Signature-256")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processPayload(body); err != nil {
		slog.Error("spacelift webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// spaceliftPayload is the wire shape of a Spacelift named-webhook run
// state-change notification.
//
// Spacelift reference payload (simplified):
//
//	{
//	  "state":        "FINISHED",
//	  "stateVersion": 1,
//	  "timestamp":    1715077200,
//	  "outcome":      "success",
//	  "run": {
//	    "id":           "01JXXXXXXXXXXXXXX",
//	    "type":         "TRACKED",
//	    "triggeredBy":  "alice@example.com",
//	    "commit": {
//	      "authorName": "Alice Smith",
//	      "authorLogin": "alice",
//	      "hash": "abc123def456"
//	    }
//	  },
//	  "stack": {
//	    "id":   "my-stack",
//	    "name": "My Stack",
//	    "spaceDetails": {"id": "root"}
//	  }
//	}
//
// Fields not listed here are discarded; unknown JSON keys are ignored by
// the decoder per Go's default behaviour.
type spaceliftPayload struct {
	// State is the new run state, e.g. "FINISHED", "FAILED", "APPLYING".
	State string `json:"state"`

	// StateVersion is the monotonic version of the state transition; we
	// include it in the payload for idempotency analysis downstream.
	StateVersion int `json:"stateVersion"`

	// Timestamp is the Unix epoch (seconds) at which the state transition
	// occurred. Falls back to time.Now() if zero.
	Timestamp int64 `json:"timestamp"`

	// Outcome distinguishes success from failure within a FINISHED state.
	// Typical values: "success", "failure", "" (absent for non-FINISHED states).
	Outcome string `json:"outcome"`

	// Run holds identity and attribution for the stack run.
	Run spaceliftRun `json:"run"`

	// Stack holds the stack that owns the run.
	Stack spaceliftStack `json:"stack"`
}

// spaceliftRun contains the run-level fields from the webhook payload.
type spaceliftRun struct {
	// ID is the Spacelift opaque run identifier, e.g. "01JXXXXXXXXXXXXXXX".
	ID string `json:"id"`

	// Type is the run type: "TRACKED", "PROPOSED", "TASK", etc.
	Type string `json:"type"`

	// TriggeredBy is the user or integration that triggered the run.
	// This is the primary actor field; redacted before envelope construction.
	TriggeredBy string `json:"triggeredBy"`

	// Commit contains VCS attribution metadata for the run.
	Commit spaceliftCommit `json:"commit"`
}

// spaceliftCommit contains the VCS commit metadata embedded in a run.
type spaceliftCommit struct {
	// AuthorName is the commit author display name (may contain PII).
	AuthorName string `json:"authorName"`

	// AuthorLogin is the VCS login handle of the commit author.
	AuthorLogin string `json:"authorLogin"`

	// Hash is the full or abbreviated commit hash.
	Hash string `json:"hash"`

	// Message is the commit message (may contain PII; excluded from payload).
	Message string `json:"message"`
}

// spaceliftStack contains stack-level fields from the webhook payload.
type spaceliftStack struct {
	// ID is the Spacelift stack slug.
	ID string `json:"id"`

	// Name is the human-readable stack name.
	Name string `json:"name"`
}

// processPayload unmarshals a Spacelift run state-change webhook payload and
// emits a normalized envelope.Event. Returns an error only if the JSON is
// malformed; unknown states are mapped to a reasonable default and logged at
// DEBUG level so the handler always returns 204 to Spacelift.
func (s *Source) processPayload(body []byte) error {
	var p spaceliftPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("unmarshal spacelift payload: %w", err)
	}

	evType := mapRunState(p.State, p.Outcome)

	// Determine the actor: prefer triggered-by, fall back to commit author login,
	// then commit author name. Apply redaction to whichever we pick.
	rawActor := p.Run.TriggeredBy
	if rawActor == "" {
		rawActor = p.Run.Commit.AuthorLogin
	}
	if rawActor == "" {
		rawActor = p.Run.Commit.AuthorName
	}
	actor := s.redact.RedactActor(ptrs.String(rawActor))

	// Build the resource identifier: "stackName/runID" — this uniquely
	// identifies the entity the event describes (CONTRACT.md §7 rule 7).
	resource := resourceID(p.Stack.Name, p.Stack.ID, p.Run.ID)

	// Determine occurred_at from the Unix timestamp; fall back to now when
	// the payload carries zero (CONTRACT.md §7 rule 4).
	var occurredAt time.Time
	if p.Timestamp > 0 {
		occurredAt = time.Unix(p.Timestamp, 0).UTC()
	} else {
		occurredAt = time.Now().UTC()
	}

	// Build the normalized payload map. Exclude raw commit message (may
	// contain PII) and any field that is not needed for DORA analysis.
	// Apply redact.Apply to scrub any PII values (emails, IPs) in the map
	// (CONTRACT.md §7 rule 1).
	rawPayload := map[string]any{
		"state":         p.State,
		"state_version": p.StateVersion,
		"outcome":       p.Outcome,
		"run_id":        p.Run.ID,
		"run_type":      p.Run.Type,
		"stack_id":      p.Stack.ID,
		"stack_name":    p.Stack.Name,
		"commit_hash":   p.Run.Commit.Hash,
		"commit_author": p.Run.Commit.AuthorLogin,
	}
	payload := s.redact.Apply(rawPayload)

	slog.Debug("spacelift webhook: emitting event",
		"state", p.State,
		"event_type", evType,
		"run_id", p.Run.ID,
	)

	s.emit(envelope.Event{
		OccurredAt:  occurredAt,
		EventType:   evType,
		EventSource: envelope.SourceSpacelift,
		Actor:       actor,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

// resourceID computes a stable resource string for the event.
// Format: "<stackName>/<runID>" when both are available.
// Falls back to stackID if stackName is empty, and to runID alone if stack
// information is absent.
func resourceID(stackName, stackID, runID string) string {
	stack := stackName
	if stack == "" {
		stack = stackID
	}
	switch {
	case stack != "" && runID != "":
		return stack + "/" + runID
	case stack != "":
		return stack
	default:
		return runID
	}
}

// MapRunState maps a Spacelift run state and optional outcome to a canonical
// event type from the taxonomy in CONTRACT.md §8 / manifest §4.5.
//
// Mapping rationale:
//
//   - TRIGGERED / PREPARING / PLANNING / APPLYING: the run is in-flight;
//     emit deploy.started to mark the beginning of a deployment lifecycle.
//   - FINISHED with outcome != "failure": the run completed successfully;
//     emit deploy.completed.
//   - FINISHED with outcome == "failure": completed but with failure outcome;
//     emit deploy.failed.
//   - FAILED / STOPPED: terminal error state; emit deploy.failed.
//   - DISCARDED / CANCELED: operator-cancelled run; emit deploy.failed
//     because the intended change did not land.
//   - CONFIRMED: a run was manually approved / confirmed; the IaC change has
//     been approved for execution. Map to change.iac_applied because this
//     represents a human approval of the IaC delta (similar to change.approved
//     in PR workflows, but IaC-specific per manifest §4.5).
//   - Unknown states: default to deploy.started (conservative; avoids silent
//     data loss) and log at DEBUG.
//
// Exported as MapRunState so tests can call it directly.
func MapRunState(state, outcome string) string {
	return mapRunState(state, outcome)
}

func mapRunState(state, outcome string) string {
	switch strings.ToUpper(state) {
	case "TRIGGERED", "PREPARING", "PLANNING", "APPLYING":
		return "deploy.started"
	case "FINISHED":
		if strings.ToLower(outcome) == "failure" {
			return "deploy.failed"
		}
		return "deploy.completed"
	case "FAILED", "STOPPED":
		return "deploy.failed"
	case "DISCARDED", "CANCELED":
		return "deploy.failed"
	case "CONFIRMED":
		return "change.iac_applied"
	default:
		slog.Debug("spacelift: unknown run state; defaulting to deploy.started", "state", state)
		return "deploy.started"
	}
}

// HandleWebhookForTest exposes the internal webhook handler for use in
// external test packages. This avoids requiring a running HTTP server in
// unit tests (mirrors the pattern used by prometheus and datadog sources).
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
