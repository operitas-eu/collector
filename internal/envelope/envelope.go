// Package envelope defines the canonical wire-format types the collector produces.
// Every event emitted by any source package must pass through this package before
// being handed to the transport layer. This is the single boundary that enforces
// conformance with infra/schemas/evidence_envelope.json (schema version 1.0.0).
//
// The ingest service is expected to accept the same BatchRequest shape; field
// names and constraints here must stay in lock-step with the JSON schema.
//
// Fixture-based contract tests live in internal/envelope/testdata/fixtures/.
// Both validators (collector + ingest) run against the same fixture tree; they
// must agree on accept/reject outcomes and error substrings (manifest §0 lock-step).
// The fixture copy is checked in — do not pull at runtime. See the TODO in
// envelope_contract_test.go for the future vendoring strategy.
package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// EnvelopeVersion is the only value the schema allows for the envelope_version field.
const EnvelopeVersion = "1.0.0"

// EventSource values are the exact enum from the JSON schema.
type EventSource string

// EventSource enum values — kept in lockstep with the JSON schema.
// SourceAzureActivity is declared for schema completeness; the Azure collector
// source package is not yet implemented (a new internal/sources/azure/
// package plus the AWS-style read-only API audit is required first —
// architectural review 2026-05-07).
const (
	SourceAWSCloudTrail EventSource = "aws.cloudtrail"
	SourceAzureActivity EventSource = "azure.activity"
	SourceGitHub        EventSource = "github"
	SourceGitLab        EventSource = "gitlab"
	SourcePagerDuty     EventSource = "pagerduty"
	SourceDatadog       EventSource = "datadog"
	SourceJira          EventSource = "jira"
	SourceArgoCD        EventSource = "argocd"
	SourceK8sAudit      EventSource = "k8s.audit"
	SourceVendorStatus  EventSource = "vendor.statuspage"
)

// eventTypePattern matches the pattern from the JSON schema:
// ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$
var eventTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// validSources is the set of allowed event_source values.
var validSources = map[EventSource]struct{}{
	SourceAWSCloudTrail: {},
	SourceAzureActivity: {},
	SourceGitHub:        {},
	SourceGitLab:        {},
	SourcePagerDuty:     {},
	SourceDatadog:       {},
	SourceJira:          {},
	SourceArgoCD:        {},
	SourceK8sAudit:      {},
	SourceVendorStatus:  {},
}

// Event is a single normalized event item.
// All fields map directly to the "event" $def in evidence_envelope.json.
// The payload field must never contain raw PII; the redact package is responsible
// for stripping it before an Event is constructed.
type Event struct {
	// OccurredAt is the source-system timestamp, RFC3339Nano in UTC.
	// The ingest service sets ingested_at server-side; we do not send it.
	OccurredAt time.Time `json:"occurred_at"`

	// EventType uses lower.dot.notation per manifest §4.5.
	EventType string `json:"event_type"`

	// EventSource must be one of the enum values in the JSON schema.
	EventSource EventSource `json:"event_source"`

	// Actor is the IAM principal, user email (post-redaction), or bot name that
	// performed the action. Null when unknown.
	Actor *string `json:"actor,omitempty"`

	// Resource identifies the affected resource: ARN, repository path, service name, etc.
	Resource *string `json:"resource,omitempty"`

	// Payload is the normalized source-specific event body. It must not be logged at
	// INFO level (manifest §12.13). It will be hashed by the ingest service for the
	// hash chain (manifest §4.3).
	Payload map[string]any `json:"payload"`
}

// BatchRequest is the top-level wire format for POST /v1/events:batch (manifest §8.2).
type BatchRequest struct {
	CollectorID     string  `json:"collector_id"`
	TenantID        string  `json:"tenant_id"`
	EnvelopeVersion string  `json:"envelope_version"`
	Events          []Event `json:"events"`
}

// BatchResponse mirrors the ingest API success response (manifest §8.2, ADR 0003).
// The endpoint is all-or-nothing: Accepted always equals len(Events); there is no
// Rejected field because partial success is not representable. See docs/api/ingest-batch.md
// in the operitas-eu/operitas monorepo for the canonical retry-semantics spec.
type BatchResponse struct {
	Accepted    int    `json:"accepted"`
	FirstSeq    int64  `json:"first_seq"`
	LastSeq     int64  `json:"last_seq"`
	LastRowHash string `json:"last_row_hash"`
}

// ValidationError422 is the wire shape returned by the ingest API on 422
// Unprocessable Entity (schema validation failure). The batch was all-or-nothing
// rejected; no events were written. Route the batch to the DLQ; do not retry.
type ValidationError422 struct {
	Error          string       `json:"error"`
	EnvelopeErrors []string     `json:"envelope_errors,omitempty"`
	Events         []EventError `json:"events"`
}

// EventError is one element of ValidationError422.Events, keyed by zero-based
// event index in the original batch.
type EventError struct {
	Index  int      `json:"index"`
	Errors []string `json:"errors"`
}

// Validate checks that the event is schema-conformant. It returns a non-nil error
// describing every violation found so callers can log them before dropping the event.
//
// Error substrings must satisfy the fixture .expect.txt assertions in
// internal/envelope/testdata/fixtures/invalid/ — changes here require a paired
// update to the fixture files or a review of the expected substrings.
func (e *Event) Validate() error {
	var errs []error

	if e.OccurredAt.IsZero() {
		errs = append(errs, errors.New("occurred_at: zero time"))
	} else if e.OccurredAt.Location() != time.UTC {
		// Enforce UTC so the ingest service can trust the timezone.
		errs = append(errs, errors.New("occurred_at: must be in UTC"))
	}
	if !eventTypePattern.MatchString(e.EventType) {
		// "pattern mismatch" substring is asserted by bad_event_type_pattern.expect.txt.
		errs = append(errs, fmt.Errorf("event_type %q: pattern mismatch", e.EventType))
	}
	if _, ok := validSources[e.EventSource]; !ok {
		// "not in enum" substring is asserted by unknown_event_source.expect.txt.
		errs = append(errs, fmt.Errorf("event_source %q: not in enum", e.EventSource))
	}
	if e.Payload == nil {
		// "payload" + "required" substrings are asserted by missing_payload.expect.txt.
		errs = append(errs, errors.New("payload: required object"))
	}

	return errors.Join(errs...)
}

// ValidateBatch validates a BatchRequest before it is handed to the transport layer.
// It enforces the JSON schema constraints that cannot be expressed through struct tags alone.
//
// Error substrings must satisfy the fixture .expect.txt assertions in
// internal/envelope/testdata/fixtures/invalid/. The fixture tree is the cross-repo
// wire contract (manifest §0); both this validator and the ingest-side validator must
// agree on every fixture.
func ValidateBatch(b *BatchRequest) error {
	var errs []error

	if _, err := uuid.Parse(b.CollectorID); err != nil {
		// "collector_id" substring is asserted by bad_uuid_collector.expect.txt.
		errs = append(errs, fmt.Errorf("collector_id: not a UUID"))
	}
	if _, err := uuid.Parse(b.TenantID); err != nil {
		// "tenant_id" substring is asserted by bad_uuid_tenant.expect.txt.
		errs = append(errs, fmt.Errorf("tenant_id: not a UUID"))
	}
	if b.EnvelopeVersion != EnvelopeVersion {
		// "envelope_version" substring is asserted by wrong_envelope_version.expect.txt.
		errs = append(errs, fmt.Errorf("envelope_version: must be %q", EnvelopeVersion))
	}
	switch {
	case len(b.Events) == 0:
		// "minItems" substring is asserted by empty_events.expect.txt.
		errs = append(errs, errors.New("events: minItems is 1"))
	case len(b.Events) > 1000:
		// "maxItems" substring: consistent with ingest-side error.
		errs = append(errs, fmt.Errorf("events: maxItems is 1000, got %d", len(b.Events)))
	}
	for i, ev := range b.Events {
		if err := ev.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("events[%d]: %w", i, err))
		}
	}

	return errors.Join(errs...)
}

// wireEvent is the raw on-wire shape for an event — occurred_at is kept as a
// string so that DecodeAndValidate can validate its RFC3339Nano format
// independently of Go's time.Time.UnmarshalJSON (which would absorb the format
// check at the decoder level, producing a Go-internal format error string rather
// than the "occurred_at: not RFC3339Nano" string the fixture .expect.txt asserts).
type wireEvent struct {
	OccurredAt  string          `json:"occurred_at"`
	EventType   string          `json:"event_type"`
	EventSource string          `json:"event_source"`
	Actor       *string         `json:"actor,omitempty"`
	Resource    *string         `json:"resource,omitempty"`
	Payload     json.RawMessage `json:"payload"`
}

// wireBatch is the raw on-wire envelope batch — mirrors the JSON schema exactly
// so DecodeAndValidate can apply DisallowUnknownFields and validate the
// occurred_at format as a string.
type wireBatch struct {
	CollectorID     string      `json:"collector_id"`
	TenantID        string      `json:"tenant_id"`
	EnvelopeVersion string      `json:"envelope_version"`
	Events          []wireEvent `json:"events"`
}

// DecodeAndValidate performs a strict JSON decode (rejecting unknown fields per
// additionalProperties: false in the JSON schema) followed by field-level
// validation. This mirrors the handler path on the ingest side and is the path
// used by the contract fixture test.
//
// It uses the raw wire types (occurred_at as string) so the format validation
// error message contains "RFC3339" as asserted by bad_occurred_at.expect.txt.
func DecodeAndValidate(body []byte) error {
	var w wireBatch
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		// "unknown field" substring is asserted by additional_property.expect.txt.
		return fmt.Errorf("decode: %w", err)
	}
	return validateWireBatch(&w)
}

// validateWireBatch runs the same checks as ValidateBatch but operates on the
// raw wire types so occurred_at can be validated as a string (RFC3339Nano format
// check). Error messages match the fixture .expect.txt assertions exactly.
func validateWireBatch(w *wireBatch) error {
	var errs []error

	if _, err := uuid.Parse(w.CollectorID); err != nil {
		errs = append(errs, fmt.Errorf("collector_id: not a UUID"))
	}
	if _, err := uuid.Parse(w.TenantID); err != nil {
		errs = append(errs, fmt.Errorf("tenant_id: not a UUID"))
	}
	if w.EnvelopeVersion != EnvelopeVersion {
		errs = append(errs, fmt.Errorf("envelope_version: must be %q", EnvelopeVersion))
	}
	switch {
	case len(w.Events) == 0:
		errs = append(errs, errors.New("events: minItems is 1"))
	case len(w.Events) > 1000:
		errs = append(errs, fmt.Errorf("events: maxItems is 1000, got %d", len(w.Events)))
	}
	for i, ev := range w.Events {
		if msgs := validateWireEvent(ev); len(msgs) > 0 {
			for _, msg := range msgs {
				errs = append(errs, fmt.Errorf("events[%d]: %s", i, msg))
			}
		}
	}
	return errors.Join(errs...)
}

// validateWireEvent validates a single on-wire event. Error strings must match
// the fixture .expect.txt substring assertions.
func validateWireEvent(ev wireEvent) []string {
	var msgs []string
	t, err := time.Parse(time.RFC3339Nano, ev.OccurredAt)
	if err != nil {
		// "occurred_at" + "RFC3339" substrings are asserted by bad_occurred_at.expect.txt.
		msgs = append(msgs, "occurred_at: not RFC3339Nano")
	} else if t.IsZero() {
		msgs = append(msgs, "occurred_at: zero time")
	}
	if !eventTypePattern.MatchString(ev.EventType) {
		// "event_type" + "pattern mismatch" substrings from bad_event_type_pattern.expect.txt.
		msgs = append(msgs, fmt.Sprintf("event_type %q: pattern mismatch", ev.EventType))
	}
	if _, ok := validSources[EventSource(ev.EventSource)]; !ok {
		// "event_source" + "not in enum" substrings from unknown_event_source.expect.txt.
		msgs = append(msgs, fmt.Sprintf("event_source %q: not in enum", ev.EventSource))
	}
	if len(ev.Payload) == 0 {
		// "payload" + "required" substrings from missing_payload.expect.txt.
		msgs = append(msgs, "payload: required object")
	} else {
		var probe any
		if err := json.Unmarshal(ev.Payload, &probe); err != nil {
			msgs = append(msgs, fmt.Sprintf("payload: invalid JSON: %s", err.Error()))
		} else if _, ok := probe.(map[string]any); !ok {
			msgs = append(msgs, "payload: must be an object")
		}
	}
	return msgs
}

// NewBatch constructs a BatchRequest with the fixed envelope_version constant.
func NewBatch(collectorID, tenantID string, events []Event) *BatchRequest {
	return &BatchRequest{
		CollectorID:     collectorID,
		TenantID:        tenantID,
		EnvelopeVersion: EnvelopeVersion,
		Events:          events,
	}
}
