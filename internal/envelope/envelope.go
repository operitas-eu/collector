// Package envelope defines the canonical wire-format types the collector produces.
// Every event emitted by any source package must pass through this package before
// being handed to the transport layer. This is the single boundary that enforces
// conformance with infra/schemas/evidence_envelope.json (schema version 1.0.0).
//
// The ingest service is expected to accept the same BatchRequest shape; field
// names and constraints here must stay in lock-step with the JSON schema.
package envelope

import (
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

const (
	SourceAWSCloudTrail  EventSource = "aws.cloudtrail"
	// Declared for schema completeness with the JSON envelope. The Azure
	// collector source package is not yet implemented; the constant exists so
	// the wire enum stays in lockstep across services. Adding an Azure source
	// requires a new `internal/sources/azure/` package and the AWS-style
	// read-only API audit (architectural review 2026-05-07).
	SourceAzureActivity  EventSource = "azure.activity"
	SourceGitHub         EventSource = "github"
	SourcePagerDuty      EventSource = "pagerduty"
	SourceDatadog        EventSource = "datadog"
	SourceJira           EventSource = "jira"
	SourceArgoCD         EventSource = "argocd"
	SourceK8sAudit       EventSource = "k8s.audit"
	SourceVendorStatus   EventSource = "vendor.statuspage"
)

// eventTypePattern matches the pattern from the JSON schema:
// ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$
var eventTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// validSources is the set of allowed event_source values.
var validSources = map[EventSource]struct{}{
	SourceAWSCloudTrail: {},
	SourceAzureActivity: {},
	SourceGitHub:        {},
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

// BatchResponse mirrors the ingest API success response (manifest §8.2).
type BatchResponse struct {
	Accepted    int    `json:"accepted"`
	Rejected    int    `json:"rejected"`
	FirstSeq    int64  `json:"first_seq"`
	LastSeq     int64  `json:"last_seq"`
	LastRowHash string `json:"last_row_hash"`
}

// Validate checks that the event is schema-conformant. It returns a non-nil error
// describing every violation found so callers can log them before dropping the event.
func (e *Event) Validate() error {
	var errs []error

	if e.OccurredAt.IsZero() {
		errs = append(errs, errors.New("occurred_at must not be zero"))
	}
	if e.OccurredAt.Location() != time.UTC {
		// Enforce UTC so the ingest service can trust the timezone.
		errs = append(errs, errors.New("occurred_at must be in UTC"))
	}
	if !eventTypePattern.MatchString(e.EventType) {
		errs = append(errs, fmt.Errorf("event_type %q does not match pattern ^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$", e.EventType))
	}
	if _, ok := validSources[e.EventSource]; !ok {
		errs = append(errs, fmt.Errorf("event_source %q is not in the schema enum", e.EventSource))
	}
	if e.Payload == nil {
		errs = append(errs, errors.New("payload must not be nil"))
	}

	return errors.Join(errs...)
}

// ValidateBatch validates a BatchRequest before it is handed to the transport layer.
// It enforces the JSON schema constraints that cannot be expressed through struct tags alone.
func ValidateBatch(b *BatchRequest) error {
	var errs []error

	if _, err := uuid.Parse(b.CollectorID); err != nil {
		errs = append(errs, fmt.Errorf("collector_id is not a valid UUID: %w", err))
	}
	if _, err := uuid.Parse(b.TenantID); err != nil {
		errs = append(errs, fmt.Errorf("tenant_id is not a valid UUID: %w", err))
	}
	if b.EnvelopeVersion != EnvelopeVersion {
		errs = append(errs, fmt.Errorf("envelope_version must be %q, got %q", EnvelopeVersion, b.EnvelopeVersion))
	}
	if len(b.Events) == 0 {
		errs = append(errs, errors.New("events must have at least 1 item"))
	}
	if len(b.Events) > 1000 {
		errs = append(errs, fmt.Errorf("events must have at most 1000 items, got %d", len(b.Events)))
	}
	for i, ev := range b.Events {
		if err := ev.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("events[%d]: %w", i, err))
		}
	}

	return errors.Join(errs...)
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
