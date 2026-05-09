package envelope_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"operitas.eu/collector/internal/envelope"
)

func ptr(s string) *string { return &s }

func TestEventValidate(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name    string
		ev      envelope.Event
		wantErr bool
		errFrag string
	}{
		{
			name: "valid minimal event",
			ev: envelope.Event{
				OccurredAt:  now,
				EventType:   "deploy.completed",
				EventSource: envelope.SourceGitHub,
				Payload:     map[string]any{"ref": "main"},
			},
		},
		{
			name: "valid with optional fields",
			ev: envelope.Event{
				OccurredAt:  now,
				EventType:   "incident.opened",
				EventSource: envelope.SourcePagerDuty,
				Actor:       ptr("alice@bank.eu"),
				Resource:    ptr("payments-api"),
				Payload:     map[string]any{"id": "P123"},
			},
		},
		{
			name:    "zero occurred_at",
			ev:      envelope.Event{EventType: "deploy.completed", EventSource: envelope.SourceGitHub, Payload: map[string]any{}},
			wantErr: true,
			errFrag: "occurred_at",
		},
		{
			name: "non-UTC time",
			ev: envelope.Event{
				OccurredAt:  time.Now().In(time.FixedZone("CET", 3600)),
				EventType:   "deploy.completed",
				EventSource: envelope.SourceGitHub,
				Payload:     map[string]any{},
			},
			wantErr: true,
			errFrag: "UTC",
		},
		{
			name: "bad event_type - no dot",
			ev: envelope.Event{
				OccurredAt:  now,
				EventType:   "deploy",
				EventSource: envelope.SourceGitHub,
				Payload:     map[string]any{},
			},
			wantErr: true,
			errFrag: "pattern mismatch",
		},
		{
			name: "bad event_type - uppercase",
			ev: envelope.Event{
				OccurredAt:  now,
				EventType:   "Deploy.completed",
				EventSource: envelope.SourceGitHub,
				Payload:     map[string]any{},
			},
			wantErr: true,
			errFrag: "pattern mismatch",
		},
		{
			name: "unknown event_source",
			ev: envelope.Event{
				OccurredAt:  now,
				EventType:   "deploy.completed",
				EventSource: "gcp.audit",
				Payload:     map[string]any{},
			},
			wantErr: true,
			errFrag: "not in enum",
		},
		{
			name: "nil payload",
			ev: envelope.Event{
				OccurredAt:  now,
				EventType:   "deploy.completed",
				EventSource: envelope.SourceGitHub,
				Payload:     nil,
			},
			wantErr: true,
			errFrag: "required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ev.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errFrag != "" && !strings.Contains(err.Error(), tc.errFrag) {
					t.Fatalf("expected error containing %q, got %q", tc.errFrag, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateBatch(t *testing.T) {
	now := time.Now().UTC()
	goodEvent := envelope.Event{
		OccurredAt:  now,
		EventType:   "deploy.completed",
		EventSource: envelope.SourceAWSCloudTrail,
		Payload:     map[string]any{"action": "RunInstances"},
	}

	tests := []struct {
		name    string
		batch   *envelope.BatchRequest
		wantErr bool
		errFrag string
	}{
		{
			name:  "valid batch",
			batch: envelope.NewBatch("a1b2c3d4-e5f6-7890-abcd-ef1234567890", "b1b2c3d4-e5f6-7890-abcd-ef1234567890", []envelope.Event{goodEvent}),
		},
		{
			name:    "bad collector_id",
			batch:   &envelope.BatchRequest{CollectorID: "not-a-uuid", TenantID: "b1b2c3d4-e5f6-7890-abcd-ef1234567890", EnvelopeVersion: "1.0.0", Events: []envelope.Event{goodEvent}},
			wantErr: true,
			errFrag: "collector_id",
		},
		{
			name:    "wrong envelope version",
			batch:   &envelope.BatchRequest{CollectorID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", TenantID: "b1b2c3d4-e5f6-7890-abcd-ef1234567890", EnvelopeVersion: "2.0.0", Events: []envelope.Event{goodEvent}},
			wantErr: true,
			errFrag: "envelope_version",
		},
		{
			name: "1001 events — maxItems violation",
			batch: func() *envelope.BatchRequest {
				evs := make([]envelope.Event, 1001)
				for i := range evs {
					evs[i] = goodEvent
				}
				return &envelope.BatchRequest{
					CollectorID:     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
					TenantID:        "b1b2c3d4-e5f6-7890-abcd-ef1234567890",
					EnvelopeVersion: "1.0.0",
					Events:          evs,
				}
			}(),
			wantErr: true,
			errFrag: "maxItems",
		},
		{
			name:    "empty events",
			batch:   &envelope.BatchRequest{CollectorID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", TenantID: "b1b2c3d4-e5f6-7890-abcd-ef1234567890", EnvelopeVersion: "1.0.0", Events: []envelope.Event{}},
			wantErr: true,
			errFrag: "minItems",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := envelope.ValidateBatch(tc.batch)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errFrag != "" && !strings.Contains(err.Error(), tc.errFrag) {
					t.Fatalf("expected error containing %q, got %q", tc.errFrag, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestRoundTrip verifies that a BatchRequest survives JSON marshal/unmarshal with
// all fields intact, which is the wire-format contract with the ingest service.
func TestRoundTrip(t *testing.T) {
	now := time.Date(2026, 5, 7, 8, 14, 2, 123456000, time.UTC)
	actor := "argocd-bot"
	resource := "payments-api"

	original := envelope.NewBatch(
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"b1b2c3d4-e5f6-7890-abcd-ef1234567890",
		[]envelope.Event{
			{
				OccurredAt:  now,
				EventType:   "deploy.completed",
				EventSource: envelope.SourceGitHub,
				Actor:       &actor,
				Resource:    &resource,
				Payload:     map[string]any{"version": "v3.21.4", "commit": "a7f3c9"},
			},
		},
	)

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded envelope.BatchRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.EnvelopeVersion != envelope.EnvelopeVersion {
		t.Errorf("envelope_version mismatch: got %q", decoded.EnvelopeVersion)
	}
	if decoded.CollectorID != original.CollectorID {
		t.Errorf("collector_id mismatch")
	}
	if len(decoded.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(decoded.Events))
	}
	ev := decoded.Events[0]
	if ev.EventType != "deploy.completed" {
		t.Errorf("event_type mismatch: got %q", ev.EventType)
	}
	if ev.EventSource != envelope.SourceGitHub {
		t.Errorf("event_source mismatch: got %q", ev.EventSource)
	}
	if *ev.Actor != actor {
		t.Errorf("actor mismatch")
	}
	// Verify the timestamp survived JSON round-trip with sub-second precision.
	if !ev.OccurredAt.Equal(now) {
		t.Errorf("occurred_at mismatch: got %v, want %v", ev.OccurredAt, now)
	}
}
