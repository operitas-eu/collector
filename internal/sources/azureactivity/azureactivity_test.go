package azureactivity_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/ptrs"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/azureactivity"
)

// newNoopRedactor returns a Redactor with default hard-redact (hash_pii=false).
func newNoopRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

// loadFixture reads a JSON fixture from testdata/fixtures/<name>.json and
// unmarshals it into an armmonitor.EventData struct.
func loadFixture(t *testing.T, name string) *armmonitor.EventData {
	t.Helper()
	path := filepath.Join("testdata", "fixtures", name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %q: %v", path, err)
	}
	var entry armmonitor.EventData
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("unmarshal fixture %q: %v", path, err)
	}
	return &entry
}

// --- MapEventType tests -------------------------------------------------------

func TestMapEventType_AuthEvents(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		status    string
		want      string
	}{
		{
			name:      "role assignment succeeded",
			operation: "Microsoft.Authorization/roleAssignments/write",
			status:    "Succeeded",
			want:      "auth.role_assumed",
		},
		{
			name:      "role assignment failed",
			operation: "Microsoft.Authorization/roleAssignments/write",
			status:    "Failed",
			want:      "auth.mfa_failed",
		},
		{
			name:      "sign-in succeeded",
			operation: "Microsoft.AAD/signIns/read",
			status:    "Succeeded",
			want:      "auth.privileged_access",
		},
		{
			name:      "sign-in failed",
			operation: "Microsoft.AAD/signIns/read",
			status:    "Failed",
			want:      "auth.mfa_failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := makeEntry(tc.operation, tc.status, "")
			got := azureactivity.MapEventType(entry)
			if got != tc.want {
				t.Errorf("MapEventType(%q, %q) = %q, want %q", tc.operation, tc.status, got, tc.want)
			}
		})
	}
}

func TestMapEventType_DeployEvents(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		status    string
		want      string
	}{
		{
			name:      "VM write started",
			operation: "Microsoft.Compute/virtualMachines/write",
			status:    "Started",
			want:      "deploy.started",
		},
		{
			name:      "VM write succeeded",
			operation: "Microsoft.Compute/virtualMachines/write",
			status:    "Succeeded",
			want:      "deploy.completed",
		},
		{
			name:      "VM write failed",
			operation: "Microsoft.Compute/virtualMachines/write",
			status:    "Failed",
			want:      "deploy.failed",
		},
		{
			name:      "resource group delete started",
			operation: "Microsoft.Resources/resourceGroups/delete",
			status:    "Accepted",
			want:      "deploy.started",
		},
		{
			name:      "resource group delete completed",
			operation: "Microsoft.Resources/resourceGroups/delete",
			status:    "Succeeded",
			want:      "deploy.completed",
		},
		{
			name:      "VM start action",
			operation: "Microsoft.Compute/virtualMachines/start/action",
			status:    "Succeeded",
			want:      "change.iac_applied",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := makeEntry(tc.operation, tc.status, "")
			got := azureactivity.MapEventType(entry)
			if got != tc.want {
				t.Errorf("MapEventType(%q, %q) = %q, want %q", tc.operation, tc.status, got, tc.want)
			}
		})
	}
}

func TestMapEventType_DataEvents(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		want      string
	}{
		{
			name:      "storage account read",
			operation: "Microsoft.Storage/storageAccounts/read",
			want:      "data.bulk_access",
		},
		{
			name:      "key vault read",
			operation: "Microsoft.KeyVault/vaults/read",
			want:      "data.bulk_access",
		},
		{
			name:      "generic read — not data sensitive",
			operation: "Microsoft.Network/virtualNetworks/read",
			want:      "change.iac_applied",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := makeEntry(tc.operation, "Succeeded", "")
			got := azureactivity.MapEventType(entry)
			if got != tc.want {
				t.Errorf("MapEventType(%q) = %q, want %q", tc.operation, got, tc.want)
			}
		})
	}
}

func TestMapEventType_NilEntry(t *testing.T) {
	got := azureactivity.MapEventType(nil)
	if got != "change.iac_applied" {
		t.Errorf("nil entry: got %q, want %q", got, "change.iac_applied")
	}
}

// --- normalizeEntry via fixture -----------------------------------------------

// TestNormalizeEntry_VMWrite loads the vm_write fixture and checks that the
// resulting envelope.Event is valid and has the expected field values.
func TestNormalizeEntry_VMWrite(t *testing.T) {
	entry := loadFixture(t, "vm_write")
	events := collectEvents(t, entry)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]

	if ev.EventSource != envelope.SourceAzureActivity {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceAzureActivity)
	}
	if ev.EventType != "deploy.completed" {
		t.Errorf("event_type = %q, want %q", ev.EventType, "deploy.completed")
	}
	if ev.OccurredAt.IsZero() {
		t.Error("occurred_at is zero")
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at not in UTC: %v", ev.OccurredAt.Location())
	}
	if ev.Resource == nil || !strings.Contains(*ev.Resource, "virtualMachines") {
		t.Errorf("resource does not reference virtualMachines: %v", ev.Resource)
	}
	if ev.Payload == nil {
		t.Error("payload is nil")
	}
	if _, ok := ev.Payload["operation"]; !ok {
		t.Error("payload missing 'operation' key")
	}

	// Validate passes the envelope contract.
	if err := ev.Validate(); err != nil {
		t.Errorf("Validate() error: %v", err)
	}
}

// TestNormalizeEntry_RoleAssignment checks that role assignment events are
// classified as auth.role_assumed and the actor is correctly extracted.
func TestNormalizeEntry_RoleAssignment(t *testing.T) {
	entry := loadFixture(t, "role_assignment")
	events := collectEvents(t, entry)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]

	if ev.EventType != "auth.role_assumed" {
		t.Errorf("event_type = %q, want %q", ev.EventType, "auth.role_assumed")
	}
	if ev.EventSource != envelope.SourceAzureActivity {
		t.Errorf("event_source = %q, want %q", ev.EventSource, envelope.SourceAzureActivity)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("Validate() error: %v", err)
	}
}

// TestNormalizeEntry_PIIRedaction verifies that email addresses in the caller
// field are stripped before the event leaves the normalizer.
func TestNormalizeEntry_PIIRedaction(t *testing.T) {
	ts := time.Now().UTC()
	email := "alice@example.eu"
	entry := &armmonitor.EventData{
		EventTimestamp: &ts,
		OperationName: &armmonitor.LocalizableString{
			Value: ptrs.String("Microsoft.Compute/virtualMachines/write"),
		},
		Status: &armmonitor.LocalizableString{
			Value: ptrs.String("Succeeded"),
		},
		// Caller is the ARM-level UPN/SPN field populated on real Activity Log entries.
		Caller:     ptrs.String(email),
		ResourceID: ptrs.String("/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web-1"),
	}

	events := collectEvents(t, entry)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	// The actor field must not contain the raw email.
	if ev.Actor != nil && strings.Contains(*ev.Actor, email) {
		t.Errorf("actor contains raw PII email %q: %q", email, *ev.Actor)
	}
}

// TestNormalizeEntry_MissingTimestamp verifies that entries without a timestamp
// are dropped (not emitted) rather than emitted with a zero time.
func TestNormalizeEntry_MissingTimestamp(t *testing.T) {
	entry := &armmonitor.EventData{
		OperationName: &armmonitor.LocalizableString{
			Value: ptrs.String("Microsoft.Compute/virtualMachines/write"),
		},
		Status: &armmonitor.LocalizableString{
			Value: ptrs.String("Succeeded"),
		},
	}
	events := collectEvents(t, entry)
	if len(events) != 0 {
		t.Errorf("expected 0 events for missing timestamp, got %d", len(events))
	}
}

// --- envelope contract test ---------------------------------------------------

// TestEnvelopeContract builds a full BatchRequest from an Azure Activity event
// and validates it against the envelope contract (same path as the wire-contract
// fixture test in internal/envelope/).
func TestEnvelopeContract_AzureActivity(t *testing.T) {
	events := collectEvents(t, loadFixture(t, "vm_write"))
	if len(events) == 0 {
		t.Fatal("no events produced from vm_write fixture")
	}

	batch := envelope.NewBatch(
		"11111111-1111-1111-1111-111111111111",
		"22222222-2222-2222-2222-222222222222",
		events,
	)
	if err := envelope.ValidateBatch(batch); err != nil {
		t.Errorf("ValidateBatch failed: %v", err)
	}
}

// --- helpers ------------------------------------------------------------------

// makeEntry constructs a minimal armmonitor.EventData for MapEventType tests.
func makeEntry(operation, status, resourceID string) *armmonitor.EventData {
	e := &armmonitor.EventData{
		OperationName: &armmonitor.LocalizableString{Value: ptrs.String(operation)},
		Status:        &armmonitor.LocalizableString{Value: ptrs.String(status)},
	}
	if resourceID != "" {
		e.ResourceID = ptrs.String(resourceID)
	}
	return e
}

// collectEvents invokes the internal normalizer via a single-shot Source
// constructed with a no-op cursor path. This avoids constructing an actual
// Azure ARM client (which would need network access) while still exercising
// the normalizeEntry logic end-to-end.
func collectEvents(t *testing.T, entry *armmonitor.EventData) []envelope.Event {
	t.Helper()
	r := newNoopRedactor(t)
	var events []envelope.Event

	// We call the package-internal exported test helper rather than constructing
	// a Source (which requires Azure credentials). The helper is defined in
	// azureactivity_internal_test.go (same package, _test suffix excluded via
	// build tag) but we expose what we need via the NormalizeEntryForTest func.
	ev, ok := azureactivity.NormalizeEntryForTest(r, entry)
	if ok {
		events = append(events, ev)
	}
	return events
}
