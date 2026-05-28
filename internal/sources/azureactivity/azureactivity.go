// Package azureactivity polls Azure Activity Logs for a subscription and
// converts each log entry to a canonical envelope event.
//
// Read-only API calls only:
//   - ActivityLogs.List (GET /subscriptions/{id}/providers/microsoft.insights/eventtypes/management/values)
//
// The collector never calls any Azure write API and never stores credentials on
// disk. Authentication supports two modes, controlled by AzureActivityConfig:
//
//  1. Client-secret (service principal): TenantID, ClientID, ClientSecret
//     populated from OPERITAS_AZURE_CLIENT_ID / OPERITAS_AZURE_CLIENT_SECRET.
//  2. Managed Identity (preferred in AKS with Azure Workload Identity):
//     ClientID is set to the managed-identity client ID; no client secret.
//     Controlled by UseWorkloadIdentity: true.
//
// Both modes use azidentity from the official Azure SDK for Go.
// The ARM endpoint is always the Azure public cloud (management.azure.com).
// Only subscriptions in EU-resident tenants should be configured here; the
// collector does not validate tenant geography, but the EU-only requirement
// applies to all customer data (manifest §8, hard failure rule 1).
//
// Checkpoint: the last event timestamp is persisted to CursorPath under
// /var/lib/operitas/ so restarts skip already-seen events.
package azureactivity

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/ptrs"
	"operitas.eu/collector/internal/redact"
	internalrt "operitas.eu/collector/internal/runtime"
)

// Source polls Azure Activity Logs and emits canonical events.
type Source struct {
	cfg        config.AzureActivityConfig
	client     *armmonitor.ActivityLogsClient
	redact     *redact.Redactor
	emit       func(envelope.Event)
	cursorPath string
	// lastEventTime is the high-water-mark timestamp for the polling window.
	// It is persisted to cursorPath across restarts.
	lastEventTime time.Time
}

// New constructs an AzureActivity source. It authenticates using either
// client-secret credentials or Azure Workload Identity based on the config.
//
// The armmonitor.ActivityLogsClient only calls the Azure Resource Manager
// read endpoint: GET .../eventtypes/management/values — no write API is
// reachable through this client.
func New(cfg config.AzureActivityConfig, r *redact.Redactor, emit func(envelope.Event)) (*Source, error) {
	cred, err := buildCredential(cfg)
	if err != nil {
		return nil, fmt.Errorf("azureactivity: build credential: %w", err)
	}

	// ClientFactory wraps the Azure Resource Manager API. We pass nil options
	// so the SDK uses its default retry policy and the global ARM endpoint.
	// EU data residency is enforced by the subscription/tenant ID the customer
	// configures — the ARM management plane itself is global but processes no
	// customer event data, only audit log metadata.
	factory, err := armmonitor.NewClientFactory(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azureactivity: new client factory: %w", err)
	}

	s := &Source{
		cfg:        cfg,
		client:     factory.NewActivityLogsClient(),
		redact:     r,
		emit:       emit,
		cursorPath: cfg.CursorPath,
	}
	s.loadCursor()
	return s, nil
}

// loadCursor reads the persisted high-water-mark from disk. If absent or
// unreadable, the source defaults to polling the last PollLookback window.
func (s *Source) loadCursor() {
	if s.cursorPath == "" {
		return
	}
	data, err := os.ReadFile(s.cursorPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("azureactivity: cursor read failed; starting from lookback window",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("azureactivity: cursor parse failed; starting from lookback window",
			"path", s.cursorPath, "err", err)
		return
	}
	s.lastEventTime = t
}

func (s *Source) writeCursor() {
	if s.cursorPath == "" || s.lastEventTime.IsZero() {
		return
	}
	tmp := s.cursorPath + ".tmp"
	val := s.lastEventTime.UTC().Format(time.RFC3339Nano)
	if err := os.WriteFile(tmp, []byte(val), 0o600); err != nil {
		slog.Warn("azureactivity: cursor write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("azureactivity: cursor rename failed", "err", err)
	}
}

// Run polls Activity Logs on the configured interval until ctx is cancelled.
func (s *Source) Run(ctx context.Context) error {
	slog.Info("azureactivity source started",
		"subscription_id", s.cfg.SubscriptionID,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "azureactivity", s.poll)
}

// poll fetches Activity Log entries since the last high-water mark (or the
// configured PollLookback if no cursor exists) and emits a canonical event
// for each entry. It advances the cursor to the latest event timestamp.
func (s *Source) poll(ctx context.Context) error {
	now := time.Now().UTC()
	from := s.lastEventTime
	if from.IsZero() {
		from = now.Add(-s.cfg.PollLookback)
	}

	// Azure Activity Logs API uses OData filter syntax.
	// eventTimestamp is an ISO8601 datetime. We use ge (>=) for the start of
	// our window and lt (<) for now to avoid an open-ended query.
	// See: https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log
	filter := fmt.Sprintf("eventTimestamp ge '%s' and eventTimestamp lt '%s'",
		from.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)

	slog.Debug("azureactivity: polling",
		"subscription_id", s.cfg.SubscriptionID,
		"filter_from", from.Format(time.RFC3339),
		"filter_to", now.Format(time.RFC3339),
	)

	pager := s.client.NewListPager(filter, nil)
	var highWater time.Time
	var count int

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("azureactivity: list activity logs: %w", err)
		}

		for _, entry := range page.Value {
			ev, ok := s.normalizeEntry(entry)
			if !ok {
				continue
			}
			s.emit(ev)
			count++
			if ev.OccurredAt.After(highWater) {
				highWater = ev.OccurredAt
			}
		}
	}

	if !highWater.IsZero() && highWater.After(s.lastEventTime) {
		// Advance cursor one nanosecond past the last seen event to exclude it
		// on the next poll without losing events at the same timestamp boundary.
		s.lastEventTime = highWater.Add(time.Nanosecond)
		s.writeCursor()
	}

	slog.Debug("azureactivity: poll complete", "events_emitted", count)
	return nil
}

// normalizeEntry converts a single Azure Activity Log entry to a canonical
// envelope event. Returns (event, false) when the entry should be skipped
// (e.g. missing timestamp).
func (s *Source) normalizeEntry(entry *armmonitor.EventData) (envelope.Event, bool) {
	if entry == nil {
		return envelope.Event{}, false
	}

	// Prefer EventTimestamp; fall back to SubmissionTimestamp.
	var t time.Time
	if entry.EventTimestamp != nil {
		t = entry.EventTimestamp.UTC()
	} else if entry.SubmissionTimestamp != nil {
		t = entry.SubmissionTimestamp.UTC()
	} else {
		slog.Warn("azureactivity: entry missing timestamp; skipping")
		return envelope.Event{}, false
	}

	evType := MapEventType(entry)

	// Actor: caller from authorization section, then claims (upn/appid),
	// then HTTP request caller.
	actor := extractCaller(entry)
	var actorPtr *string
	if actor != "" {
		actorPtr = s.redact.RedactActor(ptrs.String(actor))
	}

	// Resource: the resource ID the operation targeted.
	var resource *string
	if entry.ResourceID != nil && *entry.ResourceID != "" {
		resource = ptrs.String(*entry.ResourceID)
	}

	// Build a minimal payload. Raw request/response bodies are not transmitted
	// to avoid inadvertent PII leakage (manifest §12.13).
	payload := buildPayload(entry)
	payload = s.redact.Apply(payload)

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceAzureActivity,
		Actor:       actorPtr,
		Resource:    resource,
		Payload:     payload,
	}, true
}

// buildPayload assembles the normalized payload map from an Activity Log entry.
// Only metadata fields are included — no request/response body content.
func buildPayload(entry *armmonitor.EventData) map[string]any {
	p := map[string]any{}

	if entry.OperationName != nil && entry.OperationName.Value != nil {
		p["operation"] = *entry.OperationName.Value
	}
	if entry.Status != nil && entry.Status.Value != nil {
		p["status"] = *entry.Status.Value
	}
	if entry.ResourceType != nil && entry.ResourceType.Value != nil {
		p["resource_type"] = *entry.ResourceType.Value
	}
	if entry.ResourceGroupName != nil {
		p["resource_group"] = *entry.ResourceGroupName
	}
	if entry.SubscriptionID != nil {
		p["subscription_id"] = *entry.SubscriptionID
	}
	if entry.CorrelationID != nil {
		p["correlation_id"] = *entry.CorrelationID
	}
	if entry.Level != nil {
		p["level"] = string(*entry.Level)
	}
	if entry.Category != nil && entry.Category.Value != nil {
		p["category"] = *entry.Category.Value
	}

	return p
}

// extractCaller returns the best available caller identity from the entry.
// It checks, in order: Caller field (ARM-populated UPN/SPN), claims.upn,
// claims.appid, httpRequest.clientIpAddress (redacted downstream).
// Returns "" if none found.
func extractCaller(entry *armmonitor.EventData) string {
	// Caller is the ARM-level "who made this request" field — UPN or SPN.
	if entry.Caller != nil && *entry.Caller != "" {
		return *entry.Caller
	}
	// Claims is map[string]*string in the v0.12 SDK.
	if entry.Claims != nil {
		if upnPtr, ok := entry.Claims["upn"]; ok && upnPtr != nil && *upnPtr != "" {
			return *upnPtr
		}
		if appidPtr, ok := entry.Claims["appid"]; ok && appidPtr != nil && *appidPtr != "" {
			return *appidPtr
		}
	}
	if entry.HTTPRequest != nil && entry.HTTPRequest.ClientIPAddress != nil {
		return *entry.HTTPRequest.ClientIPAddress
	}
	return ""
}

// MapEventType converts an Azure Activity Log entry to a canonical event type
// from manifest §4.5. Exported for testing.
//
// The mapping uses the OperationName value (e.g.
// "Microsoft.Compute/virtualMachines/write") and the Status value
// ("Succeeded", "Failed", "Started").
func MapEventType(entry *armmonitor.EventData) string {
	if entry == nil {
		return "change.iac_applied"
	}

	var operation, status string
	if entry.OperationName != nil && entry.OperationName.Value != nil {
		operation = strings.ToLower(*entry.OperationName.Value)
	}
	if entry.Status != nil && entry.Status.Value != nil {
		status = strings.ToLower(*entry.Status.Value)
	}

	// Authorization / policy events.
	if contains(operation, "roleassignment") || contains(operation, "roledefinition") {
		if status == "failed" {
			return "auth.mfa_failed"
		}
		return "auth.role_assumed"
	}
	if contains(operation, "policyassignment") || contains(operation, "policydefinition") {
		return "change.iac_applied"
	}
	if contains(operation, "signin") || contains(operation, "login") {
		if status == "failed" {
			return "auth.mfa_failed"
		}
		return "auth.privileged_access"
	}

	// Deploy / infrastructure write events.
	if hasSuffix(operation, "/write") || hasSuffix(operation, "/create") {
		if status == "started" || status == "accepted" {
			return "deploy.started"
		}
		if status == "failed" {
			return "deploy.failed"
		}
		return "deploy.completed"
	}
	if hasSuffix(operation, "/delete") {
		if status == "started" || status == "accepted" {
			return "deploy.started"
		}
		return "deploy.completed"
	}
	if hasSuffix(operation, "/action") {
		// Actions like start/restart/stop are operational change events.
		return "change.iac_applied"
	}

	// Read operations on data resources — flag as data.bulk_access.
	if hasSuffix(operation, "/read") || hasSuffix(operation, "/list") {
		if containsAny(operation, []string{"storageaccount", "keyvault", "datalake", "blob"}) {
			return "data.bulk_access"
		}
	}

	// Alert / policy compliance events.
	if contains(operation, "alert") || contains(operation, "securityalert") {
		return "monitor.alert"
	}

	return "change.iac_applied"
}

// buildCredential constructs an Azure credential chain. The chain is tried in
// order: Workload Identity (if configured), client secret (if configured),
// managed identity (fallback). The azcore.TokenCredential interface is what
// NewChainedTokenCredential accepts in the SDK v1.x.
func buildCredential(cfg config.AzureActivityConfig) (*azidentity.ChainedTokenCredential, error) {
	var creds []azcore.TokenCredential

	if cfg.UseWorkloadIdentity {
		wic, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
			ClientID: cfg.ClientID,
			TenantID: cfg.TenantID,
		})
		if err != nil {
			return nil, fmt.Errorf("workload identity credential: %w", err)
		}
		creds = append(creds, wic)
	} else if cfg.ClientSecret != "" {
		spc, err := azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("client secret credential: %w", err)
		}
		creds = append(creds, spc)
	}

	// Managed identity fallback — zero config in AKS with system-assigned identity.
	// When cfg.ClientID is empty, the SDK uses the system-assigned identity.
	opts := &azidentity.ManagedIdentityCredentialOptions{}
	if cfg.ClientID != "" {
		opts.ID = azidentity.ClientID(cfg.ClientID)
	}
	mic, err := azidentity.NewManagedIdentityCredential(opts)
	if err != nil {
		return nil, fmt.Errorf("managed identity credential: %w", err)
	}
	creds = append(creds, mic)

	chain, err := azidentity.NewChainedTokenCredential(creds, nil)
	if err != nil {
		return nil, fmt.Errorf("chained credential: %w", err)
	}
	return chain, nil
}

// NormalizeEntryForTest exposes normalizeEntry for use in external test packages.
// It constructs a minimal Source with the given Redactor and no cursor, then
// delegates to the internal normalizer. This avoids requiring Azure credentials
// in unit tests while still exercising the full mapping and redaction path.
func NormalizeEntryForTest(r *redact.Redactor, entry *armmonitor.EventData) (envelope.Event, bool) {
	s := &Source{redact: r}
	return s.normalizeEntry(entry)
}

// marshalEntry serializes an EventData entry to JSON for test fixtures.
// Used only in test helpers; not called in the hot path.
func marshalEntry(entry *armmonitor.EventData) ([]byte, error) {
	return json.Marshal(entry)
}

// contains checks if s contains substr (case-sensitive; caller must lowercase).
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// hasSuffix checks if s ends with suffix.
func hasSuffix(s, suffix string) bool {
	return strings.HasSuffix(s, suffix)
}

// containsAny checks if s contains any element of substrs.
func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
