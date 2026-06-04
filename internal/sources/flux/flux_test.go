package flux_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/flux"
)

func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

// TestMapReason verifies every documented reason-to-event_type mapping.
func TestMapReason(t *testing.T) {
	tests := []struct {
		reason string
		want   string
	}{
		// Successful reconciliation.
		{"ReconciliationSucceeded", "deploy.completed"},
		{"ArtifactUpToDate", "deploy.completed"},
		// Failures.
		{"ReconciliationFailed", "deploy.failed"},
		{"BuildFailed", "deploy.failed"},
		{"HealthCheckFailed", "deploy.failed"},
		{"DependencyNotReady", "deploy.failed"},
		// In-progress.
		{"Progressing", "deploy.started"},
		{"ProgressingWithRetry", "deploy.started"},
		// Configuration changes.
		{"Suspended", "change.iac_applied"},
		{"Resumed", "change.iac_applied"},
		// Unknown reasons fall back to deploy.completed (forward-compat).
		{"SomeNewReason", "deploy.completed"},
		{"", "deploy.completed"},
	}

	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			got := flux.MapReason(tc.reason)
			if got != tc.want {
				t.Errorf("MapReason(%q) = %q, want %q", tc.reason, got, tc.want)
			}
		})
	}
}

// TestWebhookSecret_Valid checks that a correct Gotk-Webhook-Secret is accepted.
func TestWebhookSecret_Valid(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.FluxConfig{
		Enabled:       true,
		WebhookSecret: "super-secret-flux",
	}

	var emitted []envelope.Event
	src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body := makeFluxPayload(t, "ReconciliationSucceeded", "Kustomization", "flux-system", "apps")

	req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(body))
	req.Header.Set("Gotk-Webhook-Secret", "super-secret-flux")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d (body: %s)", w.Code, w.Body.String())
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}
}

// TestWebhookSecret_Invalid checks that a wrong Gotk-Webhook-Secret is rejected with 401.
func TestWebhookSecret_Invalid(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.FluxConfig{
		Enabled:       true,
		WebhookSecret: "super-secret-flux",
	}

	var emitted []envelope.Event
	src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body := makeFluxPayload(t, "ReconciliationSucceeded", "Kustomization", "flux-system", "apps")

	req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(body))
	req.Header.Set("Gotk-Webhook-Secret", "wrong-secret")
	w := httptest.NewRecorder()

	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if len(emitted) != 0 {
		t.Errorf("expected no events on auth failure, got %d", len(emitted))
	}
}

// TestWebhookSecret_Missing checks that an absent header is rejected when a secret is configured.
func TestWebhookSecret_Missing(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.FluxConfig{
		Enabled:       true,
		WebhookSecret: "super-secret-flux",
	}

	var emitted []envelope.Event
	src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body := makeFluxPayload(t, "ReconciliationSucceeded", "Kustomization", "flux-system", "apps")

	req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(body))
	// Intentionally no Gotk-Webhook-Secret header.
	w := httptest.NewRecorder()

	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestWebhookSecret_NoConfiguredSecret checks that requests are accepted when
// WebhookSecret is empty (network-isolation auth model).
func TestWebhookSecret_NoConfiguredSecret(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.FluxConfig{
		Enabled:       true,
		WebhookSecret: "", // no secret configured
	}

	var emitted []envelope.Event
	src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	body := makeFluxPayload(t, "ReconciliationSucceeded", "Kustomization", "flux-system", "apps")

	req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(body))
	w := httptest.NewRecorder()

	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Errorf("expected 1 event, got %d", len(emitted))
	}
}

// TestWebhookHandler_MethodNotAllowed checks that non-POST methods are rejected.
func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.FluxConfig{Enabled: true}
	src := flux.New(cfg, r, func(e envelope.Event) {})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/webhook/flux", nil)
			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: expected 405, got %d", method, w.Code)
			}
		})
	}
}

// TestNormalization_AllReasonMappings exercises every reason through the full
// handler pipeline and verifies the emitted event_type.
func TestNormalization_AllReasonMappings(t *testing.T) {
	tests := []struct {
		reason string
		wantEv string
	}{
		{"ReconciliationSucceeded", "deploy.completed"},
		{"ArtifactUpToDate", "deploy.completed"},
		{"ReconciliationFailed", "deploy.failed"},
		{"BuildFailed", "deploy.failed"},
		{"HealthCheckFailed", "deploy.failed"},
		{"DependencyNotReady", "deploy.failed"},
		{"Progressing", "deploy.started"},
		{"ProgressingWithRetry", "deploy.started"},
		{"Suspended", "change.iac_applied"},
		{"Resumed", "change.iac_applied"},
	}

	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			r := newTestRedactor(t)
			cfg := config.FluxConfig{Enabled: true}

			var emitted []envelope.Event
			src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

			body := makeFluxPayload(t, tc.reason, "Kustomization", "production", "infra")

			req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(body))
			w := httptest.NewRecorder()
			src.HandleWebhookForTest(w, req)

			if w.Code != http.StatusNoContent {
				t.Fatalf("expected 204, got %d", w.Code)
			}
			if len(emitted) != 1 {
				t.Fatalf("expected 1 event, got %d", len(emitted))
			}
			if emitted[0].EventType != tc.wantEv {
				t.Errorf("event_type = %q, want %q", emitted[0].EventType, tc.wantEv)
			}
			if emitted[0].EventSource != envelope.SourceFlux {
				t.Errorf("event_source = %q, want flux", emitted[0].EventSource)
			}
		})
	}
}

// TestNormalization_FixtureKustomizationSucceeded uses the checked-in fixture to
// validate field-by-field normalization from a realistic notification-controller payload.
func TestNormalization_FixtureKustomizationSucceeded(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "fixtures", "kustomization_succeeded.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	r := newTestRedactor(t)
	cfg := config.FluxConfig{Enabled: true}

	var emitted []envelope.Event
	src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(body))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body: %s)", w.Code, w.Body.String())
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	ev := emitted[0]

	// event_type
	if ev.EventType != "deploy.completed" {
		t.Errorf("event_type = %q, want deploy.completed", ev.EventType)
	}

	// event_source
	if ev.EventSource != envelope.SourceFlux {
		t.Errorf("event_source = %q, want flux", ev.EventSource)
	}

	// occurred_at: must be UTC, non-zero, matching the fixture timestamp.
	wantTime := time.Date(2026, 5, 7, 8, 14, 2, 0, time.UTC)
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("occurred_at = %v, want %v", ev.OccurredAt, wantTime)
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at must be UTC, got %v", ev.OccurredAt.Location())
	}

	// resource: namespace/kind/name
	if ev.Resource == nil {
		t.Fatal("resource must not be nil")
	}
	if *ev.Resource != "flux-system/Kustomization/apps" {
		t.Errorf("resource = %q, want flux-system/Kustomization/apps", *ev.Resource)
	}

	// actor: kustomize-controller (the reporting controller)
	if ev.Actor == nil {
		t.Fatal("actor must not be nil for events with a reporting controller")
	}
	if *ev.Actor != "kustomize-controller" {
		t.Errorf("actor = %q, want kustomize-controller", *ev.Actor)
	}

	// payload: required keys present
	for _, key := range []string{"reason", "severity", "message", "kind", "namespace", "name", "controller"} {
		if _, ok := ev.Payload[key]; !ok {
			t.Errorf("payload missing key %q", key)
		}
	}

	// payload: revision from metadata
	if rev, ok := ev.Payload["revision"]; !ok || rev == "" {
		t.Errorf("payload[revision] missing or empty, got %v", rev)
	}

	// Validate the event against the envelope schema.
	if err := ev.Validate(); err != nil {
		t.Errorf("envelope.Event.Validate() failed: %v", err)
	}
}

// TestNormalization_HelmReleaseFailed checks a HelmRelease failure event.
func TestNormalization_HelmReleaseFailed(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.FluxConfig{Enabled: true}

	var emitted []envelope.Event
	src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload, err := json.Marshal(map[string]any{
		"involvedObject": map[string]any{
			"kind":       "HelmRelease",
			"namespace":  "monitoring",
			"name":       "prometheus-stack",
			"apiVersion": "helm.toolkit.fluxcd.io/v2",
		},
		"severity":            "error",
		"timestamp":           "2026-05-10T12:00:00Z",
		"message":             "Helm upgrade failed: rendered manifests contain a resource that already exists",
		"reason":              "ReconciliationFailed",
		"metadata":            map[string]string{"revision": "chart-version/1.2.3"},
		"reportingController": "helm-controller",
		"reportingInstance":   "helm-controller-abc-def",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	ev := emitted[0]

	if ev.EventType != "deploy.failed" {
		t.Errorf("event_type = %q, want deploy.failed", ev.EventType)
	}
	if ev.EventSource != envelope.SourceFlux {
		t.Errorf("event_source = %q, want flux", ev.EventSource)
	}
	if ev.Resource == nil || *ev.Resource != "monitoring/HelmRelease/prometheus-stack" {
		t.Errorf("resource = %v, want monitoring/HelmRelease/prometheus-stack", ev.Resource)
	}
	if ev.Actor == nil || *ev.Actor != "helm-controller" {
		t.Errorf("actor = %v, want helm-controller", ev.Actor)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("envelope.Event.Validate() failed: %v", err)
	}
}

// TestNormalization_TimestampFallback checks that a missing timestamp falls back
// to time.Now() and does not produce a zero occurred_at.
func TestNormalization_TimestampFallback(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.FluxConfig{Enabled: true}

	var emitted []envelope.Event
	src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	before := time.Now().UTC().Add(-time.Second)

	payload, err := json.Marshal(map[string]any{
		"involvedObject": map[string]any{
			"kind":      "GitRepository",
			"namespace": "flux-system",
			"name":      "main",
		},
		"severity": "info",
		// timestamp intentionally omitted
		"reason":              "ArtifactUpToDate",
		"message":             "stored artifact for revision",
		"reportingController": "source-controller",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	after := time.Now().UTC().Add(time.Second)
	ev := emitted[0]

	if ev.OccurredAt.IsZero() {
		t.Error("occurred_at must not be zero when timestamp is absent")
	}
	if ev.OccurredAt.Before(before) || ev.OccurredAt.After(after) {
		t.Errorf("occurred_at %v outside expected range [%v, %v]", ev.OccurredAt, before, after)
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred_at must be UTC, got %v", ev.OccurredAt.Location())
	}
}

// TestNormalization_PIIRedaction verifies that email addresses in message/payload
// are stripped before the event is emitted.
func TestNormalization_PIIRedaction(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.FluxConfig{Enabled: true}

	var emitted []envelope.Event
	src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	payload, err := json.Marshal(map[string]any{
		"involvedObject": map[string]any{
			"kind":      "Kustomization",
			"namespace": "production",
			"name":      "apps",
		},
		"severity":            "error",
		"timestamp":           "2026-06-01T10:00:00Z",
		"reason":              "ReconciliationFailed",
		"message":             "contact admin@example.com for details",
		"reportingController": "kustomize-controller",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	ev := emitted[0]

	msg, _ := ev.Payload["message"].(string)
	if msg == "" {
		t.Fatal("payload[message] missing")
	}
	if contains(msg, "admin@example.com") {
		t.Errorf("payload[message] still contains raw email address: %q", msg)
	}
}

// TestNormalization_ResourcePartial checks that buildResource handles partial
// involvedObject gracefully (no leading/trailing slashes).
func TestNormalization_ResourcePartial(t *testing.T) {
	r := newTestRedactor(t)
	cfg := config.FluxConfig{Enabled: true}

	var emitted []envelope.Event
	src := flux.New(cfg, r, func(e envelope.Event) { emitted = append(emitted, e) })

	// Omit namespace to exercise partial resource construction.
	payload, err := json.Marshal(map[string]any{
		"involvedObject": map[string]any{
			"kind": "Kustomization",
			"name": "apps",
			// namespace deliberately absent
		},
		"severity":  "info",
		"timestamp": "2026-06-01T10:00:00Z",
		"reason":    "ReconciliationSucceeded",
		"message":   "ok",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook/flux", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	src.HandleWebhookForTest(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if len(emitted) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitted))
	}

	ev := emitted[0]

	// Resource must be non-nil and must not contain a leading slash.
	if ev.Resource == nil {
		t.Fatal("resource must not be nil")
	}
	res := *ev.Resource
	if len(res) > 0 && res[0] == '/' {
		t.Errorf("resource has leading slash: %q", res)
	}
	if len(res) > 0 && res[len(res)-1] == '/' {
		t.Errorf("resource has trailing slash: %q", res)
	}
}

// makeFluxPayload builds a minimal valid notification-controller Event payload.
func makeFluxPayload(t *testing.T, reason, kind, namespace, name string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"involvedObject": map[string]any{
			"kind":       kind,
			"namespace":  namespace,
			"name":       name,
			"apiVersion": "kustomize.toolkit.fluxcd.io/v1",
		},
		"severity":  "info",
		"timestamp": "2026-05-07T08:14:02Z",
		"message":   "Reconciliation finished",
		"reason":    reason,
		"metadata": map[string]string{
			"revision": "main@sha1:abc1234",
		},
		"reportingController": "kustomize-controller",
		"reportingInstance":   "kustomize-controller-abc-def",
	})
	if err != nil {
		t.Fatalf("marshal flux payload: %v", err)
	}
	return b
}

// contains is a helper to avoid importing strings in the test file.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
