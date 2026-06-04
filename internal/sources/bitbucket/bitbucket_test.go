package bitbucket_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/bitbucket"
)

// newTestRedactor returns a no-hash redactor suitable for tests.
func newTestRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New(false, "")
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	return r
}

// signBody computes the X-Hub-Signature-256 header value for a given secret and body.
func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// TestMapWebhookEventType verifies the X-Event-Key -> canonical event_type mapping.
func TestMapWebhookEventType(t *testing.T) {
	tests := []struct {
		eventKey string
		wantType string
		wantOK   bool
	}{
		{"repo:push", "change.merged", true},
		{"pullrequest:created", "change.opened", true},
		{"pullrequest:fulfilled", "change.merged", true},
		{"pullrequest:rejected", "change.closed", true},
		{"pullrequest:approved", "", false},
		{"pullrequest:comment_created", "", false},
		{"issue:created", "", false},
		{"", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.eventKey, func(t *testing.T) {
			got, ok := bitbucket.MapWebhookEventType(tc.eventKey)
			if ok != tc.wantOK {
				t.Errorf("MapWebhookEventType(%q) ok=%v, want ok=%v", tc.eventKey, ok, tc.wantOK)
			}
			if ok && got != tc.wantType {
				t.Errorf("MapWebhookEventType(%q) = %q, want %q", tc.eventKey, got, tc.wantType)
			}
		})
	}
}

// TestVerifySignature verifies HMAC-SHA256 signature checking (valid/invalid/missing prefix).
func TestVerifySignature(t *testing.T) {
	const secret = "test-webhook-secret"
	body := []byte(`{"event":"test"}`)
	validSig := signBody(secret, body)

	tests := []struct {
		name   string
		secret string
		body   []byte
		header string
		want   bool
	}{
		{
			name:   "valid signature",
			secret: secret,
			body:   body,
			header: validSig,
			want:   true,
		},
		{
			name:   "wrong secret",
			secret: "wrong-secret",
			body:   body,
			header: validSig,
			want:   false,
		},
		{
			name:   "tampered body",
			secret: secret,
			body:   []byte(`{"event":"tampered"}`),
			header: validSig,
			want:   false,
		},
		{
			name:   "missing sha256= prefix",
			secret: secret,
			body:   body,
			header: hex.EncodeToString(func() []byte {
				mac := hmac.New(sha256.New, []byte(secret))
				mac.Write(body)
				return mac.Sum(nil)
			}()),
			want: false,
		},
		{
			name:   "empty header",
			secret: secret,
			body:   body,
			header: "",
			want:   false,
		},
		{
			name:   "wrong prefix (v1=)",
			secret: secret,
			body:   body,
			header: "v1=" + hex.EncodeToString(func() []byte {
				mac := hmac.New(sha256.New, []byte(secret))
				mac.Write(body)
				return mac.Sum(nil)
			}()),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := bitbucket.VerifySignature(tc.secret, tc.body, tc.header)
			if got != tc.want {
				t.Errorf("VerifySignature(%q, body, %q) = %v, want %v",
					tc.secret, tc.header, got, tc.want)
			}
		})
	}
}

// TestHandleWebhook_MethodNotAllowed verifies the handler rejects non-POST requests.
func TestHandleWebhook_MethodNotAllowed(t *testing.T) {
	src := bitbucket.New(
		config.BitbucketConfig{Enabled: true},
		newTestRedactor(t),
		func(envelope.Event) {},
	)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/webhook/bitbucket", nil)
		rec := httptest.NewRecorder()
		src.HandleWebhookForTest(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: got %d, want %d", method, rec.Code, http.StatusMethodNotAllowed)
		}
	}
}

// TestHandleWebhook_AuthRejection verifies the handler rejects requests with
// a missing or incorrect HMAC signature.
func TestHandleWebhook_AuthRejection(t *testing.T) {
	const secret = "test-secret"
	body := []byte(`{"repository":{"full_name":"acme/backend"},"actor":null,"pullrequest":{"id":1,"title":"t","state":"OPEN","created_on":"2026-05-20T08:00:00.000000Z","updated_on":"2026-05-20T08:00:00.000000Z","author":null,"source":{"branch":{"name":"feat"},"repository":{"full_name":"acme/backend"}},"destination":{"branch":{"name":"main"},"repository":{"full_name":"acme/backend"}}}}`)

	src := bitbucket.New(
		config.BitbucketConfig{Enabled: true, WebhookSecret: secret},
		newTestRedactor(t),
		func(envelope.Event) {},
	)

	tests := []struct {
		name   string
		header string
	}{
		{"no signature header", ""},
		{"wrong secret", signBody("wrong", body)},
		{"garbage header", "sha256=notvalidhex"},
		{"missing prefix", hex.EncodeToString(func() []byte {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			return mac.Sum(nil)
		}())},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/webhook/bitbucket", bytes.NewReader(body))
			req.Header.Set("X-Event-Key", "pullrequest:created")
			if tc.header != "" {
				req.Header.Set("X-Hub-Signature-256", tc.header)
			}
			rec := httptest.NewRecorder()
			src.HandleWebhookForTest(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s: got %d, want %d", tc.name, rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

// TestHandleWebhook_ValidPayload verifies a well-formed pullrequest:created
// payload is accepted and emits the correct event.
func TestHandleWebhook_ValidPayload(t *testing.T) {
	const secret = "test-secret"

	fixtureBody, err := os.ReadFile("testdata/pr_created.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sig := signBody(secret, fixtureBody)

	var emitted []envelope.Event
	src := bitbucket.New(
		config.BitbucketConfig{Enabled: true, WebhookSecret: secret},
		newTestRedactor(t),
		func(ev envelope.Event) { emitted = append(emitted, ev) },
	)

	req := httptest.NewRequest(http.MethodPost, "/webhook/bitbucket", bytes.NewReader(fixtureBody))
	req.Header.Set("X-Event-Key", "pullrequest:created")
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	src.HandleWebhookForTest(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if len(emitted) != 1 {
		t.Fatalf("got %d emitted events, want 1", len(emitted))
	}

	ev := emitted[0]
	if ev.EventSource != envelope.SourceBitbucket {
		t.Errorf("EventSource = %q, want %q", ev.EventSource, envelope.SourceBitbucket)
	}
	if ev.EventType != "change.opened" {
		t.Errorf("EventType = %q, want change.opened", ev.EventType)
	}
	if ev.Resource == nil || *ev.Resource != "acme/backend#42" {
		t.Errorf("Resource = %v, want \"acme/backend#42\"", ev.Resource)
	}
	if ev.OccurredAt.IsZero() {
		t.Error("OccurredAt is zero")
	}
	if ev.OccurredAt.Location() != time.UTC {
		t.Errorf("OccurredAt timezone = %v, want UTC", ev.OccurredAt.Location())
	}
	if ev.Payload == nil {
		t.Error("Payload is nil")
	}
	// Actor must exist and must have been passed through redaction (no raw email leak).
	if ev.Actor == nil {
		t.Error("Actor is nil, expected a redacted actor")
	}
	if *ev.Actor == "" {
		t.Error("Actor is empty string after redaction")
	}
	// The actor nickname "janedev" contains no PII so it should pass through unchanged.
	if *ev.Actor != "janedev" {
		t.Errorf("Actor = %q, want \"janedev\"", *ev.Actor)
	}
}

// TestHandleWebhook_NoSecretSkipsVerification verifies that when WebhookSecret
// is empty, the handler accepts any request (useful in dev/test environments).
func TestHandleWebhook_NoSecretSkipsVerification(t *testing.T) {
	body := []byte(`{"repository":{"full_name":"acme/backend","name":"backend"},"actor":{"display_name":"Bob","nickname":"bob"},"pullrequest":{"id":7,"title":"chore","state":"OPEN","created_on":"2026-05-20T09:00:00.000000Z","updated_on":"2026-05-20T09:00:00.000000Z","author":{"display_name":"Bob","nickname":"bob"},"source":{"branch":{"name":"fix/typo"},"repository":{"full_name":"acme/backend"}},"destination":{"branch":{"name":"main"},"repository":{"full_name":"acme/backend"}}}}`)

	var emitted []envelope.Event
	src := bitbucket.New(
		config.BitbucketConfig{Enabled: true, WebhookSecret: ""},
		newTestRedactor(t),
		func(ev envelope.Event) { emitted = append(emitted, ev) },
	)

	req := httptest.NewRequest(http.MethodPost, "/webhook/bitbucket", bytes.NewReader(body))
	req.Header.Set("X-Event-Key", "pullrequest:created")
	// No X-Hub-Signature-256 header — should be accepted when secret is empty.
	rec := httptest.NewRecorder()
	src.HandleWebhookForTest(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if len(emitted) != 1 {
		t.Fatalf("got %d events, want 1", len(emitted))
	}
}

// TestHandleWebhook_UnsupportedEventKey verifies that unsupported event keys
// are silently dropped (204 returned, no events emitted).
func TestHandleWebhook_UnsupportedEventKey(t *testing.T) {
	body := []byte(`{"repository":{"full_name":"acme/backend"}}`)

	var emitted []envelope.Event
	src := bitbucket.New(
		config.BitbucketConfig{Enabled: true, WebhookSecret: ""},
		newTestRedactor(t),
		func(ev envelope.Event) { emitted = append(emitted, ev) },
	)

	req := httptest.NewRequest(http.MethodPost, "/webhook/bitbucket", bytes.NewReader(body))
	req.Header.Set("X-Event-Key", "pullrequest:comment_created")
	rec := httptest.NewRecorder()
	src.HandleWebhookForTest(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}
	if len(emitted) != 0 {
		t.Errorf("got %d events for unsupported key, want 0", len(emitted))
	}
}

// TestHandleWebhook_AllPREventTypes exercises all three PR event keys and
// verifies correct event type mapping.
func TestHandleWebhook_AllPREventTypes(t *testing.T) {
	prBody := func(state, eventKey string) []byte {
		payload := map[string]any{
			"repository": map[string]any{"full_name": "acme/backend", "name": "backend"},
			"actor":      map[string]any{"display_name": "Alice", "nickname": "alice"},
			"pullrequest": map[string]any{
				"id":         99,
				"title":      "some PR",
				"state":      state,
				"created_on": "2026-05-21T10:00:00.000000Z",
				"updated_on": "2026-05-21T10:01:00.000000Z",
				"author":     map[string]any{"display_name": "Alice", "nickname": "alice"},
				"source": map[string]any{
					"branch":     map[string]any{"name": "feature/x"},
					"repository": map[string]any{"full_name": "acme/backend"},
				},
				"destination": map[string]any{
					"branch":     map[string]any{"name": "main"},
					"repository": map[string]any{"full_name": "acme/backend"},
				},
			},
		}
		b, _ := json.Marshal(payload)
		return b
	}

	tests := []struct {
		eventKey string
		prState  string
		wantType string
	}{
		{"pullrequest:created", "OPEN", "change.opened"},
		{"pullrequest:fulfilled", "MERGED", "change.merged"},
		{"pullrequest:rejected", "DECLINED", "change.closed"},
	}

	for _, tc := range tests {
		t.Run(tc.eventKey, func(t *testing.T) {
			body := prBody(tc.prState, tc.eventKey)

			var emitted []envelope.Event
			src := bitbucket.New(
				config.BitbucketConfig{Enabled: true, WebhookSecret: ""},
				newTestRedactor(t),
				func(ev envelope.Event) { emitted = append(emitted, ev) },
			)

			req := httptest.NewRequest(http.MethodPost, "/webhook/bitbucket", bytes.NewReader(body))
			req.Header.Set("X-Event-Key", tc.eventKey)
			rec := httptest.NewRecorder()
			src.HandleWebhookForTest(rec, req)

			if rec.Code != http.StatusNoContent {
				t.Fatalf("got %d, want %d", rec.Code, http.StatusNoContent)
			}
			if len(emitted) != 1 {
				t.Fatalf("got %d events, want 1", len(emitted))
			}
			if emitted[0].EventType != tc.wantType {
				t.Errorf("EventType = %q, want %q", emitted[0].EventType, tc.wantType)
			}
			if err := emitted[0].Validate(); err != nil {
				t.Errorf("event failed envelope validation: %v", err)
			}
		})
	}
}

// TestHandleWebhook_Push verifies repo:push is normalized correctly.
func TestHandleWebhook_Push(t *testing.T) {
	body := []byte(`{
		"repository": {"full_name": "acme/backend", "name": "backend"},
		"actor": {"display_name": "Carol", "nickname": "carol"},
		"push": {
			"changes": [{
				"new": {
					"name": "main",
					"type": "branch",
					"target": {
						"hash": "abc1234567890",
						"date": "2026-05-22T12:00:00+00:00",
						"author": {
							"raw": "Carol <carol@example.com>",
							"user": {"display_name": "Carol", "nickname": "carol"}
						}
					}
				}
			}]
		}
	}`)

	var emitted []envelope.Event
	src := bitbucket.New(
		config.BitbucketConfig{Enabled: true, WebhookSecret: ""},
		newTestRedactor(t),
		func(ev envelope.Event) { emitted = append(emitted, ev) },
	)

	req := httptest.NewRequest(http.MethodPost, "/webhook/bitbucket", bytes.NewReader(body))
	req.Header.Set("X-Event-Key", "repo:push")
	rec := httptest.NewRecorder()
	src.HandleWebhookForTest(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if len(emitted) != 1 {
		t.Fatalf("got %d events, want 1", len(emitted))
	}

	ev := emitted[0]
	if ev.EventType != "change.merged" {
		t.Errorf("EventType = %q, want change.merged", ev.EventType)
	}
	if ev.EventSource != envelope.SourceBitbucket {
		t.Errorf("EventSource = %q, want %q", ev.EventSource, envelope.SourceBitbucket)
	}
	if ev.Resource == nil || *ev.Resource != "acme/backend" {
		t.Errorf("Resource = %v, want \"acme/backend\"", ev.Resource)
	}
	// Timestamp must come from the commit date, not time.Now.
	wantTime, _ := time.Parse(time.RFC3339, "2026-05-22T12:00:00Z")
	if !ev.OccurredAt.Equal(wantTime) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, wantTime)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event failed envelope validation: %v", err)
	}
}

// TestNormalizationRedactsEmail verifies that email addresses in actor or
// payload fields are stripped before the event is emitted.
func TestNormalizationRedactsEmail(t *testing.T) {
	// The actor nickname contains no PII but the payload title has an email.
	body := []byte(`{
		"repository": {"full_name": "acme/svc", "name": "svc"},
		"actor": {"display_name": "ops-bot", "nickname": "ops-bot"},
		"pullrequest": {
			"id": 5,
			"title": "Fix bug reported by user@example.com",
			"state": "OPEN",
			"created_on": "2026-05-23T08:00:00.000000Z",
			"updated_on": "2026-05-23T08:00:00.000000Z",
			"author": {"display_name": "ops-bot", "nickname": "ops-bot"},
			"source": {
				"branch": {"name": "bugfix"},
				"repository": {"full_name": "acme/svc"}
			},
			"destination": {
				"branch": {"name": "main"},
				"repository": {"full_name": "acme/svc"}
			}
		}
	}`)

	var emitted []envelope.Event
	src := bitbucket.New(
		config.BitbucketConfig{Enabled: true, WebhookSecret: ""},
		newTestRedactor(t),
		func(ev envelope.Event) { emitted = append(emitted, ev) },
	)

	req := httptest.NewRequest(http.MethodPost, "/webhook/bitbucket", bytes.NewReader(body))
	req.Header.Set("X-Event-Key", "pullrequest:created")
	rec := httptest.NewRecorder()
	src.HandleWebhookForTest(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("got %d, want %d", rec.Code, http.StatusNoContent)
	}
	if len(emitted) != 1 {
		t.Fatalf("got %d events, want 1", len(emitted))
	}

	ev := emitted[0]
	title, _ := ev.Payload["title"].(string)
	if title == "" {
		t.Fatal("payload title is missing")
	}
	if title == "Fix bug reported by user@example.com" {
		t.Errorf("payload title still contains raw email address; redaction failed: %q", title)
	}
	if want := "Fix bug reported by [redacted]"; title != want {
		t.Errorf("payload title = %q, want %q", title, want)
	}
}
