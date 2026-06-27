// Package opsgenie collects incident and alert events from Opsgenie.
//
// It operates in two modes:
//
//  1. Webhook receiver (preferred): Opsgenie sends a POST to the collector's
//     HTTP endpoint. The collector verifies the shared secret in the
//     X-OG-Webhook-Secret header using constant-time equality
//     (sigverify.SecretEqual) before processing any payload.
//     Reference: https://support.atlassian.com/opsgenie/docs/outgoing-webhook-settings/
//
//  2. REST poller: GET /v2/alerts on the EU Opsgenie endpoint.
//     Auth: "Authorization: GenieKey <token>" header. Only GET endpoints are
//     called. The cursor is the latest updatedAt timestamp seen.
//
// Read-only API calls only:
//   - GET /v2/alerts   (list alerts with updatedAt range filter)
//
// EU compliance: APIBaseURL must be https://api.eu.opsgenie.com/v2.
// The non-EU endpoint (api.opsgenie.com) is rejected at startup by config.validate.
//
// PII handling: actor (owner / acknowledger / source name) and payload fields
// pass through redact.Apply / redact.RedactActor before envelope construction.
// Raw payloads are never logged at INFO level (manifest §12.13).
package opsgenie

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/ptrs"
	"operitas.eu/collector/internal/redact"
	internalrt "operitas.eu/collector/internal/runtime"
	"operitas.eu/collector/internal/sigverify"
)

// Source receives Opsgenie webhook events and polls the Opsgenie Alerts API.
type Source struct {
	cfg         config.OpsgenieConfig
	http        *http.Client
	redact      *redact.Redactor
	emit        func(envelope.Event)
	cursorPath  string
	lastUpdated time.Time
}

// New constructs an Opsgenie source. No goroutines are started; no network
// calls are made. The cursor is loaded from disk if a cursor path is configured.
func New(cfg config.OpsgenieConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
	s := &Source{
		cfg:        cfg,
		http:       newHTTPClient(),
		redact:     r,
		emit:       emit,
		cursorPath: cfg.CursorPath,
	}
	s.loadCursor()
	return s
}

func newHTTPClient() *http.Client {
	return &http.Client{
		// Never follow redirects. A 302 from the Opsgenie API could forward
		// the Authorization: GenieKey header to an attacker-controlled host
		// if the redirect crosses a host boundary. The caller sees the 3xx
		// and treats it as a non-2xx error — no credentials are forwarded.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   4,
		},
	}
}

// Register adds the Opsgenie webhook handler to the shared router at
// /webhook/opsgenie. Call this before starting the shared router.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/opsgenie", s.handleWebhook)
}

// RunPoller polls the Opsgenie Alerts API on the configured interval.
// It blocks until ctx is cancelled.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("opsgenie poller started",
		"api_base_url", s.cfg.APIBaseURL,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "opsgenie", s.poll)
}

// loadCursor reads the persisted high-water-mark from disk.
func (s *Source) loadCursor() {
	if s.cursorPath == "" {
		return
	}
	data, err := os.ReadFile(s.cursorPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("opsgenie: cursor read failed; starting from lookback window",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("opsgenie: cursor parse failed; starting from lookback window",
			"path", s.cursorPath, "err", err)
		return
	}
	s.lastUpdated = t
}

func (s *Source) writeCursor() {
	if s.cursorPath == "" || s.lastUpdated.IsZero() {
		return
	}
	tmp := s.cursorPath + ".tmp"
	val := s.lastUpdated.UTC().Format(time.RFC3339Nano)
	if err := os.WriteFile(tmp, []byte(val), 0o600); err != nil {
		slog.Warn("opsgenie: cursor write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("opsgenie: cursor rename failed", "err", err)
	}
}

// poll fetches alerts updated since the last cursor and emits a normalized
// event for each alert found.
func (s *Source) poll(ctx context.Context) error {
	now := time.Now().UTC()
	from := s.lastUpdated
	if from.IsZero() {
		from = now.Add(-s.cfg.PollLookback)
	}

	// Opsgenie query parameter: updatedAt filter using epoch milliseconds.
	// "query=updatedAt > <epoch_ms>" selects alerts modified after our cursor.
	fromEpochMs := from.UnixMilli()
	query := fmt.Sprintf("updatedAt > %d", fromEpochMs)

	slog.Debug("opsgenie: polling",
		"from", from.Format(time.RFC3339),
		"query", query,
	)

	// Opsgenie GET /v2/alerts supports offset-based pagination via "offset" and
	// "limit" parameters. The response includes a "paging" object with a "next"
	// URL when there are more results.
	offset := 0
	const limit = 100
	var highWater time.Time

	for {
		alerts, nextOffset, err := s.fetchAlerts(ctx, query, offset, limit)
		if err != nil {
			return fmt.Errorf("opsgenie: fetch alerts: %w", err)
		}

		for _, a := range alerts {
			ev, ok := s.normalizeAlert(a)
			if !ok {
				continue
			}
			s.emit(ev)
			if ev.OccurredAt.After(highWater) {
				highWater = ev.OccurredAt
			}
		}

		if nextOffset < 0 || len(alerts) == 0 {
			break
		}
		offset = nextOffset
	}

	if !highWater.IsZero() && highWater.After(s.lastUpdated) {
		// Advance by 1 ms to avoid re-fetching the last seen alert.
		s.lastUpdated = highWater.Add(time.Millisecond)
		s.writeCursor()
	}

	slog.Debug("opsgenie: poll complete")
	return nil
}

// ogAlertListResponse is the shape returned by GET /v2/alerts.
type ogAlertListResponse struct {
	Data   []ogAlert `json:"data"`
	Paging ogPaging  `json:"paging"`
	Took   float64   `json:"took"`
	// RequestID is included for debugging but not used by the collector.
}

type ogPaging struct {
	Next  string `json:"next"`
	First string `json:"first"`
	Last  string `json:"last"`
}

// ogAlert is the minimal subset of the Opsgenie alert shape we need from the
// list endpoint. Field names match the Opsgenie REST API v2 response exactly.
type ogAlert struct {
	ID           string   `json:"id"`
	TinyID       string   `json:"tinyId"`
	Alias        string   `json:"alias"`
	Message      string   `json:"message"`
	Status       string   `json:"status"`
	Priority     string   `json:"priority"`
	Owner        string   `json:"owner"`
	Source       string   `json:"source"`
	Tags         []string `json:"tags"`
	CreatedAt    int64    `json:"createdAt"` // epoch milliseconds
	UpdatedAt    int64    `json:"updatedAt"` // epoch milliseconds
	IsSeen       bool     `json:"isSeen"`
	Acknowledged bool     `json:"acknowledged"`
	Snoozed      bool     `json:"snoozed"`
}

// fetchAlerts calls GET /v2/alerts with the given query, offset, and limit.
// Returns the alerts, the next offset (-1 if there is no next page), and
// any error.
func (s *Source) fetchAlerts(ctx context.Context, query string, offset, limit int) ([]ogAlert, int, error) {
	q := url.Values{}
	q.Set("query", query)
	q.Set("offset", fmt.Sprintf("%d", offset))
	q.Set("limit", fmt.Sprintf("%d", limit))
	q.Set("order", "asc")
	q.Set("sort", "updatedAt")

	reqURL := s.cfg.APIBaseURL + "/alerts?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, -1, err
	}
	req.Header.Set("Authorization", "GenieKey "+s.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return nil, -1, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, -1, fmt.Errorf("opsgenie GET /v2/alerts: unexpected status %d (response body omitted)", resp.StatusCode)
	}

	var result ogAlertListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, -1, fmt.Errorf("opsgenie: decode alerts response: %w", err)
	}

	// Determine the next offset. If Paging.Next is non-empty there are more
	// results; advance by the number of records we just fetched.
	nextOffset := -1
	if result.Paging.Next != "" && len(result.Data) > 0 {
		nextOffset = offset + len(result.Data)
	}

	return result.Data, nextOffset, nil
}

func (s *Source) normalizeAlert(a ogAlert) (envelope.Event, bool) {
	if a.UpdatedAt == 0 && a.CreatedAt == 0 {
		return envelope.Event{}, false
	}

	ts := a.UpdatedAt
	if ts == 0 {
		ts = a.CreatedAt
	}
	t := time.UnixMilli(ts).UTC()

	// Derive event type from the alert status.
	evType := mapAlertStatus(a.Status, a.Acknowledged)

	// Actor: prefer owner; fall back to source integration name.
	actorRaw := a.Owner
	if actorRaw == "" {
		actorRaw = a.Source
	}
	var actorPtr *string
	if actorRaw != "" {
		actorPtr = s.redact.RedactActor(ptrs.String(actorRaw))
	}

	// Resource: prefer alias (human-readable), fall back to tinyId, then ID.
	resource := a.Alias
	if resource == "" {
		resource = a.TinyID
	}
	if resource == "" {
		resource = a.ID
	}

	payload := s.redact.Apply(map[string]any{
		"alert_id": a.ID,
		"tiny_id":  a.TinyID,
		"alias":    a.Alias,
		"message":  a.Message,
		"status":   a.Status,
		"priority": a.Priority,
		"tags":     a.Tags,
		"source":   a.Source,
	})

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceOpsgenie,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}, true
}

// handleWebhook is the HTTP handler for incoming Opsgenie webhook notifications.
// Opsgenie sends the shared secret verbatim in X-OG-Webhook-Secret; verified
// with constant-time equality.
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

	// Verify X-OG-Webhook-Secret header with constant-time comparison.
	if s.cfg.WebhookSecret != "" {
		got := r.Header.Get("X-OG-Webhook-Secret")
		if !sigverify.SecretEqual(s.cfg.WebhookSecret, got) {
			slog.Warn("opsgenie webhook: invalid secret")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processWebhookPayload(body); err != nil {
		slog.Error("opsgenie webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ogWebhookAlert is the nested alert object inside an Opsgenie webhook payload.
// Field names match the Opsgenie outgoing webhook body exactly.
// Reference: https://support.atlassian.com/opsgenie/docs/opsgenie-edge-connector-alert-action-data/
type ogWebhookAlert struct {
	AlertID   string   `json:"alertId"`
	Message   string   `json:"message"`
	Alias     string   `json:"alias"`
	TinyID    string   `json:"tinyId"`
	Priority  string   `json:"priority"`
	Status    string   `json:"status"`
	Owner     string   `json:"owner"`
	Tags      []string `json:"tags"`
	Source    string   `json:"source"`
	CreatedAt int64    `json:"createdAt"` // epoch milliseconds
	UpdatedAt int64    `json:"updatedAt"` // epoch milliseconds
}

// ogWebhookSource holds the integration or user that triggered the action.
type ogWebhookSource struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ogWebhookPayload is the top-level shape Opsgenie sends to outgoing webhooks.
type ogWebhookPayload struct {
	Action string          `json:"action"` // "Create", "Acknowledge", "Close", "Escalate", "Assign", etc.
	Alert  ogWebhookAlert  `json:"alert"`
	Source ogWebhookSource `json:"source"`
}

func (s *Source) processWebhookPayload(body []byte) error {
	var wh ogWebhookPayload
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal opsgenie webhook: %w", err)
	}

	evType := MapAction(wh.Action)

	// Timestamp: prefer alert.updatedAt, fall back to alert.createdAt, then now.
	ts := wh.Alert.UpdatedAt
	if ts == 0 {
		ts = wh.Alert.CreatedAt
	}
	var t time.Time
	if ts != 0 {
		t = time.UnixMilli(ts).UTC()
	} else {
		t = time.Now().UTC()
	}

	// Actor: prefer alert owner (the assigned user), fall back to the webhook
	// source name (integration or user who triggered the action).
	actorRaw := wh.Alert.Owner
	if actorRaw == "" {
		actorRaw = wh.Source.Name
	}
	var actorPtr *string
	if actorRaw != "" {
		actorPtr = s.redact.RedactActor(ptrs.String(actorRaw))
	}

	// Resource: prefer alias (human-readable), fall back to tinyId, then alertId.
	resource := wh.Alert.Alias
	if resource == "" {
		resource = wh.Alert.TinyID
	}
	if resource == "" {
		resource = wh.Alert.AlertID
	}

	payload := s.redact.Apply(map[string]any{
		"alert_id": wh.Alert.AlertID,
		"tiny_id":  wh.Alert.TinyID,
		"alias":    wh.Alert.Alias,
		"message":  wh.Alert.Message,
		"priority": wh.Alert.Priority,
		"status":   wh.Alert.Status,
		"action":   wh.Action,
		"tags":     wh.Alert.Tags,
		"source":   wh.Alert.Source,
	})

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceOpsgenie,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

// MapAction maps an Opsgenie webhook action string to a canonical event type
// from §4.5 of the project manifest.
// Exported for testing.
func MapAction(action string) string {
	switch action {
	case "Create":
		return "incident.opened"
	case "Acknowledge":
		return "incident.acknowledged"
	case "Close":
		return "incident.resolved"
	case "Escalate":
		return "incident.escalated"
	case "Assign":
		// An assignment is an acknowledgement-class action in the incident lifecycle.
		return "incident.acknowledged"
	case "AddNote":
		// Notes are informational; treat as acknowledged (alert is being managed).
		return "incident.acknowledged"
	case "UnAcknowledge":
		// Re-opened / unacknowledged alerts are incident.opened again.
		return "incident.opened"
	case "Snooze":
		return "incident.acknowledged"
	default:
		// Unknown actions are treated as monitor alerts to avoid dropping events.
		return "monitor.alert"
	}
}

// mapAlertStatus maps a polled alert's status field to a canonical event type.
// Used by the REST poller path where there is no action verb.
func mapAlertStatus(status string, acknowledged bool) string {
	switch strings.ToLower(status) {
	case "resolved", "closed":
		return "incident.resolved"
	case "open":
		if acknowledged {
			return "incident.acknowledged"
		}
		return "incident.opened"
	default:
		return "monitor.alert"
	}
}

// HandleWebhookForTest exposes the internal webhook handler for use in external
// test packages. This avoids requiring a running HTTP server in unit tests.
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
