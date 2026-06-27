// Package datadog collects monitor alert events from Datadog.
//
// It operates in two modes:
//
//  1. Webhook receiver (preferred): Datadog sends a POST with the API key
//     in the DD-API-KEY header. The collector verifies this with constant-time
//     equality (sigverify.SecretEqual) before processing.
//
//  2. REST poller: GET /api/v1/events on the EU Datadog endpoint.
//     Auth: DD-API-KEY + DD-APPLICATION-KEY headers.
//     The poller only calls read endpoints and only on the configured EU base URL.
//
// Read-only API calls only:
//   - GET /api/v1/events     (list events in a time window)
//
// EU compliance: APIBaseURL must be one of the EU Datadog endpoints:
//   - https://api.datadoghq.eu (EU1 region)
//   - https://api.eu1.datadoghq.com (EU1 via the com domain)
//
// Any other datadoghq.com or datadoghq.eu variant is rejected at startup.
//
// PII handling: all payload fields and actor names pass through redact.Apply /
// redact.RedactActor before envelope construction. Raw payloads are never logged
// at INFO level (manifest §12.13).
package datadog

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

// Source receives Datadog webhook events and polls the Datadog Events API.
type Source struct {
	cfg         config.DatadogConfig
	http        *http.Client
	redact      *redact.Redactor
	emit        func(envelope.Event)
	cursorPath  string
	lastEventAt time.Time
}

// New constructs a Datadog source.
func New(cfg config.DatadogConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
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
		// Never follow redirects. A 302 from the vendor API could send
		// DD-API-KEY / DD-APPLICATION-KEY headers to an attacker-controlled
		// host if the redirect crosses a host boundary. Returning
		// http.ErrUseLastResponse causes the caller to see the 3xx and treat
		// it as a non-2xx error — no credentials are forwarded.
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

// Register adds the Datadog webhook handler to the shared router at /webhook/datadog.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/datadog", s.handleWebhook)
}

// RunPoller polls the Datadog Events API on the configured interval.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("datadog poller started",
		"api_base_url", s.cfg.APIBaseURL,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "datadog", s.poll)
}

func (s *Source) loadCursor() {
	if s.cursorPath == "" {
		return
	}
	data, err := os.ReadFile(s.cursorPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("datadog: cursor read failed; starting from lookback window",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("datadog: cursor parse failed; starting from lookback window",
			"path", s.cursorPath, "err", err)
		return
	}
	s.lastEventAt = t
}

func (s *Source) writeCursor() {
	if s.cursorPath == "" || s.lastEventAt.IsZero() {
		return
	}
	tmp := s.cursorPath + ".tmp"
	val := s.lastEventAt.UTC().Format(time.RFC3339Nano)
	if err := os.WriteFile(tmp, []byte(val), 0o600); err != nil {
		slog.Warn("datadog: cursor write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("datadog: cursor rename failed", "err", err)
	}
}

// poll fetches Datadog events since the last cursor.
func (s *Source) poll(ctx context.Context) error {
	now := time.Now().UTC()
	from := s.lastEventAt
	if from.IsZero() {
		from = now.Add(-s.cfg.PollLookback)
	}

	// The Datadog v1 Events API uses Unix timestamps.
	q := url.Values{}
	q.Set("start", fmt.Sprintf("%d", from.Unix()))
	q.Set("end", fmt.Sprintf("%d", now.Unix()))
	q.Set("priority", "all")

	reqURL := s.cfg.APIBaseURL + "/api/v1/events?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("datadog: build request: %w", err)
	}
	req.Header.Set("DD-API-KEY", s.cfg.APIKey)
	req.Header.Set("DD-APPLICATION-KEY", s.cfg.AppKey)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("datadog: GET /api/v1/events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("datadog: GET /api/v1/events: unexpected status %d (response body omitted)", resp.StatusCode)
	}

	var result ddEventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("datadog: decode events response: %w", err)
	}

	var highWater time.Time
	for _, ddEv := range result.Events {
		ev, ok := s.normalizeEvent(ddEv)
		if !ok {
			continue
		}
		s.emit(ev)
		if ev.OccurredAt.After(highWater) {
			highWater = ev.OccurredAt
		}
	}

	if !highWater.IsZero() && highWater.After(s.lastEventAt) {
		s.lastEventAt = highWater.Add(time.Second)
		s.writeCursor()
	}

	slog.Debug("datadog: poll complete", "events_fetched", len(result.Events))
	return nil
}

// ddEventsResponse is the shape returned by GET /api/v1/events.
type ddEventsResponse struct {
	Events []ddEvent `json:"events"`
}

// ddEvent is the minimal subset of the Datadog event shape we use.
type ddEvent struct {
	ID             int64    `json:"id"`
	Title          string   `json:"title"`
	Text           string   `json:"text"`
	DateHappened   int64    `json:"date_happened"` // Unix timestamp
	Priority       string   `json:"priority"`
	AlertType      string   `json:"alert_type"`
	Tags           []string `json:"tags"`
	Host           string   `json:"host"`
	SourceTypeName string   `json:"source_type_name"`
}

func (s *Source) normalizeEvent(ddEv ddEvent) (envelope.Event, bool) {
	if ddEv.DateHappened == 0 {
		return envelope.Event{}, false
	}

	t := time.Unix(ddEv.DateHappened, 0).UTC()
	evType := mapDDAlertType(ddEv.AlertType)

	payload := s.redact.Apply(map[string]any{
		"id":          ddEv.ID,
		"title":       ddEv.Title,
		"alert_type":  ddEv.AlertType,
		"priority":    ddEv.Priority,
		"tags":        ddEv.Tags,
		"host":        ddEv.Host,
		"source_type": ddEv.SourceTypeName,
	})

	resource := fmt.Sprintf("%d", ddEv.ID)

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceDatadog,
		Actor:       nil,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}, true
}

// handleWebhook is the HTTP handler for Datadog webhook notifications.
// Datadog sends the API key in the DD-API-KEY header; we verify it with
// constant-time equality.
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

	// Verify DD-API-KEY header with constant-time comparison.
	if s.cfg.WebhookSecret != "" {
		got := r.Header.Get("DD-API-KEY")
		if !sigverify.SecretEqual(s.cfg.WebhookSecret, got) {
			slog.Warn("datadog webhook: invalid DD-API-KEY")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processWebhookPayload(body); err != nil {
		slog.Error("datadog webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ddWebhookPayload is the shape Datadog sends to custom webhooks.
// Reference: https://docs.datadoghq.com/integrations/webhooks/
type ddWebhookPayload struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	URL         string `json:"url"`
	Body        string `json:"body"`
	LastUpdated string `json:"last_updated"` // ISO8601
	EventType   string `json:"event_type"`
	Date        string `json:"date"` // epoch or ISO8601
	AlertType   string `json:"alert_type"`
	AlertID     int64  `json:"alert_id"`
	AlertTitle  string `json:"alert_title"`
	AlertCycle  string `json:"alert_cycle_key"`
	Priority    string `json:"priority"`
	Hostname    string `json:"hostname"`
	Tags        string `json:"tags"` // comma-separated
	User        string `json:"user"`
	Transition  string `json:"alert_transition"`
}

func (s *Source) processWebhookPayload(body []byte) error {
	var wh ddWebhookPayload
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal datadog webhook: %w", err)
	}

	t := time.Now().UTC()
	if wh.LastUpdated != "" {
		if parsed, err := time.Parse(time.RFC3339, wh.LastUpdated); err == nil {
			t = parsed.UTC()
		}
	}

	evType := mapDDAlertType(wh.AlertType)

	var actorPtr *string
	if wh.User != "" {
		actorPtr = s.redact.RedactActor(ptrs.String(wh.User))
	}

	tags := splitTags(wh.Tags)

	payload := s.redact.Apply(map[string]any{
		"alert_id":    wh.AlertID,
		"alert_title": wh.AlertTitle,
		"alert_type":  wh.AlertType,
		"transition":  wh.Transition,
		"priority":    wh.Priority,
		"hostname":    wh.Hostname,
		"tags":        tags,
	})

	resource := fmt.Sprintf("%d", wh.AlertID)
	if wh.ID != "" {
		resource = wh.ID
	}

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceDatadog,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

// MapAlertType maps a Datadog alert_type to a canonical event type from §4.5.
// Exported for testing.
func MapAlertType(alertType string) string {
	return mapDDAlertType(alertType)
}

func mapDDAlertType(alertType string) string {
	switch strings.ToLower(alertType) {
	case "error", "alert", "warning":
		return "monitor.alert"
	case "success", "info":
		return "monitor.alert"
	case "":
		return "monitor.alert"
	default:
		return "monitor.alert"
	}
}

// splitTags converts a comma-separated Datadog tag string to a []string.
func splitTags(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// VerifyAPIKeyHeader reports whether the DD-API-KEY header matches the expected secret.
// Exported for testing.
func VerifyAPIKeyHeader(secret, headerValue string) bool {
	return sigverify.SecretEqual(secret, headerValue)
}

// HandleWebhookForTest exposes the internal webhook handler for use in external
// test packages. This avoids requiring a running HTTP server in unit tests.
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
