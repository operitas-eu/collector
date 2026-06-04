// Package servicenow collects change management and incident data from ServiceNow.
//
// It operates in two modes:
//
//  1. Webhook receiver (preferred): a ServiceNow Business Rule or Flow Designer
//     step sends a POST to the collector's HTTP endpoint whenever a change_request
//     or incident record changes. The collector verifies the plain shared secret
//     in the X-ServiceNow-Webhook-Secret header using constant-time equality
//     (sigverify.SecretEqual) before processing any payload.
//
//  2. REST poller: GET /api/now/table/{table} on the configured ServiceNow instance.
//     Auth: Bearer token when Token is set; HTTP Basic (BasicUser + WebhookSecret as
//     password) otherwise. Only GET requests are issued — no writes, no mutations.
//     Pagination via sysparm_offset; cursor on sys_updated_on.
//
// Read-only API calls only:
//   - GET /api/now/table/{table}   (ServiceNow Table API)
//
// EU compliance: BaseURL must be the customer's EU-resident ServiceNow instance.
// Validated against isKnownNonEUEndpoint at startup (config.validate).
//
// PII handling: actor strings (opened_by / assigned_to display_value) and payload
// fields pass through redact.RedactActor and redact.Apply before envelope construction.
// Raw payloads are never logged at INFO level (manifest §12.13).
package servicenow

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

// Source receives ServiceNow webhook events and polls the ServiceNow Table API.
type Source struct {
	cfg         config.ServiceNowConfig
	http        *http.Client
	redact      *redact.Redactor
	emit        func(envelope.Event)
	cursorPath  string
	lastUpdated time.Time
}

// New constructs a ServiceNow source. No goroutines are started; no network
// calls are made during construction (CONTRACT.md §2).
func New(cfg config.ServiceNowConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
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
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   4,
		},
	}
}

// Register adds the ServiceNow webhook handler to the shared router at
// /webhook/servicenow. Call before starting the shared router.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/servicenow", s.handleWebhook)
}

// RunPoller polls the ServiceNow Table API on the configured interval. Blocks
// until ctx is cancelled.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("servicenow poller started",
		"base_url", s.cfg.BaseURL,
		"tables", s.cfg.Tables,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "servicenow", s.poll)
}

// loadCursor reads the persisted high-water-mark from disk.
func (s *Source) loadCursor() {
	if s.cursorPath == "" {
		return
	}
	data, err := os.ReadFile(s.cursorPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("servicenow: cursor read failed; starting from lookback window",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("servicenow: cursor parse failed; starting from lookback window",
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
		slog.Warn("servicenow: cursor write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("servicenow: cursor rename failed", "err", err)
	}
}

// poll fetches records updated since the last cursor across all configured
// tables and emits a canonical event for each record.
func (s *Source) poll(ctx context.Context) error {
	now := time.Now().UTC()
	from := s.lastUpdated
	if from.IsZero() {
		from = now.Add(-s.cfg.PollLookback)
	}

	var highWater time.Time

	for _, table := range s.cfg.Tables {
		hw, err := s.pollTable(ctx, table, from)
		if err != nil {
			slog.Error("servicenow: poll table failed", "table", table, "err", err)
			continue
		}
		if hw.After(highWater) {
			highWater = hw
		}
	}

	if !highWater.IsZero() && highWater.After(s.lastUpdated) {
		s.lastUpdated = highWater.Add(time.Millisecond)
		s.writeCursor()
	}

	slog.Debug("servicenow: poll complete")
	return nil
}

// pollTable fetches all updated records from one ServiceNow table since from,
// returns the highest sys_updated_on seen.
func (s *Source) pollTable(ctx context.Context, table string, from time.Time) (time.Time, error) {
	// sysparmQuery uses snTimeFormat ("yyyy-MM-dd HH:mm:ss") for the
	// sys_updated_on comparison in the ServiceNow Table API.
	sysparmQuery := fmt.Sprintf("sys_updated_on>=%s^ORDERBYsys_updated_on",
		from.UTC().Format(snTimeFormat))

	const limit = 50
	offset := 0
	var highWater time.Time

	for {
		records, total, err := s.fetchPage(ctx, table, sysparmQuery, offset, limit)
		if err != nil {
			return highWater, fmt.Errorf("servicenow: fetch page table=%s offset=%d: %w", table, offset, err)
		}

		for _, rec := range records {
			ev, ok := s.normalizeRecord(table, rec)
			if !ok {
				continue
			}
			s.emit(ev)
			if ev.OccurredAt.After(highWater) {
				highWater = ev.OccurredAt
			}
		}

		offset += len(records)
		if offset >= total || len(records) == 0 {
			break
		}
	}

	return highWater, nil
}

// snTableResponse is the shape returned by GET /api/now/table/{table}.
type snTableResponse struct {
	Result []snRecord `json:"result"`
}

// snRecord holds the fields we extract from a ServiceNow table record.
// Both change_request and incident share this shape; unused fields are ignored.
type snRecord struct {
	SysID        string    `json:"sys_id"`
	Number       string    `json:"number"`
	SysClassName string    `json:"sys_class_name"`
	State        string    `json:"state"`
	ShortDesc    string    `json:"short_description"`
	SysUpdatedOn string    `json:"sys_updated_on"` // "yyyy-MM-dd HH:mm:ss" UTC
	OpenedBy     snRefLink `json:"opened_by"`
	AssignedTo   snRefLink `json:"assigned_to"`
	Priority     string    `json:"priority"`
	Category     string    `json:"category"`
}

// snRefLink is the shape ServiceNow uses for reference fields when
// sysparm_display_value=true is set.
type snRefLink struct {
	DisplayValue string `json:"display_value"`
	Link         string `json:"link"`
}

func (s *Source) fetchPage(ctx context.Context, table, sysparmQuery string, offset, limit int) ([]snRecord, int, error) {
	q := url.Values{}
	q.Set("sysparm_query", sysparmQuery)
	q.Set("sysparm_limit", fmt.Sprintf("%d", limit))
	q.Set("sysparm_offset", fmt.Sprintf("%d", offset))
	q.Set("sysparm_display_value", "true")
	q.Set("sysparm_fields", "sys_id,number,sys_class_name,state,short_description,sys_updated_on,opened_by,assigned_to,priority,category")

	reqURL := s.cfg.BaseURL + "/api/now/table/" + table + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	s.applyAuth(req)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("servicenow GET /api/now/table/%s: unexpected status %d (response body omitted)", table, resp.StatusCode)
	}

	// X-Total-Count header carries the total number of matching records.
	total := 0
	if v := resp.Header.Get("X-Total-Count"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &total) // fallback to 0 is safe
	}

	var result snTableResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("servicenow: decode table response: %w", err)
	}

	// When total header is absent, fall back to the page size heuristic.
	if total == 0 {
		total = offset + len(result.Result)
	}

	return result.Result, total, nil
}

// applyAuth sets the Authorization header using Bearer token when configured,
// falling back to HTTP Basic using BasicUser + WebhookSecret.
func (s *Source) applyAuth(req *http.Request) {
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	} else {
		req.SetBasicAuth(s.cfg.BasicUser, s.cfg.WebhookSecret)
	}
}

// snTimeFormat is the datetime format ServiceNow uses in sys_updated_on.
const snTimeFormat = "2006-01-02 15:04:05"

// normalizeRecord converts a raw ServiceNow record to a canonical envelope.Event.
func (s *Source) normalizeRecord(table string, rec snRecord) (envelope.Event, bool) {
	t, err := time.ParseInLocation(snTimeFormat, rec.SysUpdatedOn, time.UTC)
	if err != nil || t.IsZero() {
		slog.Warn("servicenow: cannot parse sys_updated_on; skipping record",
			"number", rec.Number, "raw", rec.SysUpdatedOn)
		return envelope.Event{}, false
	}

	evType := MapRecordEventType(table, rec.State)

	// Actor: prefer opened_by; fall back to assigned_to.
	var actorPtr *string
	if rec.OpenedBy.DisplayValue != "" {
		actorPtr = s.redact.RedactActor(ptrs.String(rec.OpenedBy.DisplayValue))
	} else if rec.AssignedTo.DisplayValue != "" {
		actorPtr = s.redact.RedactActor(ptrs.String(rec.AssignedTo.DisplayValue))
	}

	resource := table + "/" + rec.Number

	payload := s.redact.Apply(map[string]any{
		"sys_id":            rec.SysID,
		"number":            rec.Number,
		"table":             table,
		"state":             rec.State,
		"short_description": rec.ShortDesc,
		"priority":          rec.Priority,
		"category":          rec.Category,
	})

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceServiceNow,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}, true
}

// handleWebhook is the HTTP handler for incoming ServiceNow webhook payloads.
// ServiceNow Business Rules send the shared secret verbatim in the
// X-ServiceNow-Webhook-Secret header; verified with constant-time equality.
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

	if s.cfg.WebhookSecret != "" {
		got := r.Header.Get("X-ServiceNow-Webhook-Secret")
		if !sigverify.SecretEqual(s.cfg.WebhookSecret, got) {
			slog.Warn("servicenow webhook: invalid X-ServiceNow-Webhook-Secret")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processWebhookPayload(body); err != nil {
		slog.Error("servicenow webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// snWebhookPayload is the shape ServiceNow Business Rules send via outbound REST.
// The payload contains the record fields at the time of the Business Rule trigger.
type snWebhookPayload struct {
	Table  string   `json:"table"`
	Record snRecord `json:"record"`
}

func (s *Source) processWebhookPayload(body []byte) error {
	var wh snWebhookPayload
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal servicenow webhook: %w", err)
	}

	table := wh.Table
	if table == "" {
		// Fall back to sys_class_name when table is absent.
		table = wh.Record.SysClassName
	}
	if table == "" {
		slog.Debug("servicenow webhook: skipping record with no table/sys_class_name")
		return nil
	}

	ev, ok := s.normalizeRecord(table, wh.Record)
	if !ok {
		slog.Debug("servicenow webhook: skipping unparseable record", "table", table)
		return nil
	}

	s.emit(ev)
	return nil
}

// MapRecordEventType maps a ServiceNow table name and state value to a canonical
// event type from CONTRACT.md §8. Exported for testing.
//
// change_request state values (OOTB ServiceNow):
//
//	-5 = Pending, 1 = New, 2 = Assess, 3 = Authorize -> change.opened
//	4 = Scheduled, 0 = Implement                      -> change.merged
//	-1 = Review, 3 = Closed                           -> change.closed
//	-2 = Canceled                                     -> change.closed
//
// incident state values (OOTB ServiceNow):
//
//	1 = New, 2 = In Progress, 3 = On Hold             -> incident.opened
//	6 = Resolved, 7 = Closed                          -> incident.resolved
func MapRecordEventType(table, state string) string {
	switch table {
	case "change_request":
		return mapChangeRequestState(state)
	case "incident":
		return mapIncidentState(state)
	default:
		// Unknown table: default to change.opened so events are not silently dropped.
		return "change.opened"
	}
}

func mapChangeRequestState(state string) string {
	switch state {
	case "-5", "1", "2", "3":
		// Pending / New / Assess / Authorize
		return "change.opened"
	case "4", "0":
		// Scheduled / Implement
		return "change.merged"
	case "-1", "7", "-2":
		// Review / Closed / Canceled
		return "change.closed"
	default:
		return "change.opened"
	}
}

func mapIncidentState(state string) string {
	switch state {
	case "1", "2", "3":
		// New / In Progress / On Hold
		return "incident.opened"
	case "6", "7":
		// Resolved / Closed
		return "incident.resolved"
	default:
		return "incident.opened"
	}
}

// VerifyWebhookSecret reports whether the X-ServiceNow-Webhook-Secret header
// value matches the expected secret using constant-time comparison.
// Exported for testing.
func VerifyWebhookSecret(secret, headerValue string) bool {
	return sigverify.SecretEqual(secret, headerValue)
}

// HandleWebhookForTest exposes the internal webhook handler for use in external
// test packages without requiring a running HTTP server.
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
