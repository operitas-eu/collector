// Package incidentio collects incident lifecycle events from incident.io.
//
// It operates in two modes:
//
//  1. Webhook receiver (preferred): incident.io signs payloads with HMAC-SHA256;
//     the signature is delivered in the X-Signature-256 header with a "sha256="
//     prefix. Verified with sigverify.HexHMACPrefixed before any processing.
//     Reference: https://api-docs.incident.io/tag/Webhook-HTTP-Endpoints
//
//  2. REST poller: GET https://api.incident.io/v2/incidents
//     Auth: Authorization: Bearer <token>.
//     Pagination uses the pagination_meta.after cursor returned by the API.
//     The cursor is persisted to disk at CursorPath (RFC3339Nano, last
//     incident updated_at).
//
// Read-only API calls only:
//   - GET /v2/incidents   (paginated incident list)
//
// EU compliance: incident.io is EU-hosted SaaS (api.incident.io). The default
// APIBaseURL must not be changed to a non-EU host. Validation occurs in
// config.validate() at startup.
//
// PII handling: actor (reporter email/name) and payload fields pass through
// redact.Apply and redact.RedactActor before envelope construction. Raw payloads
// are never logged at INFO level (manifest §12.13).
package incidentio

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

// Source receives incident.io webhook events and polls the incident.io REST API.
type Source struct {
	cfg         config.IncidentIOConfig
	http        *http.Client
	redact      *redact.Redactor
	emit        func(envelope.Event)
	cursorPath  string
	lastEventAt time.Time
}

// New constructs an incident.io source. It does not start goroutines or make
// network calls. If a cursor file exists at cfg.CursorPath, it is loaded.
func New(cfg config.IncidentIOConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
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
		// Never follow redirects. A 302 from the incident.io API could forward
		// the Authorization: Bearer header to an attacker-controlled host if
		// the redirect crosses a host boundary. The caller sees the 3xx and
		// treats it as a non-2xx error — no credentials are forwarded.
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

// Register adds the incident.io webhook handler to the shared router at
// /webhook/incidentio.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/incidentio", s.handleWebhook)
}

// RunPoller polls the incident.io incidents API on the configured interval.
// It blocks until ctx is cancelled.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("incidentio poller started",
		"api_base_url", s.cfg.APIBaseURL,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "incidentio", s.poll)
}

// loadCursor reads the persisted high-water-mark from disk.
func (s *Source) loadCursor() {
	if s.cursorPath == "" {
		return
	}
	data, err := os.ReadFile(s.cursorPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("incidentio: cursor read failed; starting from lookback window",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("incidentio: cursor parse failed; starting from lookback window",
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
		slog.Warn("incidentio: cursor write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("incidentio: cursor rename failed", "err", err)
	}
}

// poll fetches incidents updated since the last cursor and emits a canonical
// event for each one. Pagination is driven by pagination_meta.after.
func (s *Source) poll(ctx context.Context) error {
	now := time.Now().UTC()
	from := s.lastEventAt
	if from.IsZero() {
		from = now.Add(-s.cfg.PollLookback)
	}

	slog.Debug("incidentio: polling", "since", from.Format(time.RFC3339))

	var highWater time.Time
	var afterCursor string

	for {
		page, after, err := s.fetchIncidentsPage(ctx, afterCursor)
		if err != nil {
			return fmt.Errorf("incidentio: fetch incidents: %w", err)
		}

		for _, inc := range page {
			// Skip incidents not updated since our window.
			if !inc.UpdatedAt.IsZero() && inc.UpdatedAt.Before(from) {
				continue
			}
			ev, ok := s.normalizeIncident(inc)
			if !ok {
				continue
			}
			s.emit(ev)
			if ev.OccurredAt.After(highWater) {
				highWater = ev.OccurredAt
			}
		}

		if after == "" {
			break
		}
		afterCursor = after
	}

	if !highWater.IsZero() && highWater.After(s.lastEventAt) {
		s.lastEventAt = highWater.Add(time.Millisecond)
		s.writeCursor()
	}

	slog.Debug("incidentio: poll complete")
	return nil
}

// incidentListResponse is the shape returned by GET /v2/incidents.
type incidentListResponse struct {
	Incidents      []incidentResource `json:"incidents"`
	PaginationMeta struct {
		After      string `json:"after"`
		PageSize   int    `json:"page_size"`
		TotalCount int    `json:"total_count"`
	} `json:"pagination_meta"`
}

// incidentResource is the minimal incident shape used for normalization.
type incidentResource struct {
	ID        string `json:"id"`
	Reference string `json:"reference"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Severity  *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Rank int    `json:"rank"`
	} `json:"severity"`
	Reporter  *incidentUser  `json:"reporter"`
	Assignees []incidentUser `json:"assignees"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// incidentUser is the minimal user shape returned by the incident.io API.
type incidentUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (s *Source) fetchIncidentsPage(ctx context.Context, after string) ([]incidentResource, string, error) {
	q := url.Values{}
	q.Set("page_size", "25")
	if after != "" {
		q.Set("after", after)
	}

	reqURL := s.cfg.APIBaseURL + "/incidents?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("incidentio GET /incidents: unexpected status %d (response body omitted)", resp.StatusCode)
	}

	var result incidentListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", fmt.Errorf("incidentio: decode incidents response: %w", err)
	}
	return result.Incidents, result.PaginationMeta.After, nil
}

func (s *Source) normalizeIncident(inc incidentResource) (envelope.Event, bool) {
	t := inc.UpdatedAt.UTC()
	if t.IsZero() {
		t = inc.CreatedAt.UTC()
	}
	if t.IsZero() {
		return envelope.Event{}, false
	}

	evType := MapIncidentStatus(inc.Status)

	// Actor: prefer reporter; fall back to first assignee.
	var actorPtr *string
	if inc.Reporter != nil {
		identity := inc.Reporter.Email
		if identity == "" {
			identity = inc.Reporter.Name
		}
		actorPtr = s.redact.RedactActor(ptrs.String(identity))
	} else if len(inc.Assignees) > 0 {
		identity := inc.Assignees[0].Email
		if identity == "" {
			identity = inc.Assignees[0].Name
		}
		actorPtr = s.redact.RedactActor(ptrs.String(identity))
	}

	severityName := ""
	if inc.Severity != nil {
		severityName = inc.Severity.Name
	}

	resource := inc.Reference
	if resource == "" {
		resource = inc.ID
	}

	payload := s.redact.Apply(map[string]any{
		"incident_id": inc.ID,
		"reference":   inc.Reference,
		"name":        inc.Name,
		"status":      inc.Status,
		"severity":    severityName,
	})

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceIncidentIO,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}, true
}

// handleWebhook is the HTTP handler for incident.io webhook payloads.
// Signature: X-Signature-256 header, "sha256=" prefix, HMAC-SHA256 over the raw body.
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

	// Verify X-Signature-256: sha256=<hex> HMAC-SHA256 over the raw request body.
	if s.cfg.WebhookSecret != "" {
		sig := r.Header.Get("X-Signature-256")
		if !sigverify.HexHMACPrefixed([]byte(s.cfg.WebhookSecret), body, sig, "sha256=") {
			slog.Warn("incidentio webhook: invalid signature")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processWebhookPayload(body); err != nil {
		slog.Error("incidentio webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// incidentWebhookPayload is the shape of incident.io webhook events.
// Reference: https://api-docs.incident.io/tag/Webhook-HTTP-Endpoints
type incidentWebhookPayload struct {
	// EventType is the incident.io webhook event type string.
	// Examples: public_incident.incident_created_v2, public_incident.incident_updated_v2
	EventType string `json:"event_type"`
	Event     struct {
		ID string `json:"id"`
	} `json:"event"`
	Incident incidentResource `json:"incident"`
}

func (s *Source) processWebhookPayload(body []byte) error {
	var wh incidentWebhookPayload
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal incidentio webhook: %w", err)
	}

	evType, ok := MapWebhookEventType(wh.EventType, wh.Incident.Status)
	if !ok {
		slog.Debug("incidentio webhook: skipping unsupported event type",
			"event_type", wh.EventType)
		return nil
	}

	t := wh.Incident.UpdatedAt.UTC()
	if t.IsZero() {
		t = wh.Incident.CreatedAt.UTC()
	}
	if t.IsZero() {
		t = time.Now().UTC()
	}

	var actorPtr *string
	if wh.Incident.Reporter != nil {
		identity := wh.Incident.Reporter.Email
		if identity == "" {
			identity = wh.Incident.Reporter.Name
		}
		actorPtr = s.redact.RedactActor(ptrs.String(identity))
	} else if len(wh.Incident.Assignees) > 0 {
		identity := wh.Incident.Assignees[0].Email
		if identity == "" {
			identity = wh.Incident.Assignees[0].Name
		}
		actorPtr = s.redact.RedactActor(ptrs.String(identity))
	}

	severityName := ""
	if wh.Incident.Severity != nil {
		severityName = wh.Incident.Severity.Name
	}

	resource := wh.Incident.Reference
	if resource == "" {
		resource = wh.Incident.ID
	}

	payload := s.redact.Apply(map[string]any{
		"incident_id": wh.Incident.ID,
		"reference":   wh.Incident.Reference,
		"name":        wh.Incident.Name,
		"status":      wh.Incident.Status,
		"severity":    severityName,
		"event_type":  wh.EventType,
	})

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceIncidentIO,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

// MapWebhookEventType maps an incident.io webhook event_type string and the
// incident status to a canonical event type from §4.5.
// Returns ("", false) for unsupported event types.
// Exported for testing.
func MapWebhookEventType(webhookEventType, incidentStatus string) (string, bool) {
	switch webhookEventType {
	case "public_incident.incident_created_v2":
		return "incident.opened", true
	case "public_incident.incident_updated_v2":
		// Distinguish update sub-states by incident status.
		return MapIncidentStatus(incidentStatus), true
	default:
		return "", false
	}
}

// MapIncidentStatus maps an incident.io incident status to a canonical event
// type from §4.5. Falls back to incident.acknowledged for unknown statuses.
// Exported for testing.
func MapIncidentStatus(status string) string {
	switch strings.ToLower(status) {
	case "triage", "investigating":
		return "incident.opened"
	case "identified", "monitoring", "watching", "live":
		return "incident.acknowledged"
	case "resolved", "post-incident", "learning":
		return "incident.resolved"
	case "closed", "cancelled":
		return "incident.resolved"
	case "escalated":
		return "incident.escalated"
	default:
		return "incident.acknowledged"
	}
}

// VerifyWebhookSignature reports whether the X-Signature-256 header is a valid
// HMAC-SHA256 signature of body using secret. The header must have the "sha256="
// prefix. Exported for testing.
func VerifyWebhookSignature(secret string, body []byte, sigHeader string) bool {
	return sigverify.HexHMACPrefixed([]byte(secret), body, sigHeader, "sha256=")
}

// HandleWebhookForTest exposes the internal webhook handler for use in external
// test packages without requiring a running HTTP server.
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
