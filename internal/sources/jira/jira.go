// Package jira collects issue transition and project-event data from Jira.
//
// It operates in two modes:
//
//  1. Webhook receiver (preferred): Jira sends a POST to the collector's HTTP
//     endpoint. The collector verifies the Authorization header (Bearer scheme)
//     using constant-time equality before processing any payload. Jira does not
//     HMAC-sign webhook payloads; the secret is sent verbatim.
//
//  2. REST poller: GET /rest/api/3/search issues updated since the last cursor.
//     Authentication uses a Bearer token. Only GET endpoints are called.
//
// Read-only API calls only:
//   - GET /rest/api/3/search    (search issues with JQL, ordered by updated desc)
//
// EU compliance: the BaseURL is validated against isKnownNonEUEndpoint at startup.
// Atlassian Cloud EU tenants should use their standard .atlassian.net URL; EU data
// residency is enforced by Atlassian's tenant configuration, not by the URL hostname.
//
// PII handling: actor (reporter/assignee usernames) and payload fields are passed
// through redact.Apply and redact.RedactActor before envelope construction.
package jira

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

// Source receives Jira webhook events and polls the Jira REST API.
type Source struct {
	cfg        config.JiraConfig
	http       *http.Client
	redact     *redact.Redactor
	emit       func(envelope.Event)
	cursorPath string
	// lastUpdated is the high-water-mark timestamp for the polling window.
	lastUpdated time.Time
}

// New constructs a Jira source.
func New(cfg config.JiraConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
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

// Register adds the Jira webhook handler to the shared router at /webhook/jira.
// Call this before starting the shared router.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/jira", s.handleWebhook)
}

// RunPoller polls the Jira REST API on the configured interval. It blocks until
// ctx is cancelled.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("jira poller started",
		"base_url", s.cfg.BaseURL,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "jira", s.poll)
}

// loadCursor reads the persisted high-water-mark from disk.
func (s *Source) loadCursor() {
	if s.cursorPath == "" {
		return
	}
	data, err := os.ReadFile(s.cursorPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("jira: cursor read failed; starting from lookback window",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("jira: cursor parse failed; starting from lookback window",
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
		slog.Warn("jira: cursor write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("jira: cursor rename failed", "err", err)
	}
}

// poll fetches issues updated since the last cursor and emits a canonical event
// for each status transition found.
func (s *Source) poll(ctx context.Context) error {
	now := time.Now().UTC()
	from := s.lastUpdated
	if from.IsZero() {
		from = now.Add(-s.cfg.PollLookback)
	}

	// JQL: issues updated since our cursor, ordered ascending so we advance
	// the cursor monotonically.
	jql := fmt.Sprintf("updated >= %q ORDER BY updated ASC",
		from.Format("2006-01-02 15:04"))
	if len(s.cfg.Projects) > 0 {
		quoted := make([]string, len(s.cfg.Projects))
		for i, p := range s.cfg.Projects {
			quoted[i] = fmt.Sprintf("%q", p)
		}
		jql = fmt.Sprintf("project in (%s) AND updated >= %q ORDER BY updated ASC",
			strings.Join(quoted, ", "),
			from.Format("2006-01-02 15:04"))
	}
	if s.cfg.JQLFilter != "" {
		jql = jql + " AND " + s.cfg.JQLFilter
	}

	slog.Debug("jira: polling",
		"jql", jql,
	)

	startAt := 0
	const maxResults = 50
	var highWater time.Time

	for {
		issues, total, err := s.searchIssues(ctx, jql, startAt, maxResults)
		if err != nil {
			return fmt.Errorf("jira: search issues: %w", err)
		}

		for _, issue := range issues {
			ev, ok := s.normalizeIssue(issue)
			if !ok {
				continue
			}
			s.emit(ev)
			if ev.OccurredAt.After(highWater) {
				highWater = ev.OccurredAt
			}
		}

		startAt += len(issues)
		if startAt >= total || len(issues) == 0 {
			break
		}
	}

	if !highWater.IsZero() && highWater.After(s.lastUpdated) {
		s.lastUpdated = highWater.Add(time.Millisecond)
		s.writeCursor()
	}

	slog.Debug("jira: poll complete")
	return nil
}

// jiraSearchResponse is the shape returned by GET /rest/api/3/search.
type jiraSearchResponse struct {
	Total      int         `json:"total"`
	StartAt    int         `json:"startAt"`
	MaxResults int         `json:"maxResults"`
	Issues     []jiraIssue `json:"issues"`
}

// jiraIssue is the minimal subset of the issue shape we need.
type jiraIssue struct {
	Key    string          `json:"key"`
	Fields jiraIssueFields `json:"fields"`
}

type jiraIssueFields struct {
	Summary   string        `json:"summary"`
	Updated   time.Time     `json:"updated"`
	Created   time.Time     `json:"created"`
	Status    jiraStatus    `json:"status"`
	IssueType jiraIssueType `json:"issuetype"`
	Reporter  *jiraUser     `json:"reporter"`
	Assignee  *jiraUser     `json:"assignee"`
	Priority  *struct {
		Name string `json:"name"`
	} `json:"priority"`
}

type jiraStatus struct {
	Name string `json:"name"`
}

type jiraIssueType struct {
	Name string `json:"name"`
}

type jiraUser struct {
	DisplayName  string `json:"displayName"`
	EmailAddress string `json:"emailAddress"`
}

func (s *Source) searchIssues(ctx context.Context, jql string, startAt, maxResults int) ([]jiraIssue, int, error) {
	q := url.Values{}
	q.Set("jql", jql)
	q.Set("startAt", fmt.Sprintf("%d", startAt))
	q.Set("maxResults", fmt.Sprintf("%d", maxResults))
	q.Set("fields", "summary,updated,created,status,issuetype,reporter,assignee,priority")

	reqURL := s.cfg.BaseURL + "/rest/api/3/search?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("jira GET /rest/api/3/search: unexpected status %d (response body omitted)", resp.StatusCode)
	}

	var result jiraSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("jira: decode search response: %w", err)
	}
	return result.Issues, result.Total, nil
}

func (s *Source) normalizeIssue(issue jiraIssue) (envelope.Event, bool) {
	t := issue.Fields.Updated.UTC()
	if t.IsZero() {
		t = issue.Fields.Created.UTC()
	}
	if t.IsZero() {
		return envelope.Event{}, false
	}

	evType := mapIssueEventType(issue.Fields.Status.Name, issue.Fields.IssueType.Name)

	// Actor: prefer reporter; fall back to assignee.
	var actorPtr *string
	if issue.Fields.Reporter != nil {
		email := issue.Fields.Reporter.EmailAddress
		if email == "" {
			email = issue.Fields.Reporter.DisplayName
		}
		actorPtr = s.redact.RedactActor(ptrs.String(email))
	} else if issue.Fields.Assignee != nil {
		email := issue.Fields.Assignee.EmailAddress
		if email == "" {
			email = issue.Fields.Assignee.DisplayName
		}
		actorPtr = s.redact.RedactActor(ptrs.String(email))
	}

	priority := ""
	if issue.Fields.Priority != nil {
		priority = issue.Fields.Priority.Name
	}

	payload := s.redact.Apply(map[string]any{
		"issue_key":  issue.Key,
		"summary":    issue.Fields.Summary,
		"status":     issue.Fields.Status.Name,
		"issue_type": issue.Fields.IssueType.Name,
		"priority":   priority,
	})

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceJira,
		Actor:       actorPtr,
		Resource:    ptrs.String(issue.Key),
		Payload:     payload,
	}, true
}

// handleWebhook is the HTTP handler for incoming Jira webhook payloads.
// Jira sends the webhook secret verbatim in the Authorization header as
// "Bearer <secret>". Verified with constant-time equality.
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

	// Verify Authorization: Bearer <secret> using constant-time comparison.
	// The header must have the "Bearer " prefix; a bare value is rejected.
	if s.cfg.WebhookSecret != "" {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			slog.Warn("jira webhook: missing Bearer prefix")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if !sigverify.SecretEqual(s.cfg.WebhookSecret, token) {
			slog.Warn("jira webhook: invalid secret")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processWebhookPayload(body); err != nil {
		slog.Error("jira webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// jiraWebhookPayload is the shape of Jira webhook events.
// Reference: https://developer.atlassian.com/server/jira/platform/webhooks/
type jiraWebhookPayload struct {
	WebhookEvent string     `json:"webhookEvent"`
	Timestamp    int64      `json:"timestamp"` // milliseconds since epoch
	User         *jiraUser  `json:"user"`
	Issue        *jiraIssue `json:"issue"`
	ChangeLog    *struct {
		Items []struct {
			Field      string `json:"field"`
			FromString string `json:"fromString"`
			ToString   string `json:"toString"`
		} `json:"items"`
	} `json:"changelog"`
}

func (s *Source) processWebhookPayload(body []byte) error {
	var wh jiraWebhookPayload
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal jira webhook: %w", err)
	}

	evType, ok := mapWebhookEventType(wh.WebhookEvent, wh.Issue)
	if !ok {
		slog.Debug("jira webhook: skipping unsupported event", "event", wh.WebhookEvent)
		return nil
	}

	t := time.Now().UTC()
	if wh.Timestamp > 0 {
		t = time.UnixMilli(wh.Timestamp).UTC()
	}

	var actorPtr *string
	if wh.User != nil {
		email := wh.User.EmailAddress
		if email == "" {
			email = wh.User.DisplayName
		}
		actorPtr = s.redact.RedactActor(ptrs.String(email))
	}

	issueKey := ""
	var payloadMap map[string]any

	if wh.Issue != nil {
		issueKey = wh.Issue.Key

		// Extract status transition from changelog if present.
		fromStatus, toStatus := "", ""
		if wh.ChangeLog != nil {
			for _, item := range wh.ChangeLog.Items {
				if item.Field == "status" {
					fromStatus = item.FromString
					toStatus = item.ToString
				}
			}
		}
		if toStatus == "" && wh.Issue.Fields.Status.Name != "" {
			toStatus = wh.Issue.Fields.Status.Name
		}

		payloadMap = s.redact.Apply(map[string]any{
			"issue_key":   issueKey,
			"summary":     wh.Issue.Fields.Summary,
			"issue_type":  wh.Issue.Fields.IssueType.Name,
			"from_status": fromStatus,
			"to_status":   toStatus,
			"event":       wh.WebhookEvent,
		})
	} else {
		payloadMap = s.redact.Apply(map[string]any{
			"event": wh.WebhookEvent,
		})
	}

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceJira,
		Actor:       actorPtr,
		Resource:    ptrs.String(issueKey),
		Payload:     payloadMap,
	})
	return nil
}

// MapWebhookEventType maps Jira webhook event names to canonical event types.
// Exported for testing.
func MapWebhookEventType(webhookEvent string, issue *jiraIssue) (string, bool) {
	return mapWebhookEventType(webhookEvent, issue)
}

func mapWebhookEventType(webhookEvent string, issue *jiraIssue) (string, bool) {
	switch webhookEvent {
	case "jira:issue_created":
		return "change.opened", true
	case "jira:issue_updated":
		// Distinguish common transitions by status name if available.
		if issue != nil && issue.Fields.Status.Name != "" {
			return mapIssueEventType(issue.Fields.Status.Name, issue.Fields.IssueType.Name), true
		}
		return "change.approved", true
	case "jira:issue_deleted":
		return "change.closed", true
	case "jira:version_released":
		return "deploy.completed", true
	case "jira:version_created":
		return "deploy.started", true
	default:
		return "", false
	}
}

// MapIssueEventType maps a Jira status name to a canonical event type from §4.5.
// Exported for testing.
func MapIssueEventType(statusName, issueTypeName string) string {
	return mapIssueEventType(statusName, issueTypeName)
}

func mapIssueEventType(statusName, issueTypeName string) string {
	lower := strings.ToLower(statusName)
	switch {
	case lower == "done" || lower == "closed" || lower == "resolved":
		return "change.approved"
	case lower == "in progress" || lower == "in review":
		return "change.opened"
	case lower == "open" || lower == "to do" || lower == "backlog":
		return "change.opened"
	case strings.Contains(lower, "deploy"):
		return "deploy.started"
	case strings.Contains(lower, "release"):
		return "deploy.completed"
	default:
		return "change.approved"
	}
}

// VerifyWebhookSecret reports whether the Authorization header matches the expected secret.
// The header must have the form "Bearer <secret>" — a bare secret without the prefix is rejected.
// Exported for testing.
func VerifyWebhookSecret(secret, authHeader string) bool {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	return sigverify.SecretEqual(secret, token)
}
