// Package gitlab collects merge-request and deployment events from GitLab.
//
// It operates in two modes:
//
//  1. Webhook receiver (preferred): GitLab pushes events to the collector's
//     HTTP endpoint. The collector verifies the X-Gitlab-Token shared secret
//     via constant-time equality before processing any payload.
//
//  2. Polling fallback: if webhook delivery cannot be configured, the collector
//     polls the GitLab REST API for recent merge requests and deployments.
//
// Read-only API calls only:
//
//	GET /api/v4/projects                              (list accessible projects)
//	GET /api/v4/projects/:id/merge_requests           (list merge requests)
//	GET /api/v4/projects/:id/deployments              (list deployments)
//
// The collector never calls any POST, PUT, or DELETE endpoint. No third-party
// client library is used — the GitLab REST surface is small enough for stdlib
// net/http and we avoid adding a new module dependency.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/ptrs"
	"operitas.eu/collector/internal/redact"
	internalrt "operitas.eu/collector/internal/runtime"
	"operitas.eu/collector/internal/sigverify"
)

// Source receives GitLab webhook events and/or polls the REST API.
type Source struct {
	cfg        config.GitLabConfig
	http       *http.Client
	redact     *redact.Redactor
	emit       func(envelope.Event)
	cursorPath string
	// lastPollAt is the start time of the last successful poll, persisted to
	// cursorPath so restarts resume from where they left off.
	lastPollAt time.Time
}

// New constructs a GitLab source.
func New(cfg config.GitLabConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
	s := &Source{
		cfg: cfg,
		http: &http.Client{
			// Never follow redirects. A 302 from the GitLab API could forward
			// the PRIVATE-TOKEN header to an attacker-controlled host if the
			// redirect crosses a host boundary. The caller sees the 3xx and
			// treats it as a non-2xx error — no credentials are forwarded.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 20 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				MaxIdleConnsPerHost:   8,
			},
		},
		redact:     r,
		emit:       emit,
		cursorPath: cfg.CursorPath,
	}
	s.loadCursor()
	return s
}

// WebhookActive reports whether the webhook receiver is configured. When true,
// the poller must NOT be started to prevent the same event appearing twice in
// the tamper-evident ledger. main.go gates RunPoller on !s.WebhookActive().
func (s *Source) WebhookActive() bool {
	return s.cfg.WebhookSecret != ""
}

func (s *Source) loadCursor() {
	if s.cursorPath == "" {
		return
	}
	data, err := os.ReadFile(s.cursorPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("gitlab: cursor read failed; starting from lookback window",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("gitlab: cursor parse failed; starting from lookback window",
			"path", s.cursorPath, "err", err)
		return
	}
	s.lastPollAt = t
}

// writeCursor persists the lastPollAt timestamp durably (open+write+fsync+
// close+rename+dir-fsync), matching the WAL pattern in internal/transport/wal.go.
func (s *Source) writeCursor() {
	if s.cursorPath == "" || s.lastPollAt.IsZero() {
		return
	}
	tmp := s.cursorPath + ".tmp"
	val := s.lastPollAt.UTC().Format(time.RFC3339Nano)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		slog.Warn("gitlab: cursor open tmp failed", "err", err)
		return
	}
	if _, err := f.Write([]byte(val)); err != nil {
		f.Close()
		slog.Warn("gitlab: cursor write failed", "err", err)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		slog.Warn("gitlab: cursor fsync failed", "err", err)
		return
	}
	if err := f.Close(); err != nil {
		slog.Warn("gitlab: cursor close failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("gitlab: cursor rename failed", "err", err)
		return
	}
	if d, err := os.Open(filepath.Dir(s.cursorPath)); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// RunWebhook starts the webhook HTTP server. Blocks until ctx is cancelled.
func (s *Source) RunWebhook(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/gitlab", s.handleWebhook)
	addr := fmt.Sprintf(":%d", s.cfg.WebhookPort)
	slog.Info("gitlab webhook server starting", "addr", addr)
	return internalrt.RunWebhookServer(ctx, addr, mux)
}

// RunPoller polls the GitLab API on the configured interval. Blocks until
// ctx is cancelled.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("gitlab poller started",
		"base_url", s.cfg.BaseURL,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "gitlab", s.poll)
}

func (s *Source) poll(ctx context.Context) error {
	pollStart := time.Now().UTC()

	// Use the persisted cursor when available; fall back to a 2x-interval
	// lookback window on first run to avoid a flood of historical events.
	since := s.lastPollAt
	if since.IsZero() {
		since = pollStart.Add(-s.cfg.PollInterval * 2)
	}

	projects, err := s.listProjects(ctx)
	if err != nil {
		return err
	}

	// Fail-closed: track whether any per-project fetch failed. If so, the
	// cursor is NOT advanced so PollLoop retries the same window next tick.
	// At-least-once with ledger-level deduplication is correct; a gap is not.
	var pollErr error
	for _, p := range projects {
		if err := s.pollMRs(ctx, p, since); err != nil {
			slog.Error("gitlab: poll MRs failed", "project", p.path(), "err", err)
			pollErr = err
		}
		if err := s.pollDeployments(ctx, p, since); err != nil {
			slog.Error("gitlab: poll deployments failed", "project", p.path(), "err", err)
			pollErr = err
		}
	}
	if pollErr != nil {
		// Return an error so PollLoop logs and retries; the cursor stays at
		// the previous position so the failed window is re-covered next tick.
		return fmt.Errorf("gitlab: poll cycle incomplete, cursor not advanced: %w", pollErr)
	}

	// All projects fetched successfully: advance the durable cursor.
	s.lastPollAt = pollStart
	s.writeCursor()
	return nil
}

// project is the minimal subset of /projects we read.
type project struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
}

func (p project) path() string {
	if p.PathWithNamespace != "" {
		return p.PathWithNamespace
	}
	return strconv.Itoa(p.ID)
}

// listProjects returns the list of projects to poll. If cfg.Projects is set,
// those are resolved directly (numeric ID or url-encoded path). Otherwise the
// full set of projects the token can read is enumerated via
// GET /projects?membership=true — a read-only call.
func (s *Source) listProjects(ctx context.Context) ([]project, error) {
	if len(s.cfg.Projects) > 0 {
		out := make([]project, 0, len(s.cfg.Projects))
		for _, p := range s.cfg.Projects {
			if id, err := strconv.Atoi(p); err == nil {
				out = append(out, project{ID: id})
				continue
			}
			out = append(out, project{PathWithNamespace: p})
		}
		return out, nil
	}

	var projects []project
	page := 1
	for {
		q := url.Values{}
		q.Set("membership", "true")
		q.Set("simple", "true")
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))

		var pageProjects []project
		next, err := s.getJSON(ctx, "/projects?"+q.Encode(), &pageProjects)
		if err != nil {
			return nil, fmt.Errorf("list projects: %w", err)
		}
		projects = append(projects, pageProjects...)
		if next == 0 {
			break
		}
		page = next
	}
	return projects, nil
}

// mergeRequest is the minimal subset of /merge_requests we read.
type mergeRequest struct {
	IID          int        `json:"iid"`
	Title        string     `json:"title"`
	State        string     `json:"state"`
	WebURL       string     `json:"web_url"`
	SourceBranch string     `json:"source_branch"`
	TargetBranch string     `json:"target_branch"`
	UpdatedAt    time.Time  `json:"updated_at"`
	MergedAt     *time.Time `json:"merged_at"`
	Author       struct {
		Username string `json:"username"`
	} `json:"author"`
	SHA string `json:"sha"`
}

// pollMRs fetches MRs updated since `since`.
func (s *Source) pollMRs(ctx context.Context, p project, since time.Time) error {
	page := 1
	for {
		q := url.Values{}
		q.Set("state", "all")
		q.Set("order_by", "updated_at")
		q.Set("sort", "desc")
		q.Set("updated_after", since.Format(time.RFC3339))
		q.Set("per_page", "50")
		q.Set("page", strconv.Itoa(page))

		path := fmt.Sprintf("/projects/%s/merge_requests?%s", url.PathEscape(p.path()), q.Encode())

		var mrs []mergeRequest
		next, err := s.getJSON(ctx, path, &mrs)
		if err != nil {
			return fmt.Errorf("list MRs: %w", err)
		}
		for _, mr := range mrs {
			s.emit(s.normalizeMR(p, mr))
		}
		if next == 0 {
			return nil
		}
		page = next
	}
}

// deployment is the minimal subset of /deployments we read.
type deployment struct {
	ID          int       `json:"id"`
	IID         int       `json:"iid"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Environment struct {
		Name string `json:"name"`
	} `json:"environment"`
	Deployable struct {
		Ref    string `json:"ref"`
		Tag    bool   `json:"tag"`
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	} `json:"deployable"`
}

// pollDeployments fetches deployments updated since `since`.
func (s *Source) pollDeployments(ctx context.Context, p project, since time.Time) error {
	page := 1
	for {
		q := url.Values{}
		q.Set("updated_after", since.Format(time.RFC3339))
		q.Set("order_by", "updated_at")
		q.Set("sort", "desc")
		q.Set("per_page", "50")
		q.Set("page", strconv.Itoa(page))

		path := fmt.Sprintf("/projects/%s/deployments?%s", url.PathEscape(p.path()), q.Encode())

		var deps []deployment
		next, err := s.getJSON(ctx, path, &deps)
		if err != nil {
			return fmt.Errorf("list deployments: %w", err)
		}
		for _, d := range deps {
			s.emit(s.normalizeDeployment(p, d))
		}
		if next == 0 {
			return nil
		}
		page = next
	}
}

// getJSON does a GET request and decodes the JSON body into out. The PRIVATE-TOKEN
// header carries the access token. Returns the X-Next-Page page number (0 if no
// further pages). path must start with "/" — it is appended to cfg.BaseURL.
func (s *Source) getJSON(ctx context.Context, path string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.BaseURL+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("PRIVATE-TOKEN", s.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, fmt.Errorf("gitlab GET %s: unexpected status %d (response body omitted)", path, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return 0, fmt.Errorf("decode %s: %w", path, err)
	}

	next := 0
	if v := resp.Header.Get("X-Next-Page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			next = n
		}
	}
	return next, nil
}

func (s *Source) normalizeMR(p project, mr mergeRequest) envelope.Event {
	evType := "change.opened"
	t := mr.UpdatedAt.UTC()
	switch mr.State {
	case "merged":
		evType = "change.merged"
		if mr.MergedAt != nil {
			t = mr.MergedAt.UTC()
		}
	case "closed":
		evType = "change.closed"
	}

	actor := s.redact.RedactActor(ptrs.String(mr.Author.Username))
	resource := fmt.Sprintf("%s!%d", p.path(), mr.IID)

	payload := s.redact.Apply(map[string]any{
		"iid":           mr.IID,
		"title":         mr.Title,
		"state":         mr.State,
		"source_branch": mr.SourceBranch,
		"target_branch": mr.TargetBranch,
		"sha":           mr.SHA,
		"project":       p.path(),
		"web_url":       mr.WebURL,
	})

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceGitLab,
		Actor:       actor,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}
}

func (s *Source) normalizeDeployment(p project, d deployment) envelope.Event {
	evType := deployEventType(d.Status)
	actor := s.redact.RedactActor(ptrs.String(d.Deployable.User.Username))
	resource := fmt.Sprintf("%s@%s", p.path(), d.Environment.Name)

	// Prefer updated_at over created_at so status transitions get a fresh timestamp;
	// fall back to created_at when updated_at is unset.
	t := d.UpdatedAt.UTC()
	if t.IsZero() {
		t = d.CreatedAt.UTC()
	}

	payload := s.redact.Apply(map[string]any{
		"deployment_id":  d.ID,
		"deployment_iid": d.IID,
		"environment":    d.Environment.Name,
		"ref":            d.Deployable.Ref,
		"sha":            d.Deployable.Commit.ID,
		"status":         d.Status,
		"project":        p.path(),
	})

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceGitLab,
		Actor:       actor,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}
}

// deployEventType maps a GitLab deployment status to our event_type enum.
// Reference: https://docs.gitlab.com/ee/api/deployments.html#list-project-deployments
func deployEventType(status string) string {
	switch status {
	case "success":
		return "deploy.completed"
	case "failed", "canceled":
		return "deploy.failed"
	default:
		// "created", "running", "blocked" — all in-flight states.
		return "deploy.started"
	}
}

// handleWebhook is the HTTP handler for incoming GitLab webhook payloads.
// Authentication is via the X-Gitlab-Token shared secret (plain equality,
// constant-time).
func (s *Source) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	if s.cfg.WebhookSecret != "" {
		got := r.Header.Get("X-Gitlab-Token")
		if !sigverify.SecretEqual(s.cfg.WebhookSecret, got) {
			slog.Warn("gitlab webhook: invalid token")
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
	}

	eventType := r.Header.Get("X-Gitlab-Event")
	if eventType == "" {
		http.Error(w, "missing X-Gitlab-Event", http.StatusBadRequest)
		return
	}

	if err := s.processWebhookPayload(eventType, body); err != nil {
		slog.Error("gitlab webhook: process payload failed", "event", eventType, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Source) processWebhookPayload(eventType string, body []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("unmarshal webhook payload: %w", err)
	}

	switch eventType {
	case "Merge Request Hook":
		return s.processMRWebhook(raw)
	case "Deployment Hook":
		return s.processDeploymentWebhook(raw)
	default:
		// Skip silently — pipeline/push/issue hooks etc are outside MVP scope.
		slog.Debug("gitlab webhook: skipping unknown event type", "event_type", eventType)
		return nil
	}
}

func (s *Source) processMRWebhook(raw map[string]any) error {
	attrs, _ := raw["object_attributes"].(map[string]any)
	if attrs == nil {
		return nil
	}
	action, _ := attrs["action"].(string)

	evType := ""
	switch action {
	case "open", "reopen":
		evType = "change.opened"
	case "close":
		evType = "change.closed"
	case "merge":
		evType = "change.merged"
	default:
		// "update" and any unknown actions are intentionally skipped.
		return nil
	}

	iid := intFromAny(attrs["iid"])
	title, _ := attrs["title"].(string)
	state, _ := attrs["state"].(string)
	source, _ := attrs["source_branch"].(string)
	target, _ := attrs["target_branch"].(string)
	sha, _ := attrs["last_commit"].(map[string]any)
	webURL, _ := attrs["url"].(string)
	commitSHA := ""
	if sha != nil {
		commitSHA, _ = sha["id"].(string)
	}

	projectPath := ""
	if pj, ok := raw["project"].(map[string]any); ok {
		projectPath, _ = pj["path_with_namespace"].(string)
	}
	p := project{PathWithNamespace: projectPath}

	var actor *string
	if user, ok := raw["user"].(map[string]any); ok {
		name, _ := user["username"].(string)
		actor = s.redact.RedactActor(ptrs.String(name))
	}

	resource := fmt.Sprintf("%s!%d", p.path(), iid)

	payload := s.redact.Apply(map[string]any{
		"iid":           iid,
		"title":         title,
		"state":         state,
		"source_branch": source,
		"target_branch": target,
		"sha":           commitSHA,
		"project":       p.path(),
		"web_url":       webURL,
	})

	t := time.Now().UTC()
	if ts, _ := attrs["updated_at"].(string); ts != "" {
		if parsed, err := parseGitLabTime(ts); err == nil {
			t = parsed
		}
	}

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceGitLab,
		Actor:       actor,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

func (s *Source) processDeploymentWebhook(raw map[string]any) error {
	status, _ := raw["status"].(string)
	if status == "" {
		return nil
	}
	evType := deployEventType(status)

	deploymentID := intFromAny(raw["deployment_id"])
	env, _ := raw["environment"].(string)
	ref, _ := raw["ref"].(string)
	sha, _ := raw["sha"].(string)

	projectPath := ""
	if pj, ok := raw["project"].(map[string]any); ok {
		projectPath, _ = pj["path_with_namespace"].(string)
	}
	p := project{PathWithNamespace: projectPath}

	var actor *string
	if user, ok := raw["user"].(map[string]any); ok {
		name, _ := user["username"].(string)
		actor = s.redact.RedactActor(ptrs.String(name))
	}

	resource := fmt.Sprintf("%s@%s", p.path(), env)

	payload := s.redact.Apply(map[string]any{
		"deployment_id": deploymentID,
		"environment":   env,
		"ref":           ref,
		"sha":           sha,
		"status":        status,
		"project":       p.path(),
	})

	t := time.Now().UTC()
	if ts, _ := raw["status_changed_at"].(string); ts != "" {
		if parsed, err := parseGitLabTime(ts); err == nil {
			t = parsed
		}
	}

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceGitLab,
		Actor:       actor,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

// intFromAny coerces a JSON-decoded any to int, handling float64 (the default
// for json.Unmarshal into map[string]any) and pre-typed ints.
func intFromAny(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	default:
		return 0
	}
}

// parseGitLabTime parses GitLab's webhook timestamp format. Webhook payloads
// use "2006-01-02 15:04:05 UTC" rather than RFC3339, while REST API responses
// use RFC3339. Try both.
func parseGitLabTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02 15:04:05 UTC", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %q", s)
}

// VerifyToken reports whether got matches want. Exported for testing only.
func VerifyToken(want, got string) bool {
	return sigverify.SecretEqual(want, got)
}
