// Package bitbucket collects pull-request and push events from Bitbucket.
//
// It operates in two modes:
//
//  1. Webhook receiver (preferred): Bitbucket sends a POST to the collector's
//     HTTP endpoint. The payload is signed with HMAC-SHA256; the signature
//     appears in the X-Hub-Signature-256 header with a "sha256=" prefix.
//     Verified with sigverify.HexHMACPrefixed(..., "sha256=").
//
//  2. REST poller: GET /2.0/repositories/{workspace}/{repo}/pullrequests with
//     Bearer token auth. Only GET endpoints are called; no mutations.
//     A cursor (updated_on timestamp) persists the high-water mark across
//     restarts so pull requests are never double-emitted.
//
// Supported webhook event keys (X-Event-Key header):
//   - repo:push             -> change.merged  (code was pushed to a branch)
//   - pullrequest:created   -> change.opened
//   - pullrequest:fulfilled -> change.merged  (PR was merged)
//   - pullrequest:rejected  -> change.closed  (PR was declined)
//
// EU note: Bitbucket Cloud (api.bitbucket.org) is a global endpoint with no
// EU-region-specific API host. This is acceptable for the audit-metadata path
// because the collector only reads PR/push metadata, not customer payload data.
// Operators with strict EU data-residency requirements MUST use Bitbucket Data
// Center self-hosted on an EU host and set BaseURL to their EU instance root
// (e.g. "https://bitbucket.example.eu/rest/api/1.0"). The default Cloud URL
// is flagged as a known trade-off in ADR-0015.
//
// Read-only API calls only:
//   - GET /2.0/repositories/{workspace}/{repo}/pullrequests
//
// PII handling: actor (author displayName/nickname) and all payload fields pass
// through redact.Apply / redact.RedactActor before envelope construction. Raw
// payloads are never logged at INFO level (manifest §12.13).
package bitbucket

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

// Source receives Bitbucket webhook events and polls the Bitbucket REST API.
type Source struct {
	cfg         config.BitbucketConfig
	http        *http.Client
	redact      *redact.Redactor
	emit        func(envelope.Event)
	cursorPath  string
	lastUpdated time.Time
}

// New constructs a Bitbucket source. It loads the persisted cursor from disk
// but does not start goroutines or make network calls.
func New(cfg config.BitbucketConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
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

// Register adds the Bitbucket webhook handler to the shared router at /webhook/bitbucket.
// Call this before starting the shared router.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/bitbucket", s.handleWebhook)
}

// RunPoller polls the Bitbucket REST API on the configured interval. It blocks
// until ctx is cancelled.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("bitbucket poller started",
		"base_url", s.cfg.BaseURL,
		"workspace", s.cfg.Workspace,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "bitbucket", s.poll)
}

// loadCursor reads the persisted high-water-mark timestamp from disk.
func (s *Source) loadCursor() {
	if s.cursorPath == "" {
		return
	}
	data, err := os.ReadFile(s.cursorPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("bitbucket: cursor read failed; starting from beginning",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("bitbucket: cursor parse failed; starting from beginning",
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
		slog.Warn("bitbucket: cursor write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("bitbucket: cursor rename failed", "err", err)
	}
}

// poll fetches pull requests updated since the last cursor for every configured
// repository and emits a canonical event for each.
func (s *Source) poll(ctx context.Context) error {
	if s.cfg.Workspace == "" {
		slog.Debug("bitbucket: poller skipped — no workspace configured")
		return nil
	}

	repos := s.cfg.Repos
	if len(repos) == 0 {
		// No explicit repo list: the operator must configure at least one repo
		// slug. Bitbucket Cloud does not support listing workspace repos without
		// additional repository-scoped token permissions; require explicit config.
		slog.Debug("bitbucket: poller skipped — no repos configured; set sources.bitbucket.repos")
		return nil
	}

	var highWater time.Time

	for _, repo := range repos {
		hw, err := s.pollRepo(ctx, repo)
		if err != nil {
			// Log and continue — one failing repo should not block others.
			slog.Error("bitbucket: poll repo failed", "repo", repo, "err", err)
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

	slog.Debug("bitbucket: poll complete")
	return nil
}

// pollRepo fetches pull requests for a single repository slug and emits events.
// Returns the highest updated_on timestamp seen across all pages.
func (s *Source) pollRepo(ctx context.Context, repo string) (time.Time, error) {
	var highWater time.Time

	// Build the base URL for this repository's pull requests.
	// Bitbucket Cloud: /2.0/repositories/{workspace}/{repo}/pullrequests
	// Bitbucket Data Center: /rest/api/1.0/projects/{workspace}/repos/{repo}/pull-requests
	// We target the Cloud path here; Data Center operators can adapt via BaseURL.
	reqURL := fmt.Sprintf("%s/repositories/%s/%s/pullrequests",
		strings.TrimRight(s.cfg.BaseURL, "/"),
		url.PathEscape(s.cfg.Workspace),
		url.PathEscape(repo),
	)

	// Bitbucket Cloud PR list supports ?sort=-updated_on and ?q= filters.
	// We sort descending by updated_on and stop pagination once we pass the cursor.
	q := url.Values{}
	q.Set("sort", "-updated_on")
	q.Set("state", "ALL")
	q.Set("pagelen", "50")
	if !s.lastUpdated.IsZero() {
		// Bitbucket Cloud supports ISO 8601 date filtering via the q parameter.
		q.Set("q", fmt.Sprintf("updated_on > %q", s.lastUpdated.UTC().Format(time.RFC3339)))
	}

	nextURL := reqURL + "?" + q.Encode()

	for nextURL != "" {
		prs, next, err := s.fetchPRPage(ctx, nextURL)
		if err != nil {
			return highWater, err
		}

		for _, pr := range prs {
			ev, ok := s.normalizePR(s.cfg.Workspace, repo, pr)
			if !ok {
				continue
			}
			s.emit(ev)
			if ev.OccurredAt.After(highWater) {
				highWater = ev.OccurredAt
			}
		}

		// Validate the API-supplied next URL against our configured base URL
		// before following it, to avoid sending the Bearer token to an
		// attacker-controlled host embedded in a crafted API response.
		if next == "" {
			break
		}
		if err := validateNextURL(s.cfg.BaseURL, next); err != nil {
			return highWater, fmt.Errorf("bitbucket: pagination next URL rejected: %w", err)
		}
		nextURL = next
	}

	return highWater, nil
}

// bbPRListResponse is the Bitbucket Cloud paginated pull-request list response.
type bbPRListResponse struct {
	Values []bbPullRequest `json:"values"`
	Next   string          `json:"next"`
}

// bbPullRequest is the subset of the Bitbucket pull-request shape we use.
type bbPullRequest struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	State       string    `json:"state"` // OPEN, MERGED, DECLINED, SUPERSEDED
	CreatedOn   time.Time `json:"created_on"`
	UpdatedOn   time.Time `json:"updated_on"`
	Author      *bbUser   `json:"author"`
	Source      bbPRRef   `json:"source"`
	Destination bbPRRef   `json:"destination"`
}

// bbUser is the minimal user shape in Bitbucket payloads.
type bbUser struct {
	DisplayName string `json:"display_name"`
	Nickname    string `json:"nickname"`
}

// bbPRRef is a branch/commit reference within a PR.
type bbPRRef struct {
	Branch     bbBranch     `json:"branch"`
	Repository bbRepository `json:"repository"`
}

type bbBranch struct {
	Name string `json:"name"`
}

type bbRepository struct {
	FullName string `json:"full_name"`
}

func (s *Source) fetchPRPage(ctx context.Context, pageURL string) ([]bbPullRequest, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("bitbucket: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("bitbucket: GET pull requests: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("bitbucket: GET pull requests: unexpected status %d (response body omitted)", resp.StatusCode)
	}

	var result bbPRListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", fmt.Errorf("bitbucket: decode pull requests response: %w", err)
	}
	return result.Values, result.Next, nil
}

// normalizePR maps a Bitbucket pull request to a canonical envelope.Event.
func (s *Source) normalizePR(workspace, repo string, pr bbPullRequest) (envelope.Event, bool) {
	t := pr.UpdatedOn.UTC()
	if t.IsZero() {
		t = pr.CreatedOn.UTC()
	}
	if t.IsZero() {
		return envelope.Event{}, false
	}

	evType := mapPRState(pr.State)

	var actorPtr *string
	if pr.Author != nil {
		name := pr.Author.Nickname
		if name == "" {
			name = pr.Author.DisplayName
		}
		actorPtr = s.redact.RedactActor(ptrs.String(name))
	}

	resource := fmt.Sprintf("%s/%s#%d", workspace, repo, pr.ID)

	payload := s.redact.Apply(map[string]any{
		"pr_id":         pr.ID,
		"title":         pr.Title,
		"state":         pr.State,
		"source_branch": pr.Source.Branch.Name,
		"dest_branch":   pr.Destination.Branch.Name,
		"repo":          fmt.Sprintf("%s/%s", workspace, repo),
	})

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceBitbucket,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}, true
}

// handleWebhook is the HTTP handler for incoming Bitbucket webhook payloads.
// It verifies X-Hub-Signature-256 ("sha256=" prefix, HMAC-SHA256) before
// dispatching on the X-Event-Key header.
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

	// Verify HMAC-SHA256 signature in X-Hub-Signature-256 when secret is configured.
	if s.cfg.WebhookSecret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !sigverify.HexHMACPrefixed([]byte(s.cfg.WebhookSecret), body, sig, "sha256=") {
			slog.Warn("bitbucket webhook: invalid X-Hub-Signature-256")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	eventKey := r.Header.Get("X-Event-Key")
	if err := s.processWebhookPayload(eventKey, body); err != nil {
		slog.Error("bitbucket webhook: process failed", "event_key", eventKey, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// bbWebhookPush is the payload shape for repo:push events.
type bbWebhookPush struct {
	Repository bbWebhookRepo `json:"repository"`
	Push       struct {
		Changes []struct {
			New *struct {
				Name   string   `json:"name"`
				Target bbCommit `json:"target"`
				Type   string   `json:"type"` // branch, tag
			} `json:"new"`
		} `json:"changes"`
	} `json:"push"`
	Actor *bbUser `json:"actor"`
}

// bbCommit holds minimal commit metadata within a push payload.
type bbCommit struct {
	Hash   string    `json:"hash"`
	Date   time.Time `json:"date"`
	Author struct {
		User *bbUser `json:"user"`
		Raw  string  `json:"raw"` // "Name <email@example.com>"
	} `json:"author"`
}

// bbWebhookPR is the payload shape for pullrequest:* events.
type bbWebhookPR struct {
	Repository  bbWebhookRepo `json:"repository"`
	PullRequest bbPullRequest `json:"pullrequest"`
	Actor       *bbUser       `json:"actor"`
}

// bbWebhookRepo is the minimal repository shape in webhook payloads.
type bbWebhookRepo struct {
	FullName string `json:"full_name"` // "workspace/repo"
	Name     string `json:"name"`
}

// processWebhookPayload parses the body for the given X-Event-Key and emits
// the appropriate canonical event.
func (s *Source) processWebhookPayload(eventKey string, body []byte) error {
	evType, ok := MapWebhookEventType(eventKey)
	if !ok {
		slog.Debug("bitbucket webhook: skipping unsupported event", "event_key", eventKey)
		return nil
	}

	switch eventKey {
	case "repo:push":
		return s.processPushPayload(evType, body)
	case "pullrequest:created", "pullrequest:fulfilled", "pullrequest:rejected":
		return s.processPRPayload(evType, body)
	default:
		return nil
	}
}

func (s *Source) processPushPayload(evType string, body []byte) error {
	var wh bbWebhookPush
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal bitbucket push: %w", err)
	}

	t := time.Now().UTC()
	var commitHash string

	// Use the timestamp and hash from the first change's target commit if available.
	if len(wh.Push.Changes) > 0 && wh.Push.Changes[0].New != nil {
		target := wh.Push.Changes[0].New.Target
		if !target.Date.IsZero() {
			t = target.Date.UTC()
		}
		commitHash = target.Hash
	}

	// Actor: use the webhook actor field; fall back to commit author.
	var actorPtr *string
	if wh.Actor != nil {
		name := wh.Actor.Nickname
		if name == "" {
			name = wh.Actor.DisplayName
		}
		actorPtr = s.redact.RedactActor(ptrs.String(name))
	}

	// Resource: workspace/repo path derived from repository full name.
	resource := wh.Repository.FullName

	payload := s.redact.Apply(map[string]any{
		"event_key":   "repo:push",
		"repo":        wh.Repository.FullName,
		"commit_hash": commitHash,
	})

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceBitbucket,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

func (s *Source) processPRPayload(evType string, body []byte) error {
	var wh bbWebhookPR
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal bitbucket pullrequest: %w", err)
	}

	pr := wh.PullRequest

	t := pr.UpdatedOn.UTC()
	if t.IsZero() {
		t = pr.CreatedOn.UTC()
	}
	if t.IsZero() {
		t = time.Now().UTC()
	}

	// Actor: prefer the webhook actor (the user who triggered the event);
	// fall back to the PR author.
	var actorPtr *string
	actor := wh.Actor
	if actor == nil {
		actor = pr.Author
	}
	if actor != nil {
		name := actor.Nickname
		if name == "" {
			name = actor.DisplayName
		}
		actorPtr = s.redact.RedactActor(ptrs.String(name))
	}

	// Resource: workspace/repo#id, derived from the destination repo full name.
	repoFull := wh.Repository.FullName
	if repoFull == "" {
		repoFull = pr.Destination.Repository.FullName
	}
	resource := fmt.Sprintf("%s#%d", repoFull, pr.ID)

	payload := s.redact.Apply(map[string]any{
		"pr_id":         pr.ID,
		"title":         pr.Title,
		"state":         pr.State,
		"source_branch": pr.Source.Branch.Name,
		"dest_branch":   pr.Destination.Branch.Name,
		"repo":          repoFull,
	})

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceBitbucket,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

// validateNextURL checks that the pagination next URL returned by the API has
// the same scheme and host as the configured base URL. This prevents the Bearer
// token from being forwarded to an unintended host embedded in an API response.
func validateNextURL(baseURL, nextURL string) error {
	base, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("cannot parse base URL %q: %w", baseURL, err)
	}
	next, err := url.Parse(nextURL)
	if err != nil {
		return fmt.Errorf("cannot parse next URL %q: %w", nextURL, err)
	}
	if base.Scheme != next.Scheme || base.Host != next.Host {
		return fmt.Errorf("next URL host %q does not match base URL host %q", next.Host, base.Host)
	}
	return nil
}

// MapWebhookEventType maps a Bitbucket X-Event-Key value to a canonical event
// type from §4.5. Returns ("", false) for unsupported event keys.
// Exported for testing.
func MapWebhookEventType(eventKey string) (string, bool) {
	switch eventKey {
	case "repo:push":
		// A branch push is a code change landing on a ref; treat as change.merged
		// (code integrated into a branch) per the taxonomy guidance for GitOps sources.
		return "change.merged", true
	case "pullrequest:created":
		return "change.opened", true
	case "pullrequest:fulfilled":
		// Bitbucket uses "fulfilled" to mean the PR was merged.
		return "change.merged", true
	case "pullrequest:rejected":
		// Bitbucket uses "rejected" to mean the PR was declined.
		return "change.closed", true
	default:
		return "", false
	}
}

// mapPRState maps a Bitbucket pull-request state string to a canonical event
// type. Used by the poller path.
func mapPRState(state string) string {
	switch strings.ToUpper(state) {
	case "OPEN":
		return "change.opened"
	case "MERGED":
		return "change.merged"
	case "DECLINED", "SUPERSEDED":
		return "change.closed"
	default:
		return "change.opened"
	}
}

// VerifySignature reports whether the X-Hub-Signature-256 header is a valid
// HMAC-SHA256 of body using secret. The header must have the "sha256=" prefix.
// Exported for testing.
func VerifySignature(secret string, body []byte, header string) bool {
	return sigverify.HexHMACPrefixed([]byte(secret), body, header, "sha256=")
}

// HandleWebhookForTest exposes the internal webhook handler for use in external
// test packages. This avoids requiring a running HTTP server in unit tests.
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
