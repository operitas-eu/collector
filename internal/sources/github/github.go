// Package github collects PR and deployment events from GitHub.
//
// It operates in two modes:
//
//  1. Webhook receiver (preferred): GitHub pushes events to the collector's
//     HTTP endpoint. The collector verifies the HMAC-SHA256 signature before
//     processing any payload.
//
//  2. Polling fallback: if webhook delivery cannot be configured, the collector
//     polls the GitHub REST API for recent PRs and deployments.
//
// Read-only API calls only:
//   - GET /repos/{owner}/{repo}/pulls                   (list pull requests)
//   - GET /repos/{owner}/{repo}/deployments             (list deployments)
//   - GET /repos/{owner}/{repo}/deployments/{id}/statuses (deployment status)
//   - GET /orgs/{org}/repos                             (list org repos)
//
// The collector never calls any POST, PUT, PATCH, or DELETE endpoint.
// It uses the github.com/google/go-github library for type-safe REST access.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gogithub "github.com/google/go-github/v63/github"
	"golang.org/x/oauth2"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/ptrs"
	"operitas.eu/collector/internal/redact"
	internalrt "operitas.eu/collector/internal/runtime"
	"operitas.eu/collector/internal/sigverify"
)

// Source receives GitHub webhook events and/or polls the REST API.
type Source struct {
	cfg        config.GitHubConfig
	client     *gogithub.Client
	redact     *redact.Redactor
	emit       func(envelope.Event)
	cursorPath string
	// lastPollAt is the start time of the last successful poll, persisted to
	// cursorPath so restarts resume from where they left off.
	lastPollAt time.Time
}

// New constructs a GitHub source. It creates a read-only authenticated GitHub
// client using the PAT from config.
func New(cfg config.GitHubConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
	httpCl := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   8,
		},
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpCl)
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Token})
	tc := oauth2.NewClient(ctx, ts)
	// Never follow redirects. The oauth2 transport adds Authorization: Bearer
	// on every RoundTrip — including on redirected requests — so a 302 from
	// the GitHub API would exfiltrate the token to the redirect destination.
	// Setting CheckRedirect on the outer *http.Client prevents all auto-following.
	tc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	gh := gogithub.NewClient(tc)

	s := &Source{
		cfg:        cfg,
		client:     gh,
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
			slog.Warn("github: cursor read failed; starting from lookback window",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("github: cursor parse failed; starting from lookback window",
			"path", s.cursorPath, "err", err)
		return
	}
	s.lastPollAt = t
}

// writeCursor persists the lastPollAt timestamp using the same atomic
// open+write+fsync+close+rename+dir-fsync pattern as internal/transport/wal.go
// to survive crashes without leaving a torn file in place of a good cursor.
func (s *Source) writeCursor() {
	if s.cursorPath == "" || s.lastPollAt.IsZero() {
		return
	}
	tmp := s.cursorPath + ".tmp"
	val := s.lastPollAt.UTC().Format(time.RFC3339Nano)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		slog.Warn("github: cursor open tmp failed", "err", err)
		return
	}
	if _, err := f.Write([]byte(val)); err != nil {
		f.Close()
		slog.Warn("github: cursor write failed", "err", err)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		slog.Warn("github: cursor fsync failed", "err", err)
		return
	}
	if err := f.Close(); err != nil {
		slog.Warn("github: cursor close failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("github: cursor rename failed", "err", err)
		return
	}
	if d, err := os.Open(filepath.Dir(s.cursorPath)); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// RunWebhook starts the webhook HTTP server. It blocks until ctx is cancelled.
// Events are verified via HMAC-SHA256 before processing.
func (s *Source) RunWebhook(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/github", s.handleWebhook)
	addr := fmt.Sprintf(":%d", s.cfg.WebhookPort)
	slog.Info("github webhook server starting", "addr", addr)
	return internalrt.RunWebhookServer(ctx, addr, mux)
}

// RunPoller polls the GitHub API on the configured interval. It blocks until
// ctx is cancelled.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("github poller started",
		"org", s.cfg.Org,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "github", s.poll)
}

func (s *Source) poll(ctx context.Context) error {
	pollStart := time.Now().UTC()

	// Use the persisted cursor when available; fall back to a 2x-interval
	// lookback window on first run (matches the pre-cursor behaviour and
	// avoids a flood of historical events on initial deployment).
	since := s.lastPollAt
	if since.IsZero() {
		since = pollStart.Add(-s.cfg.PollInterval * 2)
	}

	repos, err := s.listRepos(ctx)
	if err != nil {
		return err
	}

	// Fail-closed: track whether any per-repo fetch failed. If so, the cursor
	// is NOT advanced so PollLoop retries the same [since, now] window on the
	// next tick. At-least-once delivery with possible ledger-deduplicated
	// duplicates is correct; a permanent gap is permanent evidence loss.
	var pollErr error
	for _, repo := range repos {
		if err := s.pollPRs(ctx, repo, since); err != nil {
			slog.Error("github: poll PRs failed", "repo", repo, "err", err)
			pollErr = err
		}
		if err := s.pollDeployments(ctx, repo, since); err != nil {
			slog.Error("github: poll deployments failed", "repo", repo, "err", err)
			pollErr = err
		}
	}
	if pollErr != nil {
		// Return an error so PollLoop logs and retries; the cursor stays at
		// the previous position so the failed window is re-covered next tick.
		return fmt.Errorf("github: poll cycle incomplete, cursor not advanced: %w", pollErr)
	}

	// All repos fetched successfully: advance the durable cursor.
	s.lastPollAt = pollStart
	s.writeCursor()
	return nil
}

// listRepos returns the list of repositories to poll. If cfg.Repos is set,
// those are used directly. Otherwise, all repos in the org are listed via
// GET /orgs/{org}/repos — a read-only call.
func (s *Source) listRepos(ctx context.Context) ([]string, error) {
	if len(s.cfg.Repos) > 0 {
		return s.cfg.Repos, nil
	}

	// GET /orgs/{org}/repos — read-only.
	var repos []string
	opts := &gogithub.RepositoryListByOrgOptions{
		ListOptions: gogithub.ListOptions{PerPage: 100},
	}
	for {
		page, resp, err := s.client.Repositories.ListByOrg(ctx, s.cfg.Org, opts)
		if err != nil {
			return nil, fmt.Errorf("list org repos: %w", err)
		}
		for _, r := range page {
			repos = append(repos, r.GetName())
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return repos, nil
}

// pollPRs fetches recently updated pull requests via GET /repos/{owner}/{repo}/pulls.
func (s *Source) pollPRs(ctx context.Context, repo string, since time.Time) error {
	// GET /repos/{owner}/{repo}/pulls — read-only.
	opts := &gogithub.PullRequestListOptions{
		State:       "all",
		Sort:        "updated",
		Direction:   "desc",
		ListOptions: gogithub.ListOptions{PerPage: 50},
	}

	for {
		prs, resp, err := s.client.PullRequests.List(ctx, s.cfg.Org, repo, opts)
		if err != nil {
			return fmt.Errorf("list PRs: %w", err)
		}

		stop := false
		for _, pr := range prs {
			if pr.GetUpdatedAt().Before(since) {
				stop = true
				break
			}
			s.emit(s.normalizePR(repo, pr))
		}
		if stop || resp == nil || resp.NextPage == 0 {
			return nil
		}
		opts.Page = resp.NextPage
	}
}

// pollDeployments fetches recent deployments via GET /repos/{owner}/{repo}/deployments.
func (s *Source) pollDeployments(ctx context.Context, repo string, since time.Time) error {
	opts := &gogithub.DeploymentsListOptions{
		ListOptions: gogithub.ListOptions{PerPage: 50},
	}

	deployments, _, err := s.client.Repositories.ListDeployments(ctx, s.cfg.Org, repo, opts)
	if err != nil {
		return fmt.Errorf("list deployments: %w", err)
	}

	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, d := range deployments {
		if d.GetCreatedAt().Before(since) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d *gogithub.Deployment) {
			defer wg.Done()
			defer func() { <-sem }()
			statuses, _, err := s.client.Repositories.ListDeploymentStatuses(
				ctx, s.cfg.Org, repo, d.GetID(),
				&gogithub.ListOptions{PerPage: 10},
			)
			if err != nil {
				slog.Warn("github: list deployment statuses failed",
					"repo", repo,
					"deployment_id", d.GetID(),
					"err", err,
				)
			}
			s.emit(s.normalizeDeployment(repo, d, statuses))
		}(d)
	}
	wg.Wait()
	return nil
}

func (s *Source) normalizePR(repo string, pr *gogithub.PullRequest) envelope.Event {
	evType := "change.merged"

	actor := pr.GetUser().GetLogin()
	actorRedacted := s.redact.RedactActor(ptrs.String(actor))

	payload := map[string]any{
		"number":   pr.GetNumber(),
		"title":    pr.GetTitle(),
		"state":    pr.GetState(),
		"merged":   pr.GetMerged(),
		"base_ref": pr.GetBase().GetRef(),
		"head_ref": pr.GetHead().GetRef(),
		"head_sha": pr.GetHead().GetSHA(),
		"repo":     repo,
		"org":      s.cfg.Org,
		"html_url": pr.GetHTMLURL(),
	}
	payload = s.redact.Apply(payload)

	t := pr.GetUpdatedAt().UTC()
	if pr.GetMergedAt() != (gogithub.Timestamp{}) {
		t = pr.GetMergedAt().UTC()
	}

	resource := fmt.Sprintf("%s/%s#%d", s.cfg.Org, repo, pr.GetNumber())

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceGitHub,
		Actor:       actorRedacted,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}
}

func (s *Source) normalizeDeployment(repo string, d *gogithub.Deployment, statuses []*gogithub.DeploymentStatus) envelope.Event {
	evType := "deploy.started"
	var latestState string
	if len(statuses) > 0 {
		latestState = statuses[0].GetState()
		switch latestState {
		case "success":
			evType = "deploy.completed"
		case "failure", "error":
			evType = "deploy.failed"
		case "inactive":
			evType = "deploy.rolled_back"
		}
	}

	actor := d.GetCreator().GetLogin()
	actorRedacted := s.redact.RedactActor(ptrs.String(actor))

	resource := fmt.Sprintf("%s/%s@%s", s.cfg.Org, repo, d.GetEnvironment())

	payload := map[string]any{
		"deployment_id": d.GetID(),
		"environment":   d.GetEnvironment(),
		"ref":           d.GetRef(),
		"sha":           d.GetSHA(),
		"task":          d.GetTask(),
		"state":         latestState,
		"repo":          repo,
		"org":           s.cfg.Org,
	}
	payload = s.redact.Apply(payload)

	return envelope.Event{
		OccurredAt:  d.GetCreatedAt().UTC(),
		EventType:   evType,
		EventSource: envelope.SourceGitHub,
		Actor:       actorRedacted,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}
}

// handleWebhook is the HTTP handler for incoming GitHub webhook payloads.
// It verifies the HMAC-SHA256 signature before processing.
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

	// Verify HMAC-SHA256 signature from the X-Hub-Signature-256 header.
	if s.cfg.WebhookSecret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if !verifyGitHubSignature([]byte(s.cfg.WebhookSecret), body, sig) {
			slog.Warn("github webhook: invalid signature")
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
	}

	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		http.Error(w, "missing X-GitHub-Event", http.StatusBadRequest)
		return
	}

	if err := s.processWebhookPayload(eventType, body); err != nil {
		slog.Error("github webhook: process payload failed", "event", eventType, "err", err)
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
	case "pull_request":
		return s.processPRWebhook(raw)
	case "deployment", "deployment_status":
		return s.processDeploymentWebhook(eventType, raw)
	default:
		// Unknown event type: skip silently to avoid noise from events outside
		// the MVP scope (manifest §10.1).
		slog.Debug("github webhook: skipping unknown event type", "event_type", eventType)
		return nil
	}
}

func (s *Source) processPRWebhook(raw map[string]any) error {
	action, _ := raw["action"].(string)
	if action != "closed" && action != "merged" && action != "opened" {
		return nil
	}

	pr, _ := raw["pull_request"].(map[string]any)
	if pr == nil {
		return nil
	}

	repoMap, _ := raw["repository"].(map[string]any)
	repo := ""
	if repoMap != nil {
		repo, _ = repoMap["name"].(string)
	}

	var actor *string
	if sender, ok := raw["sender"].(map[string]any); ok {
		login, _ := sender["login"].(string)
		actor = s.redact.RedactActor(ptrs.String(login))
	}

	number, _ := pr["number"].(float64)
	title, _ := pr["title"].(string)
	merged, _ := pr["merged"].(bool)
	htmlURL, _ := pr["html_url"].(string)

	evType := "change.merged"

	payload := s.redact.Apply(map[string]any{
		"number":   int(number),
		"title":    title,
		"state":    action,
		"merged":   merged,
		"html_url": htmlURL,
		"repo":     repo,
		"org":      s.cfg.Org,
	})

	t := time.Now().UTC()
	if ts, _ := pr["updated_at"].(string); ts != "" {
		if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
			t = parsed.UTC()
		}
	}

	resource := fmt.Sprintf("%s/%s#%d", s.cfg.Org, repo, int(number))

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceGitHub,
		Actor:       actor,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

func (s *Source) processDeploymentWebhook(eventType string, raw map[string]any) error {
	repoMap, _ := raw["repository"].(map[string]any)
	repo := ""
	if repoMap != nil {
		repo, _ = repoMap["name"].(string)
	}

	var actor *string
	if sender, ok := raw["sender"].(map[string]any); ok {
		login, _ := sender["login"].(string)
		actor = s.redact.RedactActor(ptrs.String(login))
	}

	evType := "deploy.started"
	state := ""

	if eventType == "deployment_status" {
		if ds, ok := raw["deployment_status"].(map[string]any); ok {
			state, _ = ds["state"].(string)
			switch state {
			case "success":
				evType = "deploy.completed"
			case "failure", "error":
				evType = "deploy.failed"
			case "inactive":
				evType = "deploy.rolled_back"
			}
		}
	}

	d, _ := raw["deployment"].(map[string]any)
	if d == nil {
		return nil
	}

	env, _ := d["environment"].(string)
	ref, _ := d["ref"].(string)
	sha, _ := d["sha"].(string)
	idFloat, _ := d["id"].(float64)

	resource := fmt.Sprintf("%s/%s@%s", s.cfg.Org, repo, env)

	payload := s.redact.Apply(map[string]any{
		"deployment_id": int(idFloat),
		"environment":   env,
		"ref":           ref,
		"sha":           sha,
		"state":         state,
		"repo":          repo,
		"org":           s.cfg.Org,
	})

	t := time.Now().UTC()
	if ts, _ := d["created_at"].(string); ts != "" {
		if parsed, err := time.Parse(time.RFC3339, ts); err == nil {
			t = parsed.UTC()
		}
	}

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceGitHub,
		Actor:       actor,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

// VerifySignature checks the X-Hub-Signature-256 header value against
// the expected HMAC of the body. Returns true only on a valid, matching signature.
// Exported for testing.
func VerifySignature(secret, body []byte, signature string) bool {
	return verifyGitHubSignature(secret, body, signature)
}

func verifyGitHubSignature(secret, body []byte, signature string) bool {
	return sigverify.HexHMACPrefixed(secret, body, signature, "sha256=")
}
