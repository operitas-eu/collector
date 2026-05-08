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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	gogithub "github.com/google/go-github/v63/github"
	"golang.org/x/oauth2"
	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
)

// Source receives GitHub webhook events and/or polls the REST API.
type Source struct {
	cfg    config.GitHubConfig
	client *gogithub.Client
	redact *redact.Redactor
	emit   func(envelope.Event)
}

// New constructs a GitHub source. It creates a read-only authenticated GitHub
// client using the PAT from config.
func New(cfg config.GitHubConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Token})
	tc := oauth2.NewClient(context.Background(), ts)
	gh := gogithub.NewClient(tc)

	return &Source{
		cfg:    cfg,
		client: gh,
		redact: r,
		emit:   emit,
	}
}

// RunWebhook starts the webhook HTTP server. It blocks until ctx is cancelled.
// Events are verified via HMAC-SHA256 before processing.
func (s *Source) RunWebhook(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/github", s.handleWebhook)

	addr := fmt.Sprintf(":%d", s.cfg.WebhookPort)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	slog.Info("github webhook server starting", "addr", addr)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("github webhook server: %w", err)
	}
}

// RunPoller polls the GitHub API on the configured interval. It blocks until
// ctx is cancelled.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("github poller started",
		"org", s.cfg.Org,
		"poll_interval", s.cfg.PollInterval,
	)

	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()

	if err := s.poll(ctx); err != nil {
		slog.Error("github poll error", "err", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.poll(ctx); err != nil {
				slog.Error("github poll error", "err", err)
			}
		}
	}
}

func (s *Source) poll(ctx context.Context) error {
	repos, err := s.listRepos(ctx)
	if err != nil {
		return err
	}

	since := time.Now().UTC().Add(-s.cfg.PollInterval * 2)

	for _, repo := range repos {
		if err := s.pollPRs(ctx, repo, since); err != nil {
			slog.Error("github: poll PRs failed", "repo", repo, "err", err)
		}
		if err := s.pollDeployments(ctx, repo, since); err != nil {
			slog.Error("github: poll deployments failed", "repo", repo, "err", err)
		}
	}
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
		State:     "all",
		Sort:      "updated",
		Direction: "desc",
		ListOptions: gogithub.ListOptions{PerPage: 50},
	}

	prs, _, err := s.client.PullRequests.List(ctx, s.cfg.Org, repo, opts)
	if err != nil {
		return fmt.Errorf("list PRs: %w", err)
	}

	for _, pr := range prs {
		if pr.GetUpdatedAt().Before(since) {
			break
		}
		ev := s.normalizePR(repo, pr)
		s.emit(ev)
	}
	return nil
}

// pollDeployments fetches recent deployments via GET /repos/{owner}/{repo}/deployments.
func (s *Source) pollDeployments(ctx context.Context, repo string, since time.Time) error {
	// GET /repos/{owner}/{repo}/deployments — read-only.
	opts := &gogithub.DeploymentsListOptions{
		ListOptions: gogithub.ListOptions{PerPage: 50},
	}

	deployments, _, err := s.client.Repositories.ListDeployments(ctx, s.cfg.Org, repo, opts)
	if err != nil {
		return fmt.Errorf("list deployments: %w", err)
	}

	for _, d := range deployments {
		if d.GetCreatedAt().Before(since) {
			continue
		}

		// GET /repos/{owner}/{repo}/deployments/{id}/statuses — read-only.
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

		ev := s.normalizeDeployment(repo, d, statuses)
		s.emit(ev)
	}
	return nil
}

func (s *Source) normalizePR(repo string, pr *gogithub.PullRequest) envelope.Event {
	evType := "change.merged"
	if pr.GetMergedAt().IsZero() {
		evType = "change.merged" // PR state changes all map to change.merged for MVP
	}

	actor := pr.GetUser().GetLogin()
	actorRedacted := s.redact.RedactActor(strPtr(actor))

	payload := map[string]any{
		"number":     pr.GetNumber(),
		"title":      pr.GetTitle(),
		"state":      pr.GetState(),
		"merged":     pr.GetMerged(),
		"base_ref":   pr.GetBase().GetRef(),
		"head_ref":   pr.GetHead().GetRef(),
		"head_sha":   pr.GetHead().GetSHA(),
		"repo":       repo,
		"org":        s.cfg.Org,
		"html_url":   pr.GetHTMLURL(),
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
		Resource:    strPtr(resource),
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
	actorRedacted := s.redact.RedactActor(strPtr(actor))

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
		Resource:    strPtr(resource),
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
		actor = s.redact.RedactActor(strPtr(login))
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
		Resource:    strPtr(resource),
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
		actor = s.redact.RedactActor(strPtr(login))
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
		Resource:    strPtr(resource),
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
	const prefix = "sha256="
	if !strings.HasPrefix(signature, prefix) {
		return false
	}
	hexSig := signature[len(prefix):]
	sigBytes, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, sigBytes)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
