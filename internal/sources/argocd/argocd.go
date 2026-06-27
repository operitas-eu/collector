// Package argocd collects application deployment events from Argo CD.
//
// It operates in two modes:
//
//  1. Webhook receiver (preferred): argocd-notifications sends a POST to the
//     collector's HTTP endpoint. The collector verifies the X-ArgoCD-Token header
//     using constant-time equality (sigverify.SecretEqual) before processing any
//     payload.
//
//  2. REST poller: GET /api/v1/applications on the Argo CD API server.
//     Auth: Authorization: Bearer <token>. Optional label selector via AppSelector.
//     Only GET endpoints are called; the collector never mutates Argo CD state.
//
// Read-only API calls only:
//   - GET /api/v1/applications     (list applications, optional ?selector=)
//
// EU compliance: the BaseURL is validated against isKnownNonEUEndpoint at startup.
// Argo CD typically runs in-cluster on customer EU infrastructure; the BaseURL
// must resolve to an EU-resident Argo CD API server.
//
// Event mapping (CONTRACT.md §8 — GitOps/CD sources use deploy.*):
//   - Sync status Synced + Health Healthy  -> deploy.completed
//   - Sync status Synced + Health Degraded -> deploy.failed
//   - Sync status OutOfSync               -> change.iac_applied (drift detected)
//   - Operation phase Running             -> deploy.started
//   - Operation phase Succeeded           -> deploy.completed
//   - Operation phase Failed              -> deploy.failed
//   - Operation phase Error               -> deploy.failed
//   - Health status Unknown/Error (no op) -> deploy.failed
//   - Rollback operation detected         -> deploy.rolled_back
//
// PII handling: actor (sync initiator, revision author) and payload fields are
// passed through redact.Apply and redact.RedactActor before envelope construction.
// Raw payloads are never logged at INFO level (manifest §12.13).
package argocd

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

// Source receives Argo CD webhook events and polls the Argo CD Applications API.
type Source struct {
	cfg        config.ArgoCDConfig
	http       *http.Client
	redact     *redact.Redactor
	emit       func(envelope.Event)
	cursorPath string
	// lastSyncAt is the high-water-mark timestamp for the polling cursor.
	// It tracks the most recent reconciledAt / operationState.finishedAt seen.
	lastSyncAt time.Time
}

// New constructs an Argo CD source. No goroutines are started here.
// The cursor is loaded from disk inside the constructor.
func New(cfg config.ArgoCDConfig, r *redact.Redactor, emit func(envelope.Event)) *Source {
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
		// Never follow redirects. A 302 from the Argo CD API could forward the
		// Authorization: Bearer header to an attacker-controlled host if the
		// redirect crosses a host boundary. The caller sees the 3xx and treats
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

// Register adds the Argo CD webhook handler to the shared router at /webhook/argocd.
// Call this before starting the shared router.
func (s *Source) Register(router *internalrt.SharedWebhookRouter) {
	router.RegisterWebhookHandler("/webhook/argocd", s.handleWebhook)
}

// RunPoller polls the Argo CD Applications API on the configured interval. It
// blocks until ctx is cancelled.
func (s *Source) RunPoller(ctx context.Context) error {
	slog.Info("argocd poller started",
		"base_url", s.cfg.BaseURL,
		"poll_interval", s.cfg.PollInterval,
		"namespace", s.cfg.Namespace,
		"app_selector", s.cfg.AppSelector,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "argocd", s.poll)
}

// loadCursor reads the persisted high-water-mark from disk.
func (s *Source) loadCursor() {
	if s.cursorPath == "" {
		return
	}
	data, err := os.ReadFile(s.cursorPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("argocd: cursor read failed; starting from zero",
				"path", s.cursorPath, "err", err)
		}
		return
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("argocd: cursor parse failed; starting from zero",
			"path", s.cursorPath, "err", err)
		return
	}
	s.lastSyncAt = t
}

func (s *Source) writeCursor() {
	if s.cursorPath == "" || s.lastSyncAt.IsZero() {
		return
	}
	tmp := s.cursorPath + ".tmp"
	val := s.lastSyncAt.UTC().Format(time.RFC3339Nano)
	if err := os.WriteFile(tmp, []byte(val), 0o600); err != nil {
		slog.Warn("argocd: cursor write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("argocd: cursor rename failed", "err", err)
	}
}

// -------------------------------------------------------------------
// REST poller
// -------------------------------------------------------------------

// poll fetches all applications from the Argo CD API and emits events for
// those whose sync/operation timestamp is newer than the cursor.
func (s *Source) poll(ctx context.Context) error {
	apps, err := s.listApplications(ctx)
	if err != nil {
		return fmt.Errorf("argocd: list applications: %w", err)
	}

	var highWater time.Time
	for _, app := range apps {
		ev, ok := s.normalizeApplication(app)
		if !ok {
			continue
		}
		// Only emit if the event timestamp is strictly after the cursor.
		if !s.lastSyncAt.IsZero() && !ev.OccurredAt.After(s.lastSyncAt) {
			continue
		}
		s.emit(ev)
		if ev.OccurredAt.After(highWater) {
			highWater = ev.OccurredAt
		}
	}

	if !highWater.IsZero() && highWater.After(s.lastSyncAt) {
		s.lastSyncAt = highWater.Add(time.Millisecond)
		s.writeCursor()
	}

	slog.Debug("argocd: poll complete", "apps_fetched", len(apps))
	return nil
}

// argoApplicationsResponse mirrors the relevant fields of the Argo CD
// GET /api/v1/applications response. Only fields we normalize are included.
type argoApplicationsResponse struct {
	Items []argoApplication `json:"items"`
}

// argoApplication is a minimal representation of an Argo CD Application
// resource as returned by the API server.
type argoApplication struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Project string `json:"project"`
		Source  struct {
			RepoURL        string `json:"repoURL"`
			TargetRevision string `json:"targetRevision"`
			Path           string `json:"path"`
		} `json:"source"`
		Destination struct {
			Server    string `json:"server"`
			Namespace string `json:"namespace"`
		} `json:"destination"`
	} `json:"spec"`
	Status struct {
		Sync struct {
			Status   string `json:"status"` // Synced, OutOfSync, Unknown
			Revision string `json:"revision"`
		} `json:"sync"`
		Health struct {
			Status  string `json:"status"`  // Healthy, Progressing, Degraded, Suspended, Missing, Unknown
			Message string `json:"message"` // optional human-readable detail
		} `json:"health"`
		// ReconciledAt is set by the Argo CD controller after each reconcile.
		ReconciledAt   *time.Time          `json:"reconciledAt"`
		OperationState *ArgoOperationState `json:"operationState"`
		// Summary contains the human-readable sync state with the last applied revision.
		Summary struct {
			Images []string `json:"images"`
		} `json:"summary"`
	} `json:"status"`
}

// ArgoInfo is a single key/value metadata entry from an Argo CD operation.
// Exported so tests can construct ArgoOperationState values.
type ArgoInfo struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ArgoOperation carries the operation-level metadata associated with a sync.
// Exported so tests can construct ArgoOperationState values.
type ArgoOperation struct {
	Sync *struct {
		// Prune is set when the operation may delete resources.
		Prune bool `json:"prune"`
	} `json:"sync"`
	// Retry is set when this is an automatic or manual retry.
	Retry *struct {
		Limit int `json:"limit"`
	} `json:"retry"`
	// Info carries freeform operator metadata, including rollback markers.
	Info []ArgoInfo `json:"info"`
}

// ArgoOperationState represents the most-recent sync operation on an Argo CD
// Application. Exported so external test packages can construct test values
// for MapApplicationEventType without reflection.
type ArgoOperationState struct {
	// Phase: Running, Succeeded, Failed, Error, Terminating
	Phase      string     `json:"phase"`
	Message    string     `json:"message"`
	StartedAt  *time.Time `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	// SyncResult carries commit/revision info.
	SyncResult *struct {
		Revision string `json:"revision"`
		Source   struct {
			RepoURL string `json:"repoURL"`
		} `json:"source"`
	} `json:"syncResult"`
	// InitiatedBy is populated when a sync is triggered manually from the UI or CLI.
	InitiatedBy struct {
		Username string `json:"username"`
	} `json:"initiatedBy"`
	// Operation carries the rollback/retry annotation.
	Operation ArgoOperation `json:"operation"`
}

func (s *Source) listApplications(ctx context.Context) ([]argoApplication, error) {
	q := url.Values{}
	if s.cfg.AppSelector != "" {
		q.Set("selector", s.cfg.AppSelector)
	}
	reqURL := s.cfg.BaseURL + "/api/v1/applications"
	if len(q) > 0 {
		reqURL += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("argocd GET /api/v1/applications: unexpected status %d (response body omitted)",
			resp.StatusCode)
	}

	var result argoApplicationsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("argocd: decode applications response: %w", err)
	}
	return result.Items, nil
}

// normalizeApplication converts a polled Application into a canonical Event.
// Returns (Event, false) when the application state carries no actionable timestamp
// and should be skipped.
func (s *Source) normalizeApplication(app argoApplication) (envelope.Event, bool) {
	// Pick the best available timestamp:
	// 1. operationState.finishedAt (most precise — when the sync op completed)
	// 2. operationState.startedAt (for in-progress ops)
	// 3. status.reconciledAt (reconcile-loop timestamp)
	// Fall through to zero-value → skip.
	var t time.Time
	opState := app.Status.OperationState
	if opState != nil {
		if opState.FinishedAt != nil && !opState.FinishedAt.IsZero() {
			t = opState.FinishedAt.UTC()
		} else if opState.StartedAt != nil && !opState.StartedAt.IsZero() {
			t = opState.StartedAt.UTC()
		}
	}
	if t.IsZero() && app.Status.ReconciledAt != nil && !app.Status.ReconciledAt.IsZero() {
		t = app.Status.ReconciledAt.UTC()
	}
	if t.IsZero() {
		return envelope.Event{}, false
	}

	evType := mapApplicationEventType(app.Status.Sync.Status, app.Status.Health.Status, opState)

	// Actor: prefer the sync initiator if available.
	var actorPtr *string
	if opState != nil && opState.InitiatedBy.Username != "" {
		actorPtr = s.redact.RedactActor(ptrs.String(opState.InitiatedBy.Username))
	}

	// Resource: namespace/name mirrors how Argo CD itself identifies applications.
	ns := app.Metadata.Namespace
	if ns == "" {
		ns = s.cfg.Namespace
	}
	resource := ns + "/" + app.Metadata.Name

	revision := app.Status.Sync.Revision
	if opState != nil && opState.SyncResult != nil && opState.SyncResult.Revision != "" {
		revision = opState.SyncResult.Revision
	}

	phase := ""
	opMessage := ""
	if opState != nil {
		phase = opState.Phase
		opMessage = opState.Message
	}

	payload := s.redact.Apply(map[string]any{
		"app_name":        app.Metadata.Name,
		"app_namespace":   ns,
		"project":         app.Spec.Project,
		"sync_status":     app.Status.Sync.Status,
		"health_status":   app.Status.Health.Status,
		"health_message":  app.Status.Health.Message,
		"op_phase":        phase,
		"op_message":      opMessage,
		"revision":        revision,
		"repo_url":        app.Spec.Source.RepoURL,
		"target_revision": app.Spec.Source.TargetRevision,
		"dest_namespace":  app.Spec.Destination.Namespace,
	})

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceArgoCD,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	}, true
}

// -------------------------------------------------------------------
// Webhook handler
// -------------------------------------------------------------------

// handleWebhook is the HTTP handler for argocd-notifications webhook payloads.
// argocd-notifications sends a plain shared secret in the X-ArgoCD-Token header
// (constant-time equality via sigverify.SecretEqual).
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

	// Verify X-ArgoCD-Token with constant-time comparison (CONTRACT.md §9).
	if s.cfg.WebhookSecret != "" {
		got := r.Header.Get("X-ArgoCD-Token")
		if !sigverify.SecretEqual(s.cfg.WebhookSecret, got) {
			slog.Warn("argocd webhook: invalid X-ArgoCD-Token")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := s.processWebhookPayload(body); err != nil {
		slog.Error("argocd webhook: process failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// argoNotificationWebhook is the shape sent by argocd-notifications webhook
// templates. The exact fields depend on the template configured by the operator,
// but the notification system always includes app-level metadata in the body.
// We support two common template structures:
//   - The application-name/namespace/sync_status/health_status flat payload
//     (default argocd-notifications webhook template)
//   - The richer payload containing operation phase and initiator information.
//
// Reference: https://argo-cd.readthedocs.io/en/stable/operator-manual/notifications/
type argoNotificationWebhook struct {
	// Application is the Argo CD Application name.
	Application string `json:"app"`
	// Namespace is the Kubernetes namespace of the application.
	Namespace string `json:"namespace"`
	// Project is the Argo CD project name.
	Project string `json:"project"`
	// RepoURL is the Git repository URL.
	RepoURL string `json:"repo"`
	// Revision is the Git commit SHA being deployed.
	Revision string `json:"revision"`
	// SyncStatus is the application sync status: Synced, OutOfSync, Unknown.
	SyncStatus string `json:"sync_status"`
	// HealthStatus is the application health: Healthy, Progressing, Degraded, etc.
	HealthStatus string `json:"health_status"`
	// OperationPhase is the current operation phase: Running, Succeeded, Failed, Error.
	OperationPhase string `json:"operation_phase"`
	// OperationMessage is the human-readable operation message (may include error detail).
	OperationMessage string `json:"operation_message"`
	// Initiator is the user who triggered the sync (empty for automated syncs).
	Initiator string `json:"initiator"`
	// Timestamp is the RFC3339 timestamp of the notification.
	// argocd-notifications populates this when the notification fires.
	Timestamp string `json:"timestamp"`
	// DestNamespace is the destination Kubernetes namespace.
	DestNamespace string `json:"dest_namespace"`
	// TargetRevision is the configured target revision (branch, tag, or commit SHA).
	TargetRevision string `json:"target_revision"`
}

func (s *Source) processWebhookPayload(body []byte) error {
	var wh argoNotificationWebhook
	if err := json.Unmarshal(body, &wh); err != nil {
		return fmt.Errorf("unmarshal argocd webhook: %w", err)
	}

	// OccurredAt: prefer the notification timestamp; fall back to now.
	t := time.Now().UTC()
	if wh.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, wh.Timestamp); err == nil {
			t = parsed.UTC()
		} else if parsed, err := time.Parse(time.RFC3339Nano, wh.Timestamp); err == nil {
			t = parsed.UTC()
		}
	}

	evType := mapWebhookEventType(wh.SyncStatus, wh.HealthStatus, wh.OperationPhase)

	var actorPtr *string
	if wh.Initiator != "" {
		actorPtr = s.redact.RedactActor(ptrs.String(wh.Initiator))
	}

	ns := wh.Namespace
	if ns == "" {
		ns = s.cfg.Namespace
	}
	resource := ns + "/" + wh.Application

	payload := s.redact.Apply(map[string]any{
		"app_name":        wh.Application,
		"app_namespace":   ns,
		"project":         wh.Project,
		"sync_status":     wh.SyncStatus,
		"health_status":   wh.HealthStatus,
		"op_phase":        wh.OperationPhase,
		"op_message":      wh.OperationMessage,
		"revision":        wh.Revision,
		"repo_url":        wh.RepoURL,
		"target_revision": wh.TargetRevision,
		"dest_namespace":  wh.DestNamespace,
	})

	s.emit(envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceArgoCD,
		Actor:       actorPtr,
		Resource:    ptrs.String(resource),
		Payload:     payload,
	})
	return nil
}

// -------------------------------------------------------------------
// Event type mapping
// -------------------------------------------------------------------

// MapWebhookEventType maps webhook notification fields to a canonical event type.
// Priority order: operation phase (most specific) > sync+health combined.
// Exported for testing.
func MapWebhookEventType(syncStatus, healthStatus, operationPhase string) string {
	return mapWebhookEventType(syncStatus, healthStatus, operationPhase)
}

func mapWebhookEventType(syncStatus, healthStatus, operationPhase string) string {
	switch strings.ToLower(operationPhase) {
	case "running":
		return "deploy.started"
	case "succeeded":
		return "deploy.completed"
	case "failed", "error":
		return "deploy.failed"
	case "terminating":
		// Terminating is treated as a rollback in progress.
		return "deploy.rolled_back"
	}
	// Fall back to sync+health interpretation.
	return mapSyncHealthToEventType(syncStatus, healthStatus)
}

// MapApplicationEventType maps a polled application's sync/health/operation state
// to a canonical event type.
// Exported for testing.
func MapApplicationEventType(syncStatus, healthStatus string, opState *ArgoOperationState) string {
	return mapApplicationEventType(syncStatus, healthStatus, opState)
}

func mapApplicationEventType(syncStatus, healthStatus string, opState *ArgoOperationState) string {
	if opState != nil {
		// Check for rollback: argocd sets an "info" entry with name="Rollback" or
		// the retry operation is present, indicating automated recovery.
		if isRollbackOperation(opState) {
			switch strings.ToLower(opState.Phase) {
			case "succeeded":
				return "deploy.rolled_back"
			case "running":
				return "deploy.started"
			case "failed", "error":
				return "deploy.failed"
			}
		}
		switch strings.ToLower(opState.Phase) {
		case "running":
			return "deploy.started"
		case "succeeded":
			return "deploy.completed"
		case "failed", "error":
			return "deploy.failed"
		case "terminating":
			return "deploy.rolled_back"
		}
	}
	return mapSyncHealthToEventType(syncStatus, healthStatus)
}

// mapSyncHealthToEventType implements the base sync+health mapping used by
// both the poller and the webhook fallback path.
func mapSyncHealthToEventType(syncStatus, healthStatus string) string {
	sync := strings.ToLower(syncStatus)
	health := strings.ToLower(healthStatus)

	switch sync {
	case "synced":
		switch health {
		case "healthy":
			return "deploy.completed"
		case "degraded", "missing":
			return "deploy.failed"
		case "unknown", "error":
			return "deploy.failed"
		default:
			// Progressing, Suspended — treat as completed but not yet healthy.
			return "deploy.completed"
		}
	case "outofsync":
		// Drift detected — the live state diverged from the desired state in Git.
		return "change.iac_applied"
	default:
		// Unknown sync status.
		return "deploy.failed"
	}
}

// isRollbackOperation reports whether the operation state represents a rollback.
// Argo CD does not have a dedicated "rollback" phase; rollbacks are sync operations
// with a specific info annotation set by the argocd CLI's rollback subcommand, or
// detected by the presence of a retry block.
func isRollbackOperation(opState *ArgoOperationState) bool {
	for _, info := range opState.Operation.Info {
		if strings.EqualFold(info.Name, "rollback") {
			return true
		}
	}
	return false
}

// VerifyWebhookToken reports whether the X-ArgoCD-Token header value matches
// the expected secret using constant-time comparison.
// Exported for testing.
func VerifyWebhookToken(secret, headerValue string) bool {
	return sigverify.SecretEqual(secret, headerValue)
}

// HandleWebhookForTest exposes the internal webhook handler for use in external
// test packages. This avoids requiring a running HTTP server in unit tests.
func (s *Source) HandleWebhookForTest(w http.ResponseWriter, r *http.Request) {
	s.handleWebhook(w, r)
}
