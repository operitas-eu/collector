# Source Integration Contract

This document is the normative spec for fill-in engineers implementing the 8 stub sources.
Read it fully before writing a single line of code. Violations block merge.

## 1. Package Layout

Every source lives in its own package:

```
internal/sources/<source>/
    <source>.go       -- implementation
    <source>_test.go  -- table-driven tests (required)
```

No sub-packages. No shared state between source packages.

## 2. Constructor Signature

```go
func New(cfg config.<Source>Config, r *redact.Redactor, emit func(envelope.Event)) *Source
```

- `cfg`: the source-specific config struct from `internal/config/config.go`
- `r`: the shared redactor instance — never construct a new one inside a source
- `emit`: the transport callback — call this once per normalized event

The constructor must not start goroutines or make network calls.
For sources with a persistent cursor, load the cursor inside the constructor.

## 3. Webhook Registration

All new sources register on the shared router, not their own port:

```go
func (s *Source) Register(router *internalrt.SharedWebhookRouter)
```

Inside Register, call exactly one of:

```go
router.RegisterWebhookHandler("/webhook/<source>", s.handleWebhook)
```

The path must be `/webhook/<source>` where `<source>` matches the package name
(e.g., `/webhook/incidentio` for the `incidentio` package).

Do not start an HTTP server inside the source package. The shared router
(`internal/runtime/SharedWebhookRouter`) is started once in `cmd/collector/main.go`.

## 4. Poller Signature (hybrid sources only)

```go
func (s *Source) RunPoller(ctx context.Context) error
```

- Must block until `ctx` is cancelled.
- Use `internalrt.PollLoop(ctx, interval, "source-name", s.poll)` to implement
  the tick loop.
- The internal `poll(ctx context.Context) error` function is called by PollLoop
  on each tick. Return an error to log it; PollLoop will not abort.
- Only call GET endpoints — no writes, no mutations. Verify this in code review.

## 5. Webhook-Only Source (no poller)

Webhook-only sources (flux, spacelift, grafana, prometheus) implement:

```go
func (s *Source) Register(router *internalrt.SharedWebhookRouter)
func (s *Source) Run(_ context.Context) error
```

`Run` may be a no-op that returns nil immediately or blocks on ctx.Done().
It exists so main.go can treat all sources uniformly. The actual event
ingestion happens in the HTTP handler registered via Register.

## 6. Config Struct Convention

Config structs are defined in `internal/config/config.go`. Fill-in engineers
must NOT add fields to the config; they are already fully defined. The config
for each source includes:

- `Enabled bool` — gate everything behind this
- `WebhookSecret string \`yaml:"-"\`` — never store in YAML
- Poller fields (hybrid sources only): `Token`, `BaseURL`, `PollInterval`,
  `PollLookback`, `CursorPath`
- Source-specific fields (consult the struct comment for each source)

Secrets are never stored in YAML. They are populated via `populateSecrets()`
from environment variables following the pattern `OPERITAS_<SOURCE>_WEBHOOK_SECRET`
and `OPERITAS_<SOURCE>_TOKEN`. These are already wired in config.go.

## 7. Normalization and Redaction Rules

Every event emitted MUST follow this checklist:

1. Call `s.redact.Apply(payload)` on the payload map before assigning it.
2. Call `s.redact.RedactActor(ptrs.String(rawActor))` on any actor string.
3. Never log the raw payload at INFO level (manifest §12.13). Use `slog.Debug`
   if you need payload-level logging.
4. Set `OccurredAt` to the source-system timestamp in UTC. Fall back to
   `time.Now().UTC()` only when the source provides no timestamp.
5. Set `EventSource` to the appropriate `envelope.Source*` constant.
6. Set `EventType` using lower.dot.notation per the taxonomy below (§8).
7. Set `Resource` to the primary entity identifier (e.g., issue key, run ID).
   Use `ptrs.String("...")` to get a `*string`.
8. Set `Actor` to `nil` when the source does not include a user principal.

## 8. Event Type Taxonomy (§4.5 of the project manifest)

Use these canonical event types. Do not invent new ones.

| Category    | event_type values                                            |
|-------------|--------------------------------------------------------------|
| Deploy      | deploy.started, deploy.completed, deploy.failed, deploy.rolled_back |
| Change      | change.opened, change.merged, change.closed, change.approved |
| Incident    | incident.opened, incident.acknowledged, incident.resolved, incident.escalated |
| Monitor     | monitor.alert                                                |
| Auth        | auth.role_assumed, auth.privileged_access, auth.mfa_failed   |
| Data        | data.bulk_access                                             |

Mapping guidance per source category:

- **GitOps / CD sources** (flux, spacelift, argocd): use `deploy.*`
- **Incident management** (incidentio, opsgenie): use `incident.*`
- **Alerting / monitoring** (prometheus, grafana): use `monitor.alert`
- **Issue / change tracking** (jira, bitbucket PRs, servicenow): use `change.*`

## 9. Signature Verification

Use the existing helpers in `internal/sigverify/sigverify.go`.
Never roll your own HMAC or constant-time comparison.

| Source      | Header                        | Scheme                      | Verifier                          |
|-------------|-------------------------------|-----------------------------|-----------------------------------|
| bitbucket   | X-Hub-Signature-256           | sha256=<hex>                | HexHMACPrefixed(..., "sha256=")   |
| incidentio  | X-Signature-256               | sha256=<hex>                | HexHMACPrefixed(..., "sha256=")   |
| spacelift   | X-Signature-256               | sha256=<hex>                | HexHMACPrefixed(..., "sha256=")   |
| opsgenie    | X-OG-Webhook-Secret           | plain secret                | SecretEqual(cfg.WebhookSecret, v) |
| servicenow  | X-ServiceNow-Webhook-Secret   | plain secret                | SecretEqual(cfg.WebhookSecret, v) |
| argocd      | X-ArgoCD-Token                | plain secret                | SecretEqual(cfg.WebhookSecret, v) |
| flux        | Gotk-Webhook-Secret           | plain secret                | SecretEqual(cfg.WebhookSecret, v) |
| grafana     | Authorization: Bearer <s>     | constant-time bearer        | SecretEqual + HasPrefix check     |

Always verify when `cfg.WebhookSecret != ""`. Return HTTP 401 on mismatch
and log at WARN level without including the secret or payload in the log message.

## 10. EU Compliance

- All REST pollers must validate `cfg.BaseURL` (or `cfg.APIBaseURL`) against
  `isKnownNonEUEndpoint` before making the first request. This is done in
  `config.validate()` at startup for all new sources — do not re-check at poll time.
- Never hard-code a non-EU base URL as a fallback. All defaults in
  `applyDefaults()` already use EU endpoints.
- Sources that call vendor APIs: perform GET only. No writes.

## 11. Stub-to-Production Checklist

When replacing a stub with a real implementation:

1. Remove `stubNotImplemented` from the file.
2. Implement `handleWebhook` with the correct signature verification (see §9).
3. Implement the wire type structs for the vendor's payload shape.
4. Implement `processWebhookPayload` with normalization and redaction.
5. For hybrid sources: implement `poll`, cursor load/write, and `RunPoller` body.
6. Write table-driven tests:
   - Signature verification (valid/invalid/empty)
   - Event type mapping (all supported states)
   - Normalization (at least one positive case with an emit assertion)
   - HTTP handler: method-not-allowed, auth-rejection, valid-payload
7. Run `go test ./internal/sources/<source>/` and `go vet ./...`.
8. Run `gofmt -l .` — output must be empty.
9. Grep for any zero-callsite helpers (the `unused` linter will catch these in CI).

## 12. Wiring in main.go

main.go is already wired for all 11 sources. When you implement a stub, the
wiring in main.go does NOT change — the stub's Register/RunPoller already
connects to the shared router and event loop. You only need to fill in the
source package itself.

## 13. Example: Implementing a Stub (opsgenie as template)

```go
// 1. handleWebhook: verify X-OG-Webhook-Secret, read body, call processPayload
func (s *Source) handleWebhook(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    body, err := io.ReadAll(io.LimitReader(r.Body, 5*1024*1024))
    if err != nil { http.Error(w, "read error", http.StatusBadRequest); return }

    if s.cfg.WebhookSecret != "" {
        got := r.Header.Get("X-OG-Webhook-Secret")
        if !sigverify.SecretEqual(s.cfg.WebhookSecret, got) {
            slog.Warn("opsgenie webhook: invalid secret")
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
    }
    if err := s.processPayload(body); err != nil {
        slog.Error("opsgenie webhook: process failed", "err", err)
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

// 2. wire types for the Opsgenie webhook payload
type opsgenieWebhook struct {
    Action    string `json:"action"` // "Create", "Acknowledge", "Close", etc.
    Alert     struct {
        AlertID  string `json:"alertId"`
        Message  string `json:"message"`
        Priority string `json:"priority"`
    } `json:"alert"`
    Source struct {
        Name string `json:"name"` // the triggering user or integration
    } `json:"source"`
}

// 3. normalizeAndEmit with redact + event type mapping
func (s *Source) processPayload(body []byte) error {
    var wh opsgenieWebhook
    if err := json.Unmarshal(body, &wh); err != nil { return err }

    evType := mapOpsgenieAction(wh.Action)
    actor := s.redact.RedactActor(ptrs.String(wh.Source.Name))
    payload := s.redact.Apply(map[string]any{
        "alert_id": wh.Alert.AlertID,
        "message":  wh.Alert.Message,
        "priority": wh.Alert.Priority,
        "action":   wh.Action,
    })
    s.emit(envelope.Event{
        OccurredAt:  time.Now().UTC(),
        EventType:   evType,
        EventSource: envelope.SourceOpsgenie,
        Actor:       actor,
        Resource:    ptrs.String(wh.Alert.AlertID),
        Payload:     payload,
    })
    return nil
}
```
