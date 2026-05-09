# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build, test, lint

```
go build ./cmd/collector              # produces ./collector
go test ./...                          # full suite
go test -race ./...                    # required before pushing transport/sources changes
go test ./internal/transport -run TestFoo -v   # single package / single test
go vet ./...
golangci-lint run                      # uses .golangci.yml
helm lint helm/collector/              # required when touching the chart
```

The module requires Go ≥ 1.23 (`go.mod`). Releases use `goreleaser` driven by `.github/workflows/release.yml` with SLSA `provenance: mode=max`.

## Read-only posture (load-bearing)

The collector runs inside customer infrastructure and is the *only* part of the platform that is open-source and audited. The following are absolute constraints — any change that violates them will be rejected:

- No write API call against any source system (no `s3:Put*`, no GitHub mutation endpoints, no PagerDuty API client at all — PagerDuty is webhook-only by design).
- No Kubernetes RBAC verbs other than `get`/`list`/`watch` (and the MVP uses none).
- No disk write outside `/var/lib/operitas/` (WAL spool + cursor state).
- No raw event payloads in logs (only metadata at INFO).
- No non-EU endpoints. `config.isKnownNonEUEndpoint` and `euRegions` enforce this at startup; the Helm `NetworkPolicy` enforces it at runtime.
- No new Go module dependencies without prior discussion. Prefer stdlib.

## Architecture

The collector is a single binary (`cmd/collector`) that wires three independent **source** packages to one **transport** client through a single `emit(envelope.Event)` callback.

```
sources/awscloudtrail (S3 polling)  ─┐
sources/github       (poll + webhook) ├─ emit ─→ transport.Client ─ mTLS ─→ ingest API
sources/pagerduty    (webhook only)  ─┘                │
                                                        ↓
                                                    WAL spool
                                                /var/lib/operitas/wal/
```

Key boundaries:

- **`internal/envelope`** is the single chokepoint that defines the wire format (`Event`, `BatchRequest`) and validates against `infra/schemas/evidence_envelope.json` (schema 1.0.0). `EventSource` constants must stay in sync with the JSON schema enum across services. `ValidateBatch` enforces UUID tenant/collector IDs, the `event_type` regex (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`), and the 1000-event batch cap.
- **`internal/redact`** is applied to every payload before it leaves the source package. Default mode replaces email + IPv4/IPv6 with `[redacted]`; `hash_pii: true` switches to keyed `hmac:<hex>` for cross-event correlation. `redactString` short-circuits when the input contains no `@`, digit, or `:`.
- **`internal/transport.Client`** owns the buffer (count + byte caps), the flush loop, the WAL, and the mTLS client. `Send` is non-blocking and signals `flushCh` only when a cap is hit. `flush` writes the batch to the WAL (idempotency-key-named file) *before* attempting delivery, then deletes on 2xx. `deliverWithRetry` fails closed on TLS errors (`isTLSError` uses `errors.As` against concrete `crypto/tls` and `crypto/x509` types). Permanent 4xx (≠429) drop the WAL entry; 5xx and 429 retry with capped exponential backoff + jitter. On startup `walPrune` drops entries older than 14d or trims oldest-first if the spool exceeds 1 GiB; `replayWAL` then replays the rest.
- **`internal/runtime`** holds the shared `PollLoop(ctx, interval, name, fn)` and `RunWebhookServer(ctx, addr, handler)` helpers used by every source — do not reintroduce per-source ticker/HTTP scaffolding.
- **`internal/sigverify`** — `HexHMAC` / `HexHMACPrefixed`. All webhook signature checks (`sha256=` for GitHub, `v1=` for PagerDuty) go through this; never reimplement HMAC verification inline.
- **`internal/ptrs.String(s)`** — single canonical `*string` helper (nil for empty). Used in source normalizers for `Actor` and `Resource`.

Source-package conventions:

- Each source has a `New(...)` constructor that takes `cfg`, a `*redact.Redactor`, and the `emit` callback. The transport package is never imported by sources — events flow only via `emit`.
- Each source's `Run*` method blocks until ctx is cancelled and returns nil on graceful shutdown.
- CloudTrail persists `lastKey` to `cfg.CursorPath` (default `/var/lib/operitas/cloudtrail_cursor`). `ListObjectsV2` is narrowed via `StartAfter`, not client-side filtering. `processObject` runs with bounded concurrency (8).
- GitHub uses an explicit `*http.Client` with timeouts injected into oauth2 via `context.WithValue(ctx, oauth2.HTTPClient, ...)`; never use the default `oauth2.NewClient(context.Background(), ...)`. `pollPRs` paginates fully; `pollDeployments` fetches per-deployment statuses with bounded concurrency (8).

## Configuration

YAML at `OPERITAS_CONFIG_FILE` (default `/var/lib/operitas/config.yaml`). Secrets are env-only and never read from YAML:

- `OPERITAS_GITHUB_TOKEN`, `OPERITAS_GITHUB_WEBHOOK_SECRET`
- `OPERITAS_PD_SIGNING_SECRET`
- `OPERITAS_REDACT_HASH_KEY` (required when `redact.hash_pii: true`; must be valid hex)

`config.Load` returns a single joined error listing every validation failure rather than failing on the first one.

## Conventions and gotchas

- Conventional commits with scopes from `CONTRIBUTING.md`: `transport`, `envelope`, `sources`, `redact`, `helm`, `cmd`. Examples: `fix(transport): ...`, `feat(sources): ...`.
- Structured JSON logs to stdout via `slog`; never `log.Printf` and never write logs to disk. Log level is set from `LOG_LEVEL` env (`debug`/`info`/`warn`/`error`).
- Build tags: only `integration` is allowed.
- The `metricsHandler` in `cmd/collector/main.go` is a deliberate stub — the prometheus client library is not yet an approved dependency. Don't add it without an explicit dependency-review approval.
