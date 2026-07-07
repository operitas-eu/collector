# Changelog

All notable changes to the collector are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-07-07

This is the first entry cut into this file — `CHANGELOG.md` did not exist
before this release; everything below was previously undocumented
"unreleased" work sitting on top of the `v0.1.2` tag. See the note at the
bottom of this file for why the version number jumps from `0.1.2` to
`0.2.0` rather than reusing `0.1.0`.

### Added

- 13 new event sources, taking source coverage from 3 (`aws.cloudtrail`,
  `github`, `pagerduty`) to 16: `gitlab`, `azure.activity`, `jira`,
  `datadog`, `argocd`, `bitbucket`, `flux`, `spacelift`, `incident.io`,
  `opsgenie`, `grafana`, `prometheus`, `servicenow`. Each source is poll,
  webhook, or hybrid (webhook preferred, poll fallback) per
  `internal/sources/CONTRACT.md`.
- Shared webhook router (`internal/runtime/sharedwebhook.go`) — one HTTP
  server for all newly added webhook-capable sources, so each integration no
  longer needs a dedicated listening port.
- `--emit-event` one-shot CLI mode for wire-contract testing: pushes a single
  synthetic envelope straight to the ingest API and exits, without running a
  long-lived collector.
- `--drain-dlq` CLI mode to replay dead-letter entries back into the WAL.
- Dead-letter queue (`internal/transport/dlq.go`) for batches that receive a
  permanent 4xx rejection (422 validation failure, single-event 413).
- WAL and DLQ observability counters (writes, deletes, replays, pruned) in
  Prometheus text format on `/metrics`.
- `redact.hash_pii` startup validation: refuses to start if HMAC hashing is
  enabled but the hash key is missing or not valid hex.
- `envelope-contract-mirror` CI job: a conflict-only, reciprocal comparison of
  this repo's envelope fixtures against the canonical copy in the
  `operitas-eu/operitas` monorepo, so wire-contract fixture drift between the
  two repos fails CI instead of shipping silently.
- `FIXTURES.lock` drift guard and a source-coverage guard so every
  `event_source` enum value has at least one fixture.
- SLSA provenance (`mode=max`) on the container image build; cosign keyless
  signing (binaries via `cosign sign-blob --bundle`, image via `cosign sign`).

### Changed

- Bearer token auth added for the ingest API (`Authorization: Bearer
  <key_id>.<secret>`), plus the Helm `apiKey` / `existingApiKeySecret`
  wiring and the README quickstart that documents it end to end.
- Transport client reworked to match the ingest API's all-or-nothing batch
  contract (ADR-0003): no more partial-batch `Rejected` counts: a batch is
  either fully accepted or not, with explicit 401/403/409/413/422/429/5xx
  handling and exponential backoff with jitter.

### Fixed

- **Evidence-loss / duplication (4 defects):** poll cursors are now written
  durably and fail closed; webhook and poller paths for the same source no
  longer double-emit the same event.
- **Redaction:** IP address redaction now preserves surrounding bytes exactly
  instead of collapsing whitespace around the replaced span, which had been
  corrupting adjacent evidence in hashed-PII mode.
- **Release pipeline — container images always reported `version: "dev"`:**
  `Dockerfile` declared `ARG VERSION` while `release.yml`/`ci.yml` passed a
  `BUILD_VERSION` build-arg; Docker silently drops unconsumed build-args, so
  every image ever built (including the `v0.1.0`-`v0.1.2` releases) baked in
  `main.version=dev` regardless of the tag. Renamed the Dockerfile `ARG` to
  `BUILD_VERSION` to match both workflows. Verified empirically: extracted
  the built binary from a `docker build --build-arg BUILD_VERSION=v9.9.9`
  image and ran it — it now logs `"version":"v9.9.9"`. The standalone
  released binaries were never affected (they set `-X main.version` directly
  via `go build`, no Docker indirection).
- Removed the dead `ARG BUILD_DATE` / `-X main.buildDate=...` wiring in
  `Dockerfile` — no `buildDate` variable has ever existed in
  `cmd/collector/main.go`, so the linker flag was silently discarded on
  every build. Not replaced; nothing consumed it.
- **Release pipeline — OCI Helm chart was republished under the app's git
  tag instead of its own version:** `release.yml`'s `package-helm` job ran
  `helm package --version "${VERSION}"`, overriding whatever `Chart.yaml`
  declared. Since the chart has its own weekly-cadence SemVer independent of
  the collector binary's monthly release tags, this meant the OCI chart
  history would never match `helm/collector/CHANGELOG.md`. Removed the
  `--version` override so `helm package` uses `Chart.yaml`'s own `version`
  field; `--app-version "${TAG}"` is kept so the packaged chart still
  records which binary tag it was built alongside. Verified locally: with
  `Chart.yaml` at `0.4.1`, `helm package helm/collector --app-version
  v0.2.0` now produces `collector-0.4.1.tgz` with `appVersion: v0.2.0`
  instead of a `collector-0.2.0.tgz` that discarded the chart's real
  version.

### Security

- **Egress / EU-residency hardening:** all nine REST-polling sources now
  refuse HTTP redirects (`CheckRedirect: http.ErrUseLastResponse`), closing a
  path where a vendor-issued 302 could forward auth headers to an arbitrary
  host. EU-endpoint validation is fail-closed by default (previously
  advisory only); bypass requires the explicit
  `OPERITAS_ALLOW_NON_EU_ENDPOINT=1` escape hatch.
- Bounded in-memory buffers and live WAL/DLQ pruning to cap resource growth
  under sustained delivery failure.
- `actions/checkout` SHA-pinned in the envelope-mirror CI job (supply-chain
  hygiene, ADR-0022 §2).

### Follow-ups (not in this release)

- **SBOM generation is not wired into `release.yml`.** No `syft`/
  `sbom: true` step exists on the image or binary build jobs, despite the
  monthly binary-release cadence calling for a refreshed SBOM. Deliberately
  not added in this release — adding a new workflow step/tool is a separate
  decision from fixing the three release-pipeline bugs above and is tracked
  as a follow-up, not bundled in here.

### Dependencies

- Routine `go.mod` and GitHub Actions version bumps (Dependabot) across the
  release window: `actions/checkout`, `actions/setup-go`,
  `actions/upload-artifact`, `actions/download-artifact`,
  `docker/build-push-action`, `docker/login-action`,
  `docker/metadata-action`, `docker/setup-buildx-action`,
  `golangci/golangci-lint-action`, `github/codeql-action`,
  `aquasecurity/trivy-action`, `softprops/action-gh-release`, and Go module
  minor/patch updates. No functional changes.

## [0.1.2] - 2026-05-12

CI-only fix. No customer-facing code changes from `v0.1.1`.

### Fixed

- Re-coupled the Trivy `security-scan` job to release gating and published a
  real GitHub Release page, now that the repository's Actions
  workflow-permissions setting grants `security-events: write`.

## [0.1.1] - 2026-05-12

CI-only fix. No customer-facing code changes from `v0.1.0`.

### Fixed

- Decoupled `security-scan` from the GitHub Release publish step so an
  org-level Actions permissions gap can't silently block artifact
  publishing (the release job had been failing at "Set up job").

## [0.1.0] - 2026-05-12

Initial tagged release. MVP scope: CloudTrail, GitHub PR/deploy, and
PagerDuty event sources only.

### Added

- Read-only collector binary (`cmd/collector`) shipping envelopes conforming
  to `evidence_envelope.json` v1.0.0 over mTLS to the ingest API.
- WAL-backed transport with at-least-once delivery and crash recovery
  (`/var/lib/operitas/wal/`).
- `internal/envelope` fixture-based contract tests (accept/reject +
  error-message assertions against the shared fixture tree).
- Release pipeline: cosign keyless-signed binaries (linux/amd64,
  linux/arm64, darwin/amd64, darwin/arm64) and container image, SLSA
  provenance on the image, Helm chart packaged and pushed to the GHCR OCI
  registry.
- Helm chart: distroless nonroot deployment, read-only root filesystem, all
  Linux capabilities dropped, `ClusterRole` with zero rules, `NetworkPolicy`
  restricting egress to port 443 and DNS only.

---

**Why the jump from `0.1.2` to `0.2.0`:** at the time this file was created
(2026-07-07, preparing what monorepo issue `operitas-eu/operitas#127` calls
the collector's "first release"), the tags `v0.1.0`, `v0.1.1`, and `v0.1.2`
were found to already exist on `origin`, each with a published GitHub
Release (`v0.1.2` carries real signed binaries, a signed image, and a
packaged Helm chart from 2026-05-12). Re-using `v0.1.0` for the current body
of work is not possible without deleting or force-moving an existing public,
signed release, which was out of scope for this change. `0.2.0` is the next
free version that reflects the real SemVer delta (substantial backward
compatible feature additions, no breaking changes) since `v0.1.2`. See the
release-branch PR description for the full discrepancy report against issue
#127's premise that "no release has ever been cut."
