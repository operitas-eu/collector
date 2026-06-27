# Changelog — collector Helm Chart

## 0.4.0 — 2026-06-27

### BREAKING CHANGE

`networkPolicy.egressCidr` is now **required** when `networkPolicy.enabled=true`
(the default). Running `helm upgrade` without setting this value will fail with
an explicit error message.

**Migration step:** Resolve the FQDN of your ingest endpoint to an IP address
and set the CIDR in your values override:

```yaml
networkPolicy:
  enabled: true
  egressCidr: "1.2.3.4/32"   # replace with actual resolved IP of your ingest host
```

The previous behaviour — where omitting `egressCidr` silently rendered an
unrestricted 443 egress rule — defeated the EU-residency enforcement goal of the
NetworkPolicy and is no longer allowed.

### Added

- `networkPolicy.egressCidr` required guard (`required` Helm template function).
  `helm template` and `helm install` fail with a descriptive error if the value
  is empty or unset.

### Changed

- WAL/DLQ prune now emits `WARN`-level logs (previously `INFO`) when entries are
  dropped. Each dropped entry logs `"evidence may not reach the ingest ledger"`.
  A summary WARN with counts fires at the end of every prune cycle that actually
  drops entries: `"evidence dropped before delivery: WAL/DLQ entries pruned
  without acknowledgement"`. The existing
  `operitas_collector_wal_pruned_total{reason="age|size"}` Prometheus counter is
  unaffected — it continues to track cumulative pruned counts.

- Azure Activity source now emits a startup `WARN` reminding operators that EU
  data residency is determined by subscription geography, not the ARM hostname
  (`management.azure.com` is a global endpoint).

### Security

- All nine REST-polling sources (`datadog`, `gitlab`, `github`, `bitbucket`,
  `opsgenie`, `incidentio`, `jira`, `servicenow`, `argocd`) now refuse HTTP
  redirects (`CheckRedirect: http.ErrUseLastResponse`). A vendor-issued 302
  could previously have forwarded authentication headers to an arbitrary host.

- EU endpoint validation is now fail-closed: unknown hosts produce a hard
  validation error unless `OPERITAS_ALLOW_NON_EU_ENDPOINT=1` is set explicitly.
  Previously the guard was advisory only.

## 0.3.0 — 2026-05-28

### Added
- `sources.azure_activity` values block (enabled, tenantId, subscriptionId,
  clientId, useWorkloadIdentity, pollInterval, pollLookback). Disabled by default.
- ConfigMap template renders `azure_activity:` stanza into the collector config.
- `OPERITAS_AZURE_CLIENT_SECRET` key documented in `secret-stub.yaml` comments.
- README section covering Workload Identity, client-secret, and RBAC setup.

## 0.2.0 — 2026-05-08

### Changed
- Chart renamed from `operitas-col` to `collector` following repo extraction
  into `github.com/operitas-eu/collector`. All template helper names updated
  to `collector.*`. No functional change to rendered manifests.

## 0.1.0 — 2026-05-07

Initial release. MVP scope per manifest §10.1.

### Added
- Deployment with distroless nonroot container, read-only root filesystem.
- ServiceAccount with IRSA / Azure Workload Identity annotation scaffolding.
- ConfigMap-driven configuration (all values from values.yaml).
- Secret stub documentation (credentials are never stored in the chart).
- NetworkPolicy denying all inbound except webhook ports and metrics, and all
  egress except port 443/TCP and DNS.
- PersistentVolumeClaim for the WAL spool (/var/lib/operitas/).
- ClusterRole with zero rules (read-only posture; no Kubernetes API access needed
  in MVP).
- Service exposing github-webhook (8081), pd-webhook (8082), metrics (9090).
- Liveness and readiness probes on /healthz.
- Pod security context: runAsNonRoot, readOnlyRootFilesystem, all capabilities
  dropped, seccompProfile RuntimeDefault.
