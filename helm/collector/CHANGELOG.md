# Changelog — collector Helm Chart

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
