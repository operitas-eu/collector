# Security Policy

## Scope

This policy covers the **Operitas Collector** binary and its Helm chart
(this repository: `github.com/operitas-eu/collector`).

It does not cover the wider Operitas SaaS platform, the ingest API, or the
compliance portal. Vulnerabilities in those surfaces should still be reported
to the same address; the triage team will route them internally.

## Reporting a vulnerability

Email **security@operitas.eu** with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept (attach rather than paste if it
  contains sensitive detail).
- The version of the collector binary or Helm chart affected.

Please do not open a public GitHub issue for security vulnerabilities.

## Coordinated disclosure

We follow a **90-day coordinated disclosure** window:

1. We acknowledge receipt within **2 business days**.
2. We aim to confirm or refute the report within **7 days**.
3. We target a patch release within **30 days** for critical severity,
   **60 days** for high, **90 days** for medium and below.
4. We will coordinate the public disclosure date with the reporter. If we
   cannot reach agreement, we default to the 90-day deadline.

We do not operate a bug bounty programme at this time.

## In scope

- The collector binary (`cmd/collector` and all packages under `internal/`).
- The Helm chart (`helm/collector/`).
- The mTLS transport and evidence envelope serialisation.
- The WAL spool and crash-recovery logic.
- Container image hardening (distroless, read-only root FS, capability drops).

## Out of scope

- The Operitas control-plane SaaS (closed-source, separate infrastructure).
- Vulnerabilities that require physical access to the customer's Kubernetes nodes.
- Denial-of-service attacks that require compromised cluster credentials.
- Findings from automated scanners submitted without a verified impact statement.
