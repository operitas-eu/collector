# collector

Read-only DORA evidence collector. Part of the Operitas platform — see
`PROJECT_MANIFEST.md` at the repo root for full context.

Licensed under MIT. Customers are encouraged to read and audit this code; the
permissive license removes legal friction from that review.

## What this collector reads

| Source | What | How |
|---|---|---|
| AWS CloudTrail | Log files delivered to an S3 bucket | `s3:ListObjectsV2`, `s3:GetObject` |
| GitHub | Pull requests, deployment events | `GET` REST endpoints; webhook receiver |
| PagerDuty | Incident lifecycle events | Webhook receiver |

## What this collector never reads or writes

- It never calls any write API on any source system.
- It never reads Kubernetes Secrets, ConfigMaps, or any Kubernetes API in the MVP.
- It never writes outside `/var/lib/operitas/` (WAL spool for crash resilience).
- It never logs raw event payloads (only event metadata at INFO level).
- It never contacts non-EU cloud endpoints.

## PII handling

By default (`redact.hash_pii: false`), email addresses and IP addresses found
in event payloads are replaced with `[redacted]` before the event is transmitted.

When `redact.hash_pii: true`, PII is replaced with `hmac:<hex>` using a customer-
provided HMAC-SHA256 key (set in `OPERITAS_REDACT_HASH_KEY`). This allows
cross-event correlation without transmitting raw PII.

## Running locally

```bash
cd collector
go build ./cmd/collector
OPERITAS_CONFIG_FILE=./testdata/config-dev.yaml ./collector
```

## Testing

```bash
cd collector
go test ./...
```

## Deploying

See `helm/collector/README.md` for the Helm installation guide.
