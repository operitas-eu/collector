# Operitas Collector

Read-only DORA evidence collector. Runs inside your infrastructure and ships
signed event envelopes to the Operitas ingest API over mTLS — nothing else.

The collector is open-source (MIT) so you can read, audit, and verify it before
deploying it to your environment. The wider Operitas platform (ingest pipeline,
classification agent, ledger, compliance portal) is closed-source SaaS operated
by ReOps Tech S.R.L. in the EU. Learn more at [operitas.eu](https://operitas.eu).

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
go build ./cmd/collector
OPERITAS_CONFIG_FILE=./testdata/config-dev.yaml ./collector
```

## Testing

```bash
go test ./...
```

## Deploying

See `helm/collector/README.md` for the Helm installation guide.

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy.

## License

MIT — see [LICENSE](LICENSE).
