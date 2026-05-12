# Operitas Collector

Read-only DORA evidence collector. Runs inside your infrastructure and ships
signed event envelopes to the Operitas ingest API over mTLS — nothing else.

The collector is open-source (MIT) so you can read, audit, and verify it before
deploying it to your environment. The wider Operitas platform (ingest pipeline,
classification agent, ledger, compliance portal) is closed-source SaaS operated
by ReOps Tech S.R.L. in the EU. Learn more at [operitas.eu](https://operitas.eu).

## Quickstart

### Step 1 — Get credentials

A tenant admin opens the Operitas portal, navigates to
`https://app.operitas.eu/settings/collectors`, and clicks **New collector**.

The portal shows a one-time credential screen containing three values:

| Field | Description |
|---|---|
| `collector_id` | UUID that identifies this collector instance. Embedded in every event envelope. |
| `api_key` | Bearer token in `<key_id>.<secret>` form. Shown exactly once — save it now. |
| `ingest_url` | The HTTPS endpoint the collector ships batches to (always an EU-resident host). |

The plaintext `api_key` is never recoverable from the server after this screen
is closed. If it is lost, mint a new credential and revoke the old one.

### Step 2 — Install

#### Helm (recommended for Kubernetes)

```bash
# Create the namespace:
kubectl create namespace operitas --dry-run=client -o yaml | kubectl apply -f -

# 1. Create the API key secret (from the portal enrollment output):
kubectl create secret generic operitas-collector-api-key \
  --namespace operitas \
  --from-literal=OPERITAS_INGEST_API_KEY=<api_key from portal>

# 2. Create the mTLS secret:
kubectl create secret tls collector-mtls \
  --namespace operitas \
  --cert=collector.crt \
  --key=collector.key

# 3. Create source-credential secrets (only include keys for sources you enable):
kubectl create secret generic collector-secrets \
  --namespace operitas \
  --from-literal=OPERITAS_GITHUB_TOKEN=ghp_... \
  --from-literal=OPERITAS_GITHUB_WEBHOOK_SECRET=whsec_... \
  --from-literal=OPERITAS_PD_SIGNING_SECRET=pdsk_...

# 4. Install the chart, referencing the API key secret you just created:
helm install operitas-collector ./helm/collector \
  --namespace operitas \
  --set tenantId=<your-tenant-id> \
  --set collectorId=<collector_id from portal> \
  --set ingest.endpoint=<ingest_url from portal> \
  --set existingApiKeySecret=operitas-collector-api-key \
  --set sources.cloudtrail.enabled=true \
  --set sources.cloudtrail.bucketName=my-cloudtrail-bucket \
  --set sources.cloudtrail.bucketRegion=eu-central-1 \
  --set sources.github.enabled=true \
  --set sources.github.org=my-github-org
```

For development only (value is stored in Helm release history — use the
`existingApiKeySecret` pattern above for production):

```bash
helm install operitas-collector ./helm/collector \
  --namespace operitas \
  --set tenantId=<your-tenant-id> \
  --set collectorId=<collector_id from portal> \
  --set ingest.endpoint=<ingest_url from portal> \
  --set apiKey=<api_key from portal> \
  ...
```

See `helm/collector/README.md` for the full values reference and IAM / GitHub
App permission requirements.

#### Docker (standalone VMs or local testing)

```bash
docker run --rm \
  -e OPERITAS_CONFIG_FILE=/config/config.yaml \
  -e OPERITAS_INGEST_API_KEY=<api_key from portal> \
  -v /path/to/your/config.yaml:/config/config.yaml:ro \
  -v operitas-wal:/var/lib/operitas \
  ghcr.io/operitas-eu/collector:0.1.0
```

The config file must contain at minimum:

```yaml
tenant_id:    "<your-tenant-id>"
collector_id: "<collector_id from portal>"

ingest:
  endpoint:      "<ingest_url from portal>"
  tls_cert_file: "/certs/tls.crt"
  tls_key_file:  "/certs/tls.key"

sources:
  cloudtrail:
    enabled:       true
    bucket_name:   "my-cloudtrail-bucket"
    bucket_region: "eu-central-1"
```

`OPERITAS_INGEST_API_KEY` is a required environment variable — the collector
will exit at startup with a clear error if it is absent.

Mount your mTLS certificate into `/certs/` and the WAL volume into
`/var/lib/operitas` (a named volume or host path with appropriate permissions
for UID 65532).

### Step 3 — Verify

Check the collector logs for a successful startup:

```bash
# Kubernetes
kubectl logs -n operitas deploy/operitas-collector

# Docker
docker logs operitas-collector
```

On a healthy startup you will see:

```
{"level":"INFO","msg":"collector starting","version":"0.1.0"}
{"level":"INFO","msg":"collector running","tenant_id":"...","collector_id":"..."}
```

Any delivery failure logs at WARN (transient, will retry) or ERROR (permanent).
A clean log stream with no WARN or ERROR lines means the collector is operating
correctly.

### Step 4 — Confirm in portal

A tenant admin reloads `https://app.operitas.eu/settings/collectors`. The
collector row's **Last used** column should show a recent timestamp after the
first successful batch delivery.

### Step 5 — Rotate or revoke credentials

To rotate: mint a new collector credential in the portal, update the
`OPERITAS_INGEST_API_KEY` value (Secret or env var), then revoke the old
credential in the portal.

To revoke: a tenant admin clicks **Revoke** on the collector row. The ingest
API immediately returns `401` on the next batch attempt. The collector logs:

```
{"level":"ERROR","msg":"ingest rejected batch (permanent); dropping","status":401}
```

No further data leaves the environment until new credentials are configured.

---

## Wire-contract test mode

Use `--emit-event` to push a single synthetic event from any test box directly
to the production control plane. This exercises the full transport stack — WAL
write, envelope validation, idempotency key generation, mTLS (or plain TLS),
retry/backoff, DLQ — without running a long-lived collector. It is the
recommended way to validate the wire contract after an enrollment or after a
collector upgrade.

### Required environment variables

| Variable | Description |
|---|---|
| `OPERITAS_INGEST_API_KEY` | Bearer token from the portal enrollment screen |
| `OPERITAS_INGEST_URL` | Ingest endpoint (defaults to `https://api.operitas.eu/v1/events:batch`) |
| `OPERITAS_COLLECTOR_ID` | Collector UUID from the portal (optional; a fresh UUID is generated if absent) |

### Flag reference

```
--emit-event
    --tenant-id    <uuid>        Tenant UUID (required)
    --event-type   <string>      Event type in lower.dot.notation, e.g. vendor.outage (required)
    --event-source <string>      Event source enum, e.g. aws.cloudtrail (required)
    [--actor       <string>]     IAM principal, user, or bot name
    [--resource    <string>]     Affected resource identifier (ARN, repo path, service name…)
    [--payload-file <path>]      Path to a JSON object file; defaults to {}
```

`event-source` must be one of the enum values in the evidence envelope schema:
`aws.cloudtrail`, `azure.activity`, `github`, `pagerduty`, `datadog`, `jira`,
`argocd`, `k8s.audit`, `vendor.statuspage`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Ingest API returned 200 — event accepted |
| `1` | Delivery failed (4xx/5xx, TLS error, or DLQ routing on 422) |
| `2` | Bad flag syntax or missing required flag |

A 422 response means the envelope failed server-side schema validation and was
written to the DLQ (under `/var/lib/operitas/dlq/` in the container). This is a
wire-contract bug — the collector and ingest validators disagree. Check for
schema drift (manifest §0 P1).

### Docker example

```bash
docker run --rm \
  -e OPERITAS_INGEST_API_KEY=<api_key from portal> \
  -e OPERITAS_INGEST_URL=https://api.operitas.eu/v1/events:batch \
  -e OPERITAS_COLLECTOR_ID=<collector_id from portal> \
  ghcr.io/operitas-eu/collector:latest \
  --emit-event \
    --tenant-id <your-tenant-uuid> \
    --event-type vendor.outage \
    --event-source aws.cloudtrail
```

With an optional payload file:

```bash
docker run --rm \
  -e OPERITAS_INGEST_API_KEY=<api_key from portal> \
  -e OPERITAS_INGEST_URL=https://api.operitas.eu/v1/events:batch \
  -v /path/to/payload.json:/tmp/payload.json:ro \
  ghcr.io/operitas-eu/collector:latest \
  --emit-event \
    --tenant-id <your-tenant-uuid> \
    --event-type vendor.outage \
    --event-source aws.cloudtrail \
    --actor "ops-bot" \
    --resource "arn:aws:s3:::my-trail-bucket" \
    --payload-file /tmp/payload.json
```

On success the structured log will include:

```json
{"level":"INFO","msg":"emit_event_start","tenant_id":"...","event_type":"vendor.outage","event_source":"aws.cloudtrail","endpoint":"https://api.operitas.eu/v1/events:batch"}
{"level":"INFO","msg":"emit_event_sent","tenant_id":"...","event_type":"vendor.outage","event_source":"aws.cloudtrail","endpoint":"https://api.operitas.eu/v1/events:batch"}
```

---

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
OPERITAS_CONFIG_FILE=./testdata/config-dev.yaml \
  OPERITAS_INGEST_API_KEY=<api_key from portal> \
  ./collector
```

## Wire contract

The collector ships event envelopes conforming to `evidence_envelope.json` v1.0.0.
The canonical retry-semantics specification is `docs/api/ingest-batch.md` in the
[operitas-eu/operitas](https://github.com/operitas-eu/operitas) monorepo (read-only
link; that repository is not publicly visible). The short version:

| Response | Collector action |
|---|---|
| 200 | Advance WAL cursor to `last_seq + 1`; delete WAL entry |
| 401 / 403 | Stop delivering; surface loud log; operator must rotate key and restart |
| 413 | Split batch in half and retry each half; single-event 413 goes to DLQ |
| 422 | Schema validation failure — route to DLQ, never retry |
| 429 | Honor `Retry-After` header, then retry same batch |
| 5xx | Exponential backoff with jitter; same `Idempotency-Key` so retry is safe |
| TLS error | Fail-closed; leave WAL entry for operator investigation |

Both the collector and the ingest service run independent validators against the
same fixture tree (`internal/envelope/testdata/fixtures/`). Per manifest §0, any
fixture change must land in both repos in lock-step. If the validators disagree on
a fixture, that is a P1 wire-contract bug.

## Testing

```bash
go test -race ./...
```

The envelope contract test (`internal/envelope/envelope_contract_test.go`) walks
the fixture tree and asserts accept/reject outcomes plus error-message substrings.

## Deploying

See `helm/collector/README.md` for the full Helm values reference, IAM policy,
and GitHub App permissions.

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy.

## License

MIT — see [LICENSE](LICENSE).
