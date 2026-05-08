# collector Helm Chart

This chart deploys the read-only DORA evidence collector for the Operitas platform
into your Kubernetes cluster.

## Security posture for your security team

The collector is explicitly designed to be safe to run in production infrastructure.
Here is what it does and what it never does.

### What the collector reads

| Source | API calls made | Verb |
|---|---|---|
| AWS CloudTrail | `s3:ListObjectsV2` on your CloudTrail delivery bucket | Read |
| AWS CloudTrail | `s3:GetObject` on CloudTrail log files | Read |
| GitHub | `GET /orgs/{org}/repos` | Read |
| GitHub | `GET /repos/{owner}/{repo}/pulls` | Read |
| GitHub | `GET /repos/{owner}/{repo}/deployments` | Read |
| GitHub | `GET /repos/{owner}/{repo}/deployments/{id}/statuses` | Read |
| GitHub | Webhook payloads pushed by GitHub to the collector | Passive |
| PagerDuty | Webhook payloads pushed by PagerDuty to the collector | Passive |

### What the collector never does

- Never calls any write, create, update, patch, or delete API on any source system.
- Never stores data outside `/var/lib/operitas/` (WAL spool for crash resilience).
- Never logs raw event payloads at INFO level.
- Never sends data to any endpoint other than the configured `ingest.endpoint`.
- Never calls non-EU cloud endpoints (validated at startup).

### Kubernetes RBAC

The collector's `ClusterRole` has **no rules** in the MVP (no Kubernetes API access
needed). When the `k8s.audit` source is added in a future release, only `get`,
`list`, and `watch` verbs will be added. The role is auditable in
`templates/clusterrole.yaml`.

### Pod security

- Runs as UID 65532 (distroless nonroot).
- `readOnlyRootFilesystem: true`.
- All Linux capabilities dropped.
- `allowPrivilegeEscalation: false`.
- `seccompProfile: RuntimeDefault`.

### Network policy

The bundled `NetworkPolicy` (enabled by default) enforces:
- Inbound: only webhook ports (8081, 8082) and the metrics port (9090).
- Outbound: only port 443/TCP (HTTPS to the ingest endpoint and AWS S3 if
  CloudTrail is enabled) plus port 53/UDP+TCP for DNS.
- All other egress is denied.

## Prerequisites

- Kubernetes 1.26+
- Helm 3.12+
- An mTLS client certificate issued by the Operitas control plane (contact
  security@operitas.eu during onboarding).

## Installation

1. Create the required secrets (see `templates/secret-stub.yaml` for the full list
   of expected keys):

```bash
kubectl create secret generic collector-secrets \
  --namespace operitas \
  --from-literal=OPERITAS_GITHUB_TOKEN=ghp_... \
  --from-literal=OPERITAS_GITHUB_WEBHOOK_SECRET=whsec_... \
  --from-literal=OPERITAS_PD_SIGNING_SECRET=pdsk_...

kubectl create secret tls collector-mtls \
  --namespace operitas \
  --cert=collector.crt \
  --key=collector.key
```

2. Create a values override file:

```yaml
tenantId: "your-tenant-uuid"
collectorId: "your-collector-uuid"

sources:
  cloudtrail:
    enabled: true
    bucketName: "your-cloudtrail-bucket"
    bucketRegion: "eu-central-1"

  github:
    enabled: true
    org: "your-github-org"

  pagerduty:
    enabled: true

serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/collector-reader"
```

3. Install:

```bash
helm install collector ./collector/helm/collector \
  --namespace operitas \
  --create-namespace \
  --values my-values.yaml
```

## AWS IAM policy

Attach the following read-only policy to the IRSA role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudTrailReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::YOUR-CLOUDTRAIL-BUCKET",
        "arn:aws:s3:::YOUR-CLOUDTRAIL-BUCKET/*"
      ]
    }
  ]
}
```

No other AWS permissions are required or should be granted.

## GitHub App permissions

If using a GitHub App instead of a PAT, the required permissions are:

| Permission | Access |
|---|---|
| Contents | Read |
| Deployments | Read |
| Pull requests | Read |
| Metadata | Read |

No write permissions are required or should be granted.
