// Package config loads and validates the collector's runtime configuration.
// Configuration is read from a YAML file whose path is given by the
// OPERITAS_CONFIG_FILE environment variable (default /var/lib/operitas/config.yaml).
// All persistent state the collector writes lives under /var/lib/operitas/ (manifest §9.2,
// hard failure rule 3).
package config

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Filesystem paths owned by the collector. All persistent state must live
// under DataDir (manifest hard failure rule 3).
const (
	DefaultConfigPath = "/var/lib/operitas/config.yaml"
	DataDir           = "/var/lib/operitas"
	WALDir            = "/var/lib/operitas/wal"
	DLQDir            = "/var/lib/operitas/dlq"

	// defaultEndpoint is a placeholder; operators must set ingest.endpoint explicitly.
	// It deliberately has no default that could accidentally route data to a US region.
	defaultEndpoint = "https://ingest.operitas.eu/v1/events:batch"
)

// Config is the top-level configuration struct. All sub-structs map to YAML keys.
type Config struct {
	// TenantID is required. The collector refuses to start without it.
	TenantID string `yaml:"tenant_id"`

	// CollectorID uniquely identifies this collector instance within the tenant.
	CollectorID string `yaml:"collector_id"`

	Ingest  IngestConfig  `yaml:"ingest"`
	Sources SourcesConfig `yaml:"sources"`
	Redact  RedactConfig  `yaml:"redact"`
	Metrics MetricsConfig `yaml:"metrics"`
}

// IngestConfig controls how events are shipped to the control plane.
type IngestConfig struct {
	// Endpoint is the POST /v1/events:batch URL. Must resolve to an EU-resident host.
	Endpoint string `yaml:"endpoint"`

	// APIKey is the bearer token in <key_id>.<secret> format minted by the Operitas
	// portal enrollment flow. Required. Delivered via OPERITAS_INGEST_API_KEY; never
	// stored in YAML or logged. The collector refuses to start if this is empty.
	// Obtain it from https://app.operitas.eu/settings/collectors (shown once on enrollment).
	APIKey string `yaml:"-"`

	// TLSCertFile and TLSKeyFile are the mTLS client certificate and private key.
	// The collector refuses to start if either is absent or cannot be loaded.
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`

	// TLSCAFile is the PEM file for the server CA. Optional; if unset the system
	// cert pool is used (suitable when the control plane uses a public CA).
	TLSCAFile string `yaml:"tls_ca_file"`

	// BatchMaxEvents caps the number of events per batch (JSON schema max: 1000).
	BatchMaxEvents int `yaml:"batch_max_events"`

	// BatchMaxBytes caps the uncompressed JSON size of a batch payload.
	BatchMaxBytes int `yaml:"batch_max_bytes"`

	// BatchFlushInterval is the maximum time events are held before flushing.
	BatchFlushInterval time.Duration `yaml:"batch_flush_interval"`

	// BackoffInitial and BackoffMax bound exponential retry delays.
	BackoffInitial time.Duration `yaml:"backoff_initial"`
	BackoffMax     time.Duration `yaml:"backoff_max"`
}

// SourcesConfig enables or disables each event source.
type SourcesConfig struct {
	CloudTrail    CloudTrailConfig    `yaml:"cloudtrail"`
	AzureActivity AzureActivityConfig `yaml:"azure_activity"`
	GitHub        GitHubConfig        `yaml:"github"`
	GitLab        GitLabConfig        `yaml:"gitlab"`
	PagerDuty     PagerDutyConfig     `yaml:"pagerduty"`

	// New hybrid sources (webhook + optional REST poller).
	Jira       JiraConfig       `yaml:"jira"`
	Datadog    DatadogConfig    `yaml:"datadog"`
	Bitbucket  BitbucketConfig  `yaml:"bitbucket"`
	IncidentIO IncidentIOConfig `yaml:"incident_io"`
	Opsgenie   OpsgenieConfig   `yaml:"opsgenie"`
	ServiceNow ServiceNowConfig `yaml:"servicenow"`
	ArgoCD     ArgoCDConfig     `yaml:"argocd"`

	// New webhook-only sources (push-only platforms, no REST poller).
	Prometheus PrometheusConfig `yaml:"prometheus"`
	Flux       FluxConfig       `yaml:"flux"`
	Spacelift  SpaceliftConfig  `yaml:"spacelift"`
	Grafana    GrafanaConfig    `yaml:"grafana"`

	// SharedWebhookPort is the port all new webhook sources share.
	// Existing github/gitlab/pagerduty keep their own dedicated ports
	// until an explicit migration step is taken.
	// Default: 8090.
	SharedWebhookPort int `yaml:"shared_webhook_port"`
}

// CloudTrailConfig configures the AWS CloudTrail S3 reader.
type CloudTrailConfig struct {
	Enabled bool `yaml:"enabled"`

	// BucketName is the S3 bucket where CloudTrail delivers logs.
	BucketName string `yaml:"bucket_name"`

	// BucketRegion must be an EU region. The collector validates this at startup.
	// Permitted values: eu-central-1, eu-west-1, eu-west-2, eu-west-3,
	//                   eu-north-1, eu-south-1, eu-south-2, eu-central-2.
	BucketRegion string `yaml:"bucket_region"`

	// Prefix is the S3 key prefix where CloudTrail writes logs (e.g. "AWSLogs/").
	Prefix string `yaml:"prefix"`

	// PollInterval controls how often the S3 bucket is polled for new log files.
	PollInterval time.Duration `yaml:"poll_interval"`

	// CursorPath is the file used to persist the last-processed S3 key so
	// restarts skip already-seen objects. Defaults to DataDir/cloudtrail_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// AzureActivityConfig configures the Azure Activity Logs poller.
//
// Authentication precedence (applied by the source package):
//  1. Azure Workload Identity (UseWorkloadIdentity: true) — preferred in AKS.
//     Requires the pod service account to be federated with an Azure managed identity.
//  2. Client secret (OPERITAS_AZURE_CLIENT_SECRET set) — for non-AKS deployments.
//  3. Managed Identity (system-assigned or user-assigned) — fallback when running
//     on Azure VMs or AKS without Workload Identity federation.
//
// ClientID and TenantID are always required.
// ClientSecret must not be stored in YAML; use OPERITAS_AZURE_CLIENT_SECRET.
//
// The Activity Logs API endpoint is the Azure Resource Manager global endpoint
// (management.azure.com). This endpoint processes only metadata about your
// Azure operations, not customer event payload data. The subscription and
// tenant being monitored must be EU-resident for the EU-only data path to hold.
type AzureActivityConfig struct {
	Enabled bool `yaml:"enabled"`

	// TenantID is the Azure Active Directory tenant ID (UUID).
	TenantID string `yaml:"tenant_id"`

	// SubscriptionID is the Azure subscription to monitor (UUID).
	SubscriptionID string `yaml:"subscription_id"`

	// ClientID is the service principal or managed-identity client ID.
	// Required for client-secret and workload-identity modes.
	// For system-assigned managed identity, leave empty.
	ClientID string `yaml:"client_id"`

	// ClientSecret is the service-principal client secret.
	// Never stored in YAML — populated via OPERITAS_AZURE_CLIENT_SECRET.
	ClientSecret string `yaml:"-"`

	// UseWorkloadIdentity, when true, uses Azure Workload Identity
	// (federated OIDC token) instead of a client secret. Requires AKS with
	// Workload Identity enabled and the pod service account annotated with the
	// managed-identity client ID.
	UseWorkloadIdentity bool `yaml:"use_workload_identity"`

	// PollInterval controls how often Activity Logs are fetched.
	PollInterval time.Duration `yaml:"poll_interval"`

	// PollLookback is the time window fetched on the first poll (no cursor).
	// Defaults to 1 hour. Keep this shorter than your poll interval to avoid
	// re-processing events on restart.
	PollLookback time.Duration `yaml:"poll_lookback"`

	// CursorPath is where the last-seen event timestamp is persisted.
	// Defaults to DataDir/azureactivity_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// GitHubConfig configures the GitHub event source (webhook + polling fallback).
type GitHubConfig struct {
	Enabled bool `yaml:"enabled"`

	// Org is the GitHub organisation to watch (for polling fallback).
	Org string `yaml:"org"`

	// Repos is an optional list of repositories to watch. If empty, all repos
	// in the org are watched. The collector only ever calls GET endpoints.
	Repos []string `yaml:"repos"`

	// Token is a GitHub PAT or GitHub App installation token with read:repo scope.
	// Delivered via environment variable OPERITAS_GITHUB_TOKEN (not stored in YAML).
	// This field is populated by Load() from the env var.
	Token string `yaml:"-"`

	// WebhookSecret is the HMAC-SHA256 secret shared with GitHub for webhook
	// delivery. Delivered via OPERITAS_GITHUB_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// WebhookPort is the port on which the collector listens for GitHub webhooks.
	WebhookPort int `yaml:"webhook_port"`

	// PollInterval controls the polling fallback schedule.
	PollInterval time.Duration `yaml:"poll_interval"`

	// CursorPath is where the last-seen poll timestamp is persisted so the
	// poller picks up where it left off after a restart. Without a cursor,
	// any events that occur while the collector is down are missed.
	// Defaults to DataDir/github_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// GitLabConfig configures the GitLab event source (webhook + polling fallback).
// Read-only GET endpoints only: /projects, /projects/:id/merge_requests,
// /projects/:id/deployments. The collector never calls any POST/PUT/DELETE.
type GitLabConfig struct {
	Enabled bool `yaml:"enabled"`

	// BaseURL is the GitLab API root, e.g. "https://gitlab.com/api/v4" for SaaS
	// or "https://gitlab.example.eu/api/v4" for a self-hosted EU instance.
	// Validated against isKnownNonEUEndpoint at startup; self-hosted operators
	// with strict residency requirements should point at an EU-resident host.
	BaseURL string `yaml:"base_url"`

	// Projects is the list of project IDs or url-encoded paths (e.g.
	// "mygroup%2Fmyrepo") to poll. If empty, all projects the token has access
	// to (membership=true) are listed via GET /projects.
	Projects []string `yaml:"projects"`

	// Token is a personal access token or group/project access token with
	// read_api scope. Delivered via OPERITAS_GITLAB_TOKEN; never stored in YAML.
	Token string `yaml:"-"`

	// WebhookSecret is the shared secret matched against the X-Gitlab-Token
	// header. GitLab's default webhook auth is plain-secret equality, not HMAC;
	// verified via sigverify.SecretEqual (constant-time). Delivered via
	// OPERITAS_GITLAB_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// WebhookPort is the port the collector listens on for GitLab webhooks.
	// Defaults to 8083 to avoid collision with GitHub (8081) and PagerDuty (8082).
	WebhookPort int `yaml:"webhook_port"`

	// PollInterval controls the polling fallback schedule.
	PollInterval time.Duration `yaml:"poll_interval"`

	// CursorPath is where the last-seen poll timestamp is persisted so the
	// poller picks up where it left off after a restart. Without a cursor,
	// any events that occur while the collector is down are missed.
	// Defaults to DataDir/gitlab_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// PagerDutyConfig configures the PagerDuty webhook receiver.
type PagerDutyConfig struct {
	Enabled bool `yaml:"enabled"`

	// WebhookPort is the port the collector listens on for PagerDuty webhooks.
	WebhookPort int `yaml:"webhook_port"`

	// SigningSecret is the PagerDuty webhook signing secret for payload verification.
	// Delivered via OPERITAS_PD_SIGNING_SECRET.
	SigningSecret string `yaml:"-"`
}

// JiraConfig configures the Jira event source (webhook + REST poller).
//
// Webhook: Jira sends a POST with a shared secret in the X-Hub-Signature-256 header
// (or older deployments use a plain token in Authorization). The collector verifies
// it with sigverify.SecretEqual (plain equality, as Jira does not HMAC-sign payloads
// by default; the webhook secret is sent verbatim in the Authorization header as
// "Bearer <secret>"). Operators using Jira Automation rule webhooks should set
// WebhookSecret to the value configured in the Automation rule.
//
// REST poller: GET /rest/api/3/search (JQL ordered by updated desc) to backfill
// issues when webhooks are unavailable. EU-only: BaseURL must not resolve to a
// non-EU Atlassian Cloud host. Self-hosted Jira operators must provide an EU
// BaseURL. For Atlassian Cloud, the EU tenant URL pattern is:
//
//	https://<tenant>.atlassian.net  (data residency enforced by tenant config)
//
// The poller emits events only for issues updated since the last cursor.
type JiraConfig struct {
	Enabled bool `yaml:"enabled"`

	// BaseURL is the Jira API root, e.g. "https://mycompany.atlassian.net"
	// or "https://jira.example.eu" for self-hosted. Validated against
	// isKnownNonEUEndpoint at startup.
	BaseURL string `yaml:"base_url"`

	// WebhookSecret is the shared secret verified in the Authorization header
	// ("Bearer <secret>"). Delivered via OPERITAS_JIRA_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// Token is a Jira API token (Atlassian API token or PAT for self-hosted).
	// Required for the REST poller. Delivered via OPERITAS_JIRA_TOKEN.
	// Scopes needed: read:jira-work (Atlassian Cloud) or Browse Projects (server).
	Token string `yaml:"-"`

	// Projects is an optional list of Jira project keys (e.g. ["OPS", "INFRA"])
	// to restrict webhook events and polling. If empty, all projects are observed.
	Projects []string `yaml:"projects"`

	// JQLFilter is an optional additional JQL clause appended to the poller's
	// query (e.g. "issuetype = Story"). Default: no extra filter.
	JQLFilter string `yaml:"jql_filter"`

	// PollInterval controls how often the REST API is polled.
	PollInterval time.Duration `yaml:"poll_interval"`

	// PollLookback is the time window used on the first poll when no cursor exists.
	PollLookback time.Duration `yaml:"poll_lookback"`

	// CursorPath is where the last-seen issue updated timestamp is persisted.
	// Defaults to DataDir/jira_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// DatadogConfig configures the Datadog event source (webhook + Events REST poller).
//
// Webhook: Datadog sends an application/json POST. The shared secret is sent in
// the DD-API-KEY header (constant-time equality check via sigverify.SecretEqual).
// The collector verifies this header before processing.
//
// REST poller: GET https://api.datadoghq.eu/api/v1/events (EU endpoint only).
// Auth: DD-API-KEY and DD-APPLICATION-KEY headers. The collector validates that
// the configured APIBaseURL does not resolve to a non-EU Datadog region.
// Datadog EU API: https://api.datadoghq.eu
type DatadogConfig struct {
	Enabled bool `yaml:"enabled"`

	// APIBaseURL is the Datadog API base URL. Must be an EU endpoint.
	// Default: "https://api.datadoghq.eu"
	// Accepted alternatives: "https://api.eu1.datadoghq.com"
	// Non-EU URLs (api.datadoghq.com, api.us3.datadoghq.com, etc.) are rejected
	// at startup.
	APIBaseURL string `yaml:"api_base_url"`

	// WebhookSecret is the shared secret verified in the DD-API-KEY header.
	// Delivered via OPERITAS_DATADOG_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// APIKey is the Datadog API key for the REST poller.
	// Delivered via OPERITAS_DATADOG_TOKEN (we follow the OPERITAS_<SOURCE>_TOKEN
	// convention even though Datadog calls it an API key).
	APIKey string `yaml:"-"`

	// AppKey is the Datadog Application key (required for the Events API).
	// Delivered via OPERITAS_DATADOG_APP_KEY.
	AppKey string `yaml:"-"`

	// PollInterval controls how often the Events API is polled.
	PollInterval time.Duration `yaml:"poll_interval"`

	// PollLookback is the time window used on the first poll when no cursor exists.
	PollLookback time.Duration `yaml:"poll_lookback"`

	// CursorPath is where the last-seen event timestamp is persisted.
	// Defaults to DataDir/datadog_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// PrometheusConfig configures the Prometheus Alertmanager webhook receiver.
//
// Prometheus Alertmanager fires a POST to the collector's webhook endpoint when
// an alert fires or resolves. The collector supports two auth schemes, configurable
// via AuthScheme:
//
//   - "bearer": Authorization header is "Bearer <WebhookSecret>"
//   - "basic":  Authorization header is "Basic base64(<BasicUser>:<WebhookSecret>)"
//
// No REST poller: Prometheus/Alertmanager is push-only; the collector is purely
// a passive receiver.
//
// Reference: https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
type PrometheusConfig struct {
	Enabled bool `yaml:"enabled"`

	// WebhookSecret is the bearer token or password (for basic auth).
	// Delivered via OPERITAS_PROMETHEUS_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// AuthScheme controls how the Authorization header is validated.
	// Valid values: "bearer" (default), "basic", "none".
	// "none" disables auth checking — use only in fully private network segments.
	AuthScheme string `yaml:"auth_scheme"`

	// BasicUser is the expected username for basic auth mode.
	// Ignored unless AuthScheme is "basic".
	BasicUser string `yaml:"basic_user"`
}

// BitbucketConfig configures the Bitbucket event source (webhook + REST poller).
//
// Webhook: Bitbucket signs with HMAC-SHA256; the signature is in the
// X-Hub-Signature-256 header with "sha256=" prefix (same scheme as GitHub).
// Verify with sigverify.HexHMACPrefixed(..., "sha256=").
//
// REST poller: Bitbucket Cloud REST API v2 — GET /repositories/{workspace}/{repo}/pullrequests
// and /deployments. Requires OAuth2 client credentials (not stored in YAML).
// BaseURL for Cloud: "https://api.bitbucket.org/2.0" — this is a global endpoint;
// Bitbucket does not offer EU-region-specific API endpoints. Flag with a comment
// in the implementation: this is acceptable because it is a metadata/audit API,
// not a customer-data-storage API. The poller is hybrid but the EU-only rule
// applies strictly to customer data at rest.
type BitbucketConfig struct {
	Enabled bool `yaml:"enabled"`

	// BaseURL is the Bitbucket API root. Default: "https://api.bitbucket.org/2.0".
	// For Bitbucket Data Center (self-hosted EU instance), set to
	// "https://bitbucket.example.eu/rest/api/1.0".
	BaseURL string `yaml:"base_url"`

	// WebhookSecret is the HMAC-SHA256 secret shared with Bitbucket.
	// Delivered via OPERITAS_BITBUCKET_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// Token is the OAuth2 access token or HTTP access token for the REST poller.
	// Delivered via OPERITAS_BITBUCKET_TOKEN.
	Token string `yaml:"-"`

	// Workspace is the Bitbucket workspace (Cloud) or project key (Data Center)
	// to watch. Required for the REST poller.
	Workspace string `yaml:"workspace"`

	// Repos is an optional list of repository slugs to watch. If empty, all
	// repos in the workspace are polled.
	Repos []string `yaml:"repos"`

	// PollInterval controls how often the REST API is polled.
	PollInterval time.Duration `yaml:"poll_interval"`

	// CursorPath is where the last-seen event timestamp is persisted.
	// Defaults to DataDir/bitbucket_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// IncidentIOConfig configures the incident.io event source (webhook + REST poller).
//
// Webhook: incident.io signs payloads with HMAC-SHA256; the signature is in the
// X-Signature-256 header with "sha256=" prefix.
// Reference: https://api-docs.incident.io/tag/Webhook-HTTP-Endpoints
//
// REST poller: GET https://api.incident.io/v2/incidents (EU-hosted SaaS).
// Auth: Bearer token in Authorization header.
type IncidentIOConfig struct {
	Enabled bool `yaml:"enabled"`

	// APIBaseURL is the incident.io API base. Default: "https://api.incident.io/v2".
	// incident.io is EU-hosted SaaS; this URL must not be changed to a non-EU host.
	APIBaseURL string `yaml:"api_base_url"`

	// WebhookSecret is the HMAC-SHA256 secret configured on the incident.io webhook.
	// Delivered via OPERITAS_INCIDENTIO_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// Token is the API token for the REST poller.
	// Delivered via OPERITAS_INCIDENTIO_TOKEN.
	Token string `yaml:"-"`

	// PollInterval controls how often the incidents API is polled.
	PollInterval time.Duration `yaml:"poll_interval"`

	// PollLookback is the time window used on the first poll when no cursor exists.
	PollLookback time.Duration `yaml:"poll_lookback"`

	// CursorPath is where the last-seen incident update timestamp is persisted.
	// Defaults to DataDir/incidentio_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// OpsgenieConfig configures the Opsgenie event source (webhook + REST poller).
//
// Webhook: Opsgenie sends a POST with the shared secret in the
// X-OG-Webhook-Secret header (plain-secret equality).
// Reference: https://support.atlassian.com/opsgenie/docs/outgoing-webhook-settings/
//
// REST poller: GET https://api.eu.opsgenie.com/v2/alerts (EU endpoint required).
// Auth: GenieKey header.
type OpsgenieConfig struct {
	Enabled bool `yaml:"enabled"`

	// APIBaseURL is the Opsgenie API base URL. Must be the EU endpoint.
	// Default: "https://api.eu.opsgenie.com/v2"
	// Non-EU URL (api.opsgenie.com) is rejected at startup.
	APIBaseURL string `yaml:"api_base_url"`

	// WebhookSecret is the shared secret verified in the X-OG-Webhook-Secret header.
	// Delivered via OPERITAS_OPSGENIE_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// Token is the Opsgenie API key ("GenieKey") for the REST poller.
	// Delivered via OPERITAS_OPSGENIE_TOKEN.
	Token string `yaml:"-"`

	// PollInterval controls how often the alerts API is polled.
	PollInterval time.Duration `yaml:"poll_interval"`

	// PollLookback is the time window used on the first poll when no cursor exists.
	PollLookback time.Duration `yaml:"poll_lookback"`

	// CursorPath is where the last-seen alert creation timestamp is persisted.
	// Defaults to DataDir/opsgenie_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// ServiceNowConfig configures the ServiceNow event source (webhook + REST poller).
//
// Webhook: ServiceNow Business Rules or Flow Designer sends a POST to the
// collector's webhook endpoint. The shared secret is sent in the
// X-ServiceNow-Webhook-Secret header (plain-secret equality).
//
// REST poller: GET /api/now/table/change_request (Change Management table).
// Auth: HTTP Basic or OAuth2 bearer token. The collector supports both;
// BasicUser + WebhookSecret (as password) for Basic, or Token for Bearer.
// BaseURL must be the customer's EU-resident ServiceNow instance
// (e.g. "https://mycompany.service-now.com"). The collector validates this
// against isKnownNonEUEndpoint; self-hosted EU operators must ensure their
// instance is EU-resident.
type ServiceNowConfig struct {
	Enabled bool `yaml:"enabled"`

	// BaseURL is the ServiceNow instance root, e.g.
	// "https://mycompany.service-now.com".
	// Validated against isKnownNonEUEndpoint at startup.
	BaseURL string `yaml:"base_url"`

	// WebhookSecret is the shared secret verified in the
	// X-ServiceNow-Webhook-Secret header (also used as password for basic auth).
	// Delivered via OPERITAS_SERVICENOW_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// Token is the OAuth2 bearer token for the REST poller.
	// When set, bearer auth is used instead of basic auth.
	// Delivered via OPERITAS_SERVICENOW_TOKEN.
	Token string `yaml:"-"`

	// BasicUser is the username for HTTP basic auth (poller only).
	// Used when Token is empty. Default: "collector".
	BasicUser string `yaml:"basic_user"`

	// Tables is the list of ServiceNow table names to poll.
	// Default: ["change_request"].
	Tables []string `yaml:"tables"`

	// PollInterval controls how often the ServiceNow table API is polled.
	PollInterval time.Duration `yaml:"poll_interval"`

	// PollLookback is the time window used on the first poll when no cursor exists.
	PollLookback time.Duration `yaml:"poll_lookback"`

	// CursorPath is where the last-seen record sys_updated_on timestamp is persisted.
	// Defaults to DataDir/servicenow_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// ArgoCDConfig configures the Argo CD event source (webhook + REST poller).
//
// Webhook: Argo CD can be configured to send webhook events (shared secret
// in the X-ArgoCD-Token header, plain-secret equality).
// Reference: https://argo-cd.readthedocs.io/en/stable/operator-manual/notifications/
//
// REST poller: GET https://<argocd-server>/api/v1/applications (read-only).
// Auth: Bearer token (argocd CLI token or OIDC token). Requires the
// applications.get permission.
// BaseURL is the customer's Argo CD server URL (e.g. "https://argocd.example.eu").
// Validated against isKnownNonEUEndpoint at startup.
type ArgoCDConfig struct {
	Enabled bool `yaml:"enabled"`

	// BaseURL is the Argo CD API server root, e.g. "https://argocd.example.eu".
	// Validated against isKnownNonEUEndpoint at startup.
	BaseURL string `yaml:"base_url"`

	// WebhookSecret is the shared secret verified in the X-ArgoCD-Token header.
	// Delivered via OPERITAS_ARGOCD_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`

	// Token is a bearer token for the REST poller (argocd account token or OIDC).
	// Delivered via OPERITAS_ARGOCD_TOKEN.
	Token string `yaml:"-"`

	// Namespace is the Kubernetes namespace where Argo CD is installed.
	// Used to construct resource identifiers in events. Default: "argocd".
	Namespace string `yaml:"namespace"`

	// AppSelector is an optional label selector to restrict which Argo CD
	// Applications are polled (e.g. "team=platform"). If empty, all applications
	// the token has access to are polled.
	AppSelector string `yaml:"app_selector"`

	// PollInterval controls how often the Argo CD applications API is polled.
	PollInterval time.Duration `yaml:"poll_interval"`

	// CursorPath is where the last-seen application sync timestamp is persisted.
	// Defaults to DataDir/argocd_cursor.
	CursorPath string `yaml:"cursor_path"`
}

// FluxConfig configures the Flux CD event source (webhook-only, push model).
//
// Flux CD's notification controller sends events to external receivers via the
// Alert/Provider API. The collector acts as a generic webhook receiver.
// Auth: shared secret in the Gotk-Webhook-Secret header (constant-time equality).
// Reference: https://fluxcd.io/flux/components/notification/receivers/
//
// No REST poller: Flux does not expose a push-event history API. Operators
// wanting backfill must replay from the Kubernetes event log using a separate tool.
type FluxConfig struct {
	Enabled bool `yaml:"enabled"`

	// WebhookSecret is the shared secret configured in the Flux Receiver object.
	// Delivered via OPERITAS_FLUX_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`
}

// SpaceliftConfig configures the Spacelift event source (webhook-only, push model).
//
// Spacelift can deliver webhook events on stack run state changes.
// The payload is signed with HMAC-SHA256; the signature is in the
// X-Signature-256 header with "sha256=" prefix.
// Reference: https://docs.spacelift.io/integrations/webhooks
//
// No REST poller: Spacelift's REST API is not publicly documented as stable
// for event history retrieval.
type SpaceliftConfig struct {
	Enabled bool `yaml:"enabled"`

	// WebhookSecret is the HMAC-SHA256 secret configured in the Spacelift webhook.
	// Delivered via OPERITAS_SPACELIFT_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`
}

// GrafanaConfig configures the Grafana event source (webhook-only, push model).
//
// Grafana Alerting sends webhook notifications when alert states change.
// The shared secret is sent in the Authorization header as "Bearer <secret>"
// (constant-time equality via sigverify.SecretEqual).
// Reference: https://grafana.com/docs/grafana/latest/alerting/configure-notifications/webhook-notifier/
//
// No REST poller: Grafana does not expose a stable alerts-history REST API
// suitable for event backfill. Use the webhook as the primary signal.
type GrafanaConfig struct {
	Enabled bool `yaml:"enabled"`

	// WebhookSecret is the shared secret verified in the Authorization header.
	// Delivered via OPERITAS_GRAFANA_WEBHOOK_SECRET.
	WebhookSecret string `yaml:"-"`
}

// RedactConfig controls PII handling across all sources.
type RedactConfig struct {
	// HashPII, when true, replaces PII with a keyed HMAC-SHA256 hex string rather
	// than completely removing it. Allows correlation without exposing raw PII.
	// Default: false (hard redact per manifest §9.2).
	HashPII bool `yaml:"hash_pii"`

	// HashKey is the 32-byte hex key used for keyed hashing. Required when hash_pii
	// is true. Delivered via OPERITAS_REDACT_HASH_KEY.
	HashKey string `yaml:"-"`
}

// MetricsConfig controls the Prometheus metrics endpoint.
type MetricsConfig struct {
	// Port on which the /metrics endpoint is exposed.
	Port int `yaml:"port"`
}

// Load reads config from path, applies defaults, and populates secrets from
// environment variables. It returns a ready-to-use Config or a non-nil error
// describing every validation failure.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}

	applyDefaults(&cfg)
	populateSecrets(&cfg)

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Ingest.Endpoint == "" {
		cfg.Ingest.Endpoint = defaultEndpoint
	}
	if cfg.Ingest.BatchMaxEvents == 0 {
		cfg.Ingest.BatchMaxEvents = 1000
	}
	if cfg.Ingest.BatchMaxBytes == 0 {
		cfg.Ingest.BatchMaxBytes = 1 * 1024 * 1024 // 1 MB
	}
	if cfg.Ingest.BatchFlushInterval == 0 {
		cfg.Ingest.BatchFlushInterval = 250 * time.Millisecond
	}
	if cfg.Ingest.BackoffInitial == 0 {
		cfg.Ingest.BackoffInitial = 1 * time.Second
	}
	if cfg.Ingest.BackoffMax == 0 {
		cfg.Ingest.BackoffMax = 5 * time.Minute
	}
	if cfg.Sources.CloudTrail.PollInterval == 0 {
		cfg.Sources.CloudTrail.PollInterval = 5 * time.Minute
	}
	if cfg.Sources.CloudTrail.CursorPath == "" {
		cfg.Sources.CloudTrail.CursorPath = DataDir + "/cloudtrail_cursor"
	}
	if cfg.Sources.AzureActivity.PollInterval == 0 {
		cfg.Sources.AzureActivity.PollInterval = 5 * time.Minute
	}
	if cfg.Sources.AzureActivity.PollLookback == 0 {
		cfg.Sources.AzureActivity.PollLookback = 1 * time.Hour
	}
	if cfg.Sources.AzureActivity.CursorPath == "" {
		cfg.Sources.AzureActivity.CursorPath = DataDir + "/azureactivity_cursor"
	}
	if cfg.Sources.GitHub.WebhookPort == 0 {
		cfg.Sources.GitHub.WebhookPort = 8081
	}
	if cfg.Sources.GitHub.PollInterval == 0 {
		cfg.Sources.GitHub.PollInterval = 60 * time.Second
	}
	if cfg.Sources.GitHub.CursorPath == "" {
		cfg.Sources.GitHub.CursorPath = DataDir + "/github_cursor"
	}
	if cfg.Sources.GitLab.BaseURL == "" {
		cfg.Sources.GitLab.BaseURL = "https://gitlab.com/api/v4"
	}
	if cfg.Sources.GitLab.WebhookPort == 0 {
		cfg.Sources.GitLab.WebhookPort = 8083
	}
	if cfg.Sources.GitLab.PollInterval == 0 {
		cfg.Sources.GitLab.PollInterval = 60 * time.Second
	}
	if cfg.Sources.GitLab.CursorPath == "" {
		cfg.Sources.GitLab.CursorPath = DataDir + "/gitlab_cursor"
	}
	if cfg.Sources.PagerDuty.WebhookPort == 0 {
		cfg.Sources.PagerDuty.WebhookPort = 8082
	}
	if cfg.Sources.SharedWebhookPort == 0 {
		cfg.Sources.SharedWebhookPort = 8090
	}
	// Jira defaults.
	if cfg.Sources.Jira.PollInterval == 0 {
		cfg.Sources.Jira.PollInterval = 60 * time.Second
	}
	if cfg.Sources.Jira.PollLookback == 0 {
		cfg.Sources.Jira.PollLookback = 1 * time.Hour
	}
	if cfg.Sources.Jira.CursorPath == "" {
		cfg.Sources.Jira.CursorPath = DataDir + "/jira_cursor"
	}
	// Datadog defaults.
	if cfg.Sources.Datadog.APIBaseURL == "" {
		cfg.Sources.Datadog.APIBaseURL = "https://api.datadoghq.eu"
	}
	if cfg.Sources.Datadog.PollInterval == 0 {
		cfg.Sources.Datadog.PollInterval = 60 * time.Second
	}
	if cfg.Sources.Datadog.PollLookback == 0 {
		cfg.Sources.Datadog.PollLookback = 1 * time.Hour
	}
	if cfg.Sources.Datadog.CursorPath == "" {
		cfg.Sources.Datadog.CursorPath = DataDir + "/datadog_cursor"
	}
	// Prometheus defaults.
	if cfg.Sources.Prometheus.AuthScheme == "" {
		cfg.Sources.Prometheus.AuthScheme = "bearer"
	}
	// Bitbucket defaults.
	if cfg.Sources.Bitbucket.BaseURL == "" {
		cfg.Sources.Bitbucket.BaseURL = "https://api.bitbucket.org/2.0"
	}
	if cfg.Sources.Bitbucket.PollInterval == 0 {
		cfg.Sources.Bitbucket.PollInterval = 60 * time.Second
	}
	if cfg.Sources.Bitbucket.CursorPath == "" {
		cfg.Sources.Bitbucket.CursorPath = DataDir + "/bitbucket_cursor"
	}
	// incident.io defaults.
	if cfg.Sources.IncidentIO.APIBaseURL == "" {
		cfg.Sources.IncidentIO.APIBaseURL = "https://api.incident.io/v2"
	}
	if cfg.Sources.IncidentIO.PollInterval == 0 {
		cfg.Sources.IncidentIO.PollInterval = 60 * time.Second
	}
	if cfg.Sources.IncidentIO.PollLookback == 0 {
		cfg.Sources.IncidentIO.PollLookback = 1 * time.Hour
	}
	if cfg.Sources.IncidentIO.CursorPath == "" {
		cfg.Sources.IncidentIO.CursorPath = DataDir + "/incidentio_cursor"
	}
	// Opsgenie defaults.
	if cfg.Sources.Opsgenie.APIBaseURL == "" {
		cfg.Sources.Opsgenie.APIBaseURL = "https://api.eu.opsgenie.com/v2"
	}
	if cfg.Sources.Opsgenie.PollInterval == 0 {
		cfg.Sources.Opsgenie.PollInterval = 60 * time.Second
	}
	if cfg.Sources.Opsgenie.PollLookback == 0 {
		cfg.Sources.Opsgenie.PollLookback = 1 * time.Hour
	}
	if cfg.Sources.Opsgenie.CursorPath == "" {
		cfg.Sources.Opsgenie.CursorPath = DataDir + "/opsgenie_cursor"
	}
	// ServiceNow defaults.
	if cfg.Sources.ServiceNow.BasicUser == "" {
		cfg.Sources.ServiceNow.BasicUser = "collector"
	}
	if len(cfg.Sources.ServiceNow.Tables) == 0 {
		cfg.Sources.ServiceNow.Tables = []string{"change_request"}
	}
	if cfg.Sources.ServiceNow.PollInterval == 0 {
		cfg.Sources.ServiceNow.PollInterval = 60 * time.Second
	}
	if cfg.Sources.ServiceNow.PollLookback == 0 {
		cfg.Sources.ServiceNow.PollLookback = 1 * time.Hour
	}
	if cfg.Sources.ServiceNow.CursorPath == "" {
		cfg.Sources.ServiceNow.CursorPath = DataDir + "/servicenow_cursor"
	}
	// ArgoCD defaults.
	if cfg.Sources.ArgoCD.Namespace == "" {
		cfg.Sources.ArgoCD.Namespace = "argocd"
	}
	if cfg.Sources.ArgoCD.PollInterval == 0 {
		cfg.Sources.ArgoCD.PollInterval = 60 * time.Second
	}
	if cfg.Sources.ArgoCD.CursorPath == "" {
		cfg.Sources.ArgoCD.CursorPath = DataDir + "/argocd_cursor"
	}
	if cfg.Metrics.Port == 0 {
		cfg.Metrics.Port = 9090
	}
}

func populateSecrets(cfg *Config) {
	if v := os.Getenv("OPERITAS_INGEST_API_KEY"); v != "" {
		cfg.Ingest.APIKey = v
	}
	if v := os.Getenv("OPERITAS_GITHUB_TOKEN"); v != "" {
		cfg.Sources.GitHub.Token = v
	}
	if v := os.Getenv("OPERITAS_GITHUB_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.GitHub.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_GITLAB_TOKEN"); v != "" {
		cfg.Sources.GitLab.Token = v
	}
	if v := os.Getenv("OPERITAS_GITLAB_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.GitLab.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_AZURE_CLIENT_SECRET"); v != "" {
		cfg.Sources.AzureActivity.ClientSecret = v
	}
	if v := os.Getenv("OPERITAS_PD_SIGNING_SECRET"); v != "" {
		cfg.Sources.PagerDuty.SigningSecret = v
	}
	if v := os.Getenv("OPERITAS_REDACT_HASH_KEY"); v != "" {
		cfg.Redact.HashKey = v
	}
	// New source secrets.
	if v := os.Getenv("OPERITAS_JIRA_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.Jira.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_JIRA_TOKEN"); v != "" {
		cfg.Sources.Jira.Token = v
	}
	if v := os.Getenv("OPERITAS_DATADOG_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.Datadog.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_DATADOG_TOKEN"); v != "" {
		cfg.Sources.Datadog.APIKey = v
	}
	if v := os.Getenv("OPERITAS_DATADOG_APP_KEY"); v != "" {
		cfg.Sources.Datadog.AppKey = v
	}
	if v := os.Getenv("OPERITAS_PROMETHEUS_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.Prometheus.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_BITBUCKET_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.Bitbucket.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_BITBUCKET_TOKEN"); v != "" {
		cfg.Sources.Bitbucket.Token = v
	}
	if v := os.Getenv("OPERITAS_INCIDENTIO_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.IncidentIO.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_INCIDENTIO_TOKEN"); v != "" {
		cfg.Sources.IncidentIO.Token = v
	}
	if v := os.Getenv("OPERITAS_OPSGENIE_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.Opsgenie.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_OPSGENIE_TOKEN"); v != "" {
		cfg.Sources.Opsgenie.Token = v
	}
	if v := os.Getenv("OPERITAS_SERVICENOW_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.ServiceNow.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_SERVICENOW_TOKEN"); v != "" {
		cfg.Sources.ServiceNow.Token = v
	}
	if v := os.Getenv("OPERITAS_ARGOCD_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.ArgoCD.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_ARGOCD_TOKEN"); v != "" {
		cfg.Sources.ArgoCD.Token = v
	}
	if v := os.Getenv("OPERITAS_FLUX_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.Flux.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_SPACELIFT_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.Spacelift.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_GRAFANA_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.Grafana.WebhookSecret = v
	}
}

// euRegions is the set of AWS region names the collector permits for CloudTrail.
// Non-EU regions are rejected at startup to enforce the EU-only data path.
var euRegions = map[string]struct{}{
	"eu-central-1": {},
	"eu-central-2": {},
	"eu-west-1":    {},
	"eu-west-2":    {},
	"eu-west-3":    {},
	"eu-north-1":   {},
	"eu-south-1":   {},
	"eu-south-2":   {},
}

func validate(cfg *Config) error {
	var errs []error

	// eu-residency-1: OPERITAS_ALLOW_NON_EU_ENDPOINT=1 is the explicit operator
	// acknowledgement required to use an endpoint that cannot be automatically
	// verified as EU-resident. Without this flag, an unrecognised host fails
	// closed at startup so misconfiguration is caught before any data is sent.
	allowNonEU := os.Getenv("OPERITAS_ALLOW_NON_EU_ENDPOINT") == "1"

	// checkEUEndpoint enforces fail-closed EU residency for a configurable
	// endpoint. It appends an error when the endpoint is known non-EU, or when
	// it cannot be verified as EU-resident and the operator has not set the
	// explicit acknowledgement flag.
	checkEUEndpoint := func(field, ep string) {
		if ep == "" {
			return
		}
		if isKnownNonEUEndpoint(ep) {
			errs = append(errs, fmt.Errorf("%s %q appears to be a non-EU endpoint; all customer-data paths must be EU-resident", field, ep))
			return
		}
		if !isKnownAcceptableEndpoint(ep) {
			if !allowNonEU {
				errs = append(errs, fmt.Errorf(
					"%s %q cannot be automatically verified as EU-resident; "+
						"confirm the host is EU-provisioned, then set OPERITAS_ALLOW_NON_EU_ENDPOINT=1 to acknowledge",
					field, ep,
				))
			} else {
				slog.Warn("OPERITAS_ALLOW_NON_EU_ENDPOINT=1 — accepting unverified endpoint; confirm it is EU-resident",
					"field", field, "endpoint", ep)
			}
		}
	}

	if cfg.TenantID == "" {
		errs = append(errs, errors.New("tenant_id is required"))
	}
	if cfg.CollectorID == "" {
		errs = append(errs, errors.New("collector_id is required"))
	}

	// Bearer token is mandatory — the ingest API rejects every request without it.
	// Obtain the key from the Operitas portal (https://app.operitas.eu/settings/collectors)
	// and supply it via the OPERITAS_INGEST_API_KEY environment variable.
	if cfg.Ingest.APIKey == "" {
		errs = append(errs, errors.New("OPERITAS_INGEST_API_KEY is required; obtain this from the Operitas portal enrollment flow"))
	}

	// mTLS is mandatory — hard fail if certificates are missing.
	if cfg.Ingest.TLSCertFile == "" {
		errs = append(errs, errors.New("ingest.tls_cert_file is required"))
	}
	if cfg.Ingest.TLSKeyFile == "" {
		errs = append(errs, errors.New("ingest.tls_key_file is required"))
	}
	if cfg.Ingest.TLSCertFile != "" && cfg.Ingest.TLSKeyFile != "" {
		if _, err := tls.LoadX509KeyPair(cfg.Ingest.TLSCertFile, cfg.Ingest.TLSKeyFile); err != nil {
			errs = append(errs, fmt.Errorf("cannot load mTLS key pair: %w", err))
		}
	}

	// Fail-closed EU check for the ingest endpoint. The default (ingest.operitas.eu)
	// is on the EU allowlist; a custom endpoint must be explicitly acknowledged.
	checkEUEndpoint("ingest.endpoint", cfg.Ingest.Endpoint)

	if cfg.Sources.CloudTrail.Enabled {
		if cfg.Sources.CloudTrail.BucketName == "" {
			errs = append(errs, errors.New("sources.cloudtrail.bucket_name is required when cloudtrail is enabled"))
		}
		if _, ok := euRegions[cfg.Sources.CloudTrail.BucketRegion]; !ok {
			errs = append(errs, fmt.Errorf("sources.cloudtrail.bucket_region %q is not an approved EU region", cfg.Sources.CloudTrail.BucketRegion))
		}
	}

	if cfg.Sources.AzureActivity.Enabled {
		if cfg.Sources.AzureActivity.TenantID == "" {
			errs = append(errs, errors.New("sources.azure_activity.tenant_id is required when azure_activity is enabled"))
		}
		if cfg.Sources.AzureActivity.SubscriptionID == "" {
			errs = append(errs, errors.New("sources.azure_activity.subscription_id is required when azure_activity is enabled"))
		}
		// Client secret mode requires ClientID; workload identity mode requires ClientID too.
		// Managed identity (system-assigned) can work without ClientID.
		if !cfg.Sources.AzureActivity.UseWorkloadIdentity &&
			cfg.Sources.AzureActivity.ClientSecret != "" &&
			cfg.Sources.AzureActivity.ClientID == "" {
			errs = append(errs, errors.New("sources.azure_activity.client_id is required when azure_activity client_secret is set"))
		}
		// Never log ClientSecret — validation only checks presence, not value.
	}

	if cfg.Sources.GitHub.Enabled {
		if cfg.Sources.GitHub.Token == "" {
			errs = append(errs, errors.New("OPERITAS_GITHUB_TOKEN is required when github source is enabled"))
		}
	}

	if cfg.Sources.GitLab.Enabled {
		if cfg.Sources.GitLab.Token == "" {
			errs = append(errs, errors.New("OPERITAS_GITLAB_TOKEN is required when gitlab source is enabled"))
		}
		// Fail-closed EU check; gitlab.com is on the acceptable list so the
		// default passes without the flag.
		checkEUEndpoint("sources.gitlab.base_url", cfg.Sources.GitLab.BaseURL)
	}

	if cfg.Sources.PagerDuty.Enabled {
		if cfg.Sources.PagerDuty.SigningSecret == "" {
			errs = append(errs, errors.New("OPERITAS_PD_SIGNING_SECRET is required when pagerduty source is enabled"))
		}
	}

	if cfg.Sources.Jira.Enabled {
		if cfg.Sources.Jira.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_JIRA_WEBHOOK_SECRET is required when jira source is enabled"))
		}
		if cfg.Sources.Jira.BaseURL != "" {
			// Fail-closed EU check; *.atlassian.net is on the acceptable list.
			checkEUEndpoint("sources.jira.base_url", cfg.Sources.Jira.BaseURL)
			if strings.HasSuffix(strings.ToLower(extractHost(cfg.Sources.Jira.BaseURL)), ".atlassian.net") {
				slog.Warn("jira base_url is an Atlassian Cloud host: EU data residency depends on the Atlassian tenant Data Residency setting, not the URL alone; verify your tenant's residency pin at admin.atlassian.com")
			}
		}
	}

	if cfg.Sources.Datadog.Enabled {
		if cfg.Sources.Datadog.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_DATADOG_WEBHOOK_SECRET is required when datadog source is enabled"))
		}
		// The Datadog API base URL has a dedicated deny-list for non-EU Datadog
		// domains in addition to the generic fail-closed guard.
		if isKnownNonEUDatadogEndpoint(cfg.Sources.Datadog.APIBaseURL) {
			errs = append(errs, fmt.Errorf("sources.datadog.api_base_url %q is not an EU Datadog endpoint; use https://api.datadoghq.eu or https://api.eu1.datadoghq.com", cfg.Sources.Datadog.APIBaseURL))
		} else {
			checkEUEndpoint("sources.datadog.api_base_url", cfg.Sources.Datadog.APIBaseURL)
		}
	}

	if cfg.Sources.Prometheus.Enabled {
		scheme := cfg.Sources.Prometheus.AuthScheme
		if scheme != "bearer" && scheme != "basic" && scheme != "none" {
			errs = append(errs, fmt.Errorf("sources.prometheus.auth_scheme %q is invalid; must be bearer, basic, or none", scheme))
		}
		if scheme != "none" && cfg.Sources.Prometheus.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_PROMETHEUS_WEBHOOK_SECRET is required when prometheus source is enabled with auth"))
		}
		if scheme == "none" {
			slog.Warn("prometheus webhook auth_scheme is \"none\": the endpoint accepts unauthenticated requests; use only on a fully isolated network segment")
		}
	}

	if cfg.Sources.Bitbucket.Enabled {
		if cfg.Sources.Bitbucket.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_BITBUCKET_WEBHOOK_SECRET is required when bitbucket source is enabled"))
		}
		// api.bitbucket.org is on the acceptable list (documented ADR-0015 trade-off).
		checkEUEndpoint("sources.bitbucket.base_url", cfg.Sources.Bitbucket.BaseURL)
	}

	if cfg.Sources.IncidentIO.Enabled {
		if cfg.Sources.IncidentIO.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_INCIDENTIO_WEBHOOK_SECRET is required when incident_io source is enabled"))
		}
		// api.incident.io is on the acceptable list (EU-hosted SaaS).
		checkEUEndpoint("sources.incident_io.api_base_url", cfg.Sources.IncidentIO.APIBaseURL)
	}

	if cfg.Sources.Opsgenie.Enabled {
		if cfg.Sources.Opsgenie.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_OPSGENIE_WEBHOOK_SECRET is required when opsgenie source is enabled"))
		}
		if isKnownNonEUOpsgenieEndpoint(cfg.Sources.Opsgenie.APIBaseURL) {
			errs = append(errs, fmt.Errorf("sources.opsgenie.api_base_url %q is not the EU Opsgenie endpoint; use https://api.eu.opsgenie.com/v2", cfg.Sources.Opsgenie.APIBaseURL))
		} else {
			// api.eu.opsgenie.com is on the acceptable list.
			checkEUEndpoint("sources.opsgenie.api_base_url", cfg.Sources.Opsgenie.APIBaseURL)
		}
	}

	if cfg.Sources.ServiceNow.Enabled {
		if cfg.Sources.ServiceNow.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_SERVICENOW_WEBHOOK_SECRET is required when servicenow source is enabled"))
		}
		if cfg.Sources.ServiceNow.BaseURL == "" {
			errs = append(errs, errors.New("sources.servicenow.base_url is required when servicenow source is enabled"))
		} else {
			// *.service-now.com is on the acceptable list; fail-closed for any
			// other custom host. An EU self-hosted instance on a custom domain
			// requires OPERITAS_ALLOW_NON_EU_ENDPOINT=1.
			checkEUEndpoint("sources.servicenow.base_url", cfg.Sources.ServiceNow.BaseURL)
			if strings.HasSuffix(strings.ToLower(extractHost(cfg.Sources.ServiceNow.BaseURL)), ".service-now.com") {
				slog.Warn("servicenow base_url is a ServiceNow Cloud host: EU data residency depends on the ServiceNow instance's Data Center setting; verify your instance is provisioned in an EU data center")
			}
		}
	}

	if cfg.Sources.ArgoCD.Enabled {
		if cfg.Sources.ArgoCD.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_ARGOCD_WEBHOOK_SECRET is required when argocd source is enabled"))
		}
		if cfg.Sources.ArgoCD.BaseURL == "" {
			errs = append(errs, errors.New("sources.argocd.base_url is required when argocd source is enabled"))
		} else {
			// A typical Argo CD instance runs on the customer's EU cluster
			// (e.g. argocd.example.eu). The .eu TLD is on the acceptable list.
			// Custom non-.eu domains require OPERITAS_ALLOW_NON_EU_ENDPOINT=1.
			checkEUEndpoint("sources.argocd.base_url", cfg.Sources.ArgoCD.BaseURL)
		}
	}

	if cfg.Sources.Flux.Enabled {
		if cfg.Sources.Flux.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_FLUX_WEBHOOK_SECRET is required when flux source is enabled"))
		}
	}

	if cfg.Sources.Spacelift.Enabled {
		if cfg.Sources.Spacelift.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_SPACELIFT_WEBHOOK_SECRET is required when spacelift source is enabled"))
		}
	}

	if cfg.Sources.Grafana.Enabled {
		if cfg.Sources.Grafana.WebhookSecret == "" {
			errs = append(errs, errors.New("OPERITAS_GRAFANA_WEBHOOK_SECRET is required when grafana source is enabled"))
		}
	}

	if cfg.Redact.HashPII {
		if cfg.Redact.HashKey == "" {
			errs = append(errs, errors.New("OPERITAS_REDACT_HASH_KEY is required when redact.hash_pii is true"))
		} else if _, err := hex.DecodeString(cfg.Redact.HashKey); err != nil {
			errs = append(errs, errors.New("OPERITAS_REDACT_HASH_KEY must be a valid hex string when redact.hash_pii is true"))
		}
	}

	return errors.Join(errs...)
}

// isKnownNonEUEndpoint returns true if the endpoint URL string contains a
// recognisable non-EU region or domain fragment. This is a deny-list safeguard;
// the Helm NetworkPolicy is the primary enforcement layer. It is not exhaustive
// — operators supplying custom hostnames must use isKnownAcceptableEndpoint to
// vet them, or set OPERITAS_ALLOW_NON_EU_ENDPOINT=1 explicitly.
func isKnownNonEUEndpoint(ep string) bool {
	nonEUFragments := []string{
		// AWS non-EU regions.
		"us-east-", "us-west-", "ap-", "sa-east-", "ca-central-",
		"me-", "af-south-", "il-central-",
		// AWS GovCloud and China regions.
		"us-gov-", "cn-north-", "cn-northwest-",
		// Generic US-region patterns (SaaS and cloud vanity domains).
		".us.", ".us/", ".us:", "-us.", "-us/",
		// Common US-based SaaS region suffixes.
		"us1.", "us2.", "us3.", "us4.", "us5.",
		// Datadog US domains are caught by isKnownNonEUDatadogEndpoint but
		// include here as belt-and-suspenders for the generic guard.
		"datadoghq.com/",
	}
	lower := strings.ToLower(ep)
	for _, frag := range nonEUFragments {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// isKnownAcceptableEndpoint returns true if the endpoint host is on the vetted
// list of EU-resident or explicitly-documented globally-acceptable SaaS/PaaS
// endpoints used by the 16 supported sources.
//
// "Acceptable" does not mean unconditionally EU — it means the endpoint is
// either clearly EU-resident (by TLD or region pattern) or is a global SaaS
// whose non-EU hosting is a documented trade-off (e.g. metadata-only API paths,
// no customer event data stored at rest on the provider side).
//
// Any host that is neither in this list nor caught by isKnownNonEUEndpoint is
// considered unvetted and fails closed at startup unless the operator sets
// OPERITAS_ALLOW_NON_EU_ENDPOINT=1.
func isKnownAcceptableEndpoint(ep string) bool {
	host := strings.ToLower(extractHost(ep))
	if host == "" {
		return false
	}

	// EU TLD: any host whose public suffix is .eu is EU-resident by definition.
	if strings.HasSuffix(host, ".eu") || host == "eu" {
		return true
	}

	// Known global SaaS/PaaS hosts explicitly documented in source package
	// comments. Each entry has a rationale; the slice is ordered for clarity.
	knownHosts := []string{
		// Atlassian Cloud — Jira; EU data residency via tenant Data Residency
		// setting at admin.atlassian.com (startup validation warns about this).
		"atlassian.net",
		// Bitbucket Cloud — documented ADR-0015 trade-off: no EU-specific API
		// endpoint; collector reads metadata only, no event data stored there.
		"api.bitbucket.org",
		// Azure Resource Manager — global control-plane endpoint; EU data
		// residency is enforced by subscription geography, not this endpoint.
		// Only audit log metadata (timestamps, operation names) is fetched.
		"management.azure.com",
		// Azure identity / OIDC token endpoint — no customer data; auth only.
		"login.microsoftonline.com",
		// GitLab SaaS — EU data residency optional; operators with strict
		// requirements should point to a self-hosted EU instance.
		"gitlab.com",
		// incident.io — EU-hosted SaaS by design; documented in package comment.
		"api.incident.io",
		// PagerDuty — no EU-specific REST API endpoint available; global SaaS.
		"api.pagerduty.com",
		// Datadog EU1 REST API endpoints.
		"api.datadoghq.eu",
		"api.eu1.datadoghq.com",
		// Opsgenie EU REST API endpoint.
		"api.eu.opsgenie.com",
	}
	for _, known := range knownHosts {
		if host == known || strings.HasSuffix(host, "."+known) {
			return true
		}
	}

	// ServiceNow Cloud (*.service-now.com) — EU residency depends on the
	// instance Data Center assignment; a startup warning is emitted separately.
	if strings.HasSuffix(host, ".service-now.com") || host == "service-now.com" {
		return true
	}

	return false
}

// isKnownNonEUDatadogEndpoint rejects the US/global Datadog API endpoints.
// Datadog's EU endpoints are api.datadoghq.eu and api.eu1.datadoghq.com.
// All other datadoghq domains are US or global and must be rejected.
func isKnownNonEUDatadogEndpoint(ep string) bool {
	lower := strings.ToLower(ep)
	// Allowed EU endpoints — if we match one of these, it is NOT non-EU.
	euDatadog := []string{
		"api.datadoghq.eu",
		"api.eu1.datadoghq.com",
	}
	for _, eu := range euDatadog {
		if strings.Contains(lower, eu) {
			return false
		}
	}
	// If the URL contains "datadoghq" and is not one of the EU endpoints, reject it.
	return strings.Contains(lower, "datadoghq")
}

// isKnownNonEUOpsgenieEndpoint rejects the global Opsgenie endpoint.
// The EU endpoint is api.eu.opsgenie.com; api.opsgenie.com is global/US.
func isKnownNonEUOpsgenieEndpoint(ep string) bool {
	lower := strings.ToLower(ep)
	// The EU endpoint contains "eu.opsgenie"; the global one is just "api.opsgenie".
	if strings.Contains(lower, "eu.opsgenie") {
		return false
	}
	return strings.Contains(lower, "opsgenie.com")
}

// extractHost returns the hostname from a URL string. Returns the raw string on
// parse failure so callers can still do suffix checks safely.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	// u.Host may include a port (host:port); strip it for hostname comparison.
	host := u.Hostname()
	return host
}
