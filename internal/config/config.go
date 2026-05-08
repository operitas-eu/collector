// Package config loads and validates the collector's runtime configuration.
// Configuration is read from a YAML file whose path is given by the
// OPERITAS_CONFIG_FILE environment variable (default /var/lib/operitas/config.yaml).
// All persistent state the collector writes lives under /var/lib/operitas/ (manifest §9.2,
// hard failure rule 3).
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath = "/var/lib/operitas/config.yaml"
	DataDir           = "/var/lib/operitas"
	WALDir            = "/var/lib/operitas/wal"

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
	CloudTrail CloudTrailConfig `yaml:"cloudtrail"`
	GitHub     GitHubConfig     `yaml:"github"`
	PagerDuty  PagerDutyConfig  `yaml:"pagerduty"`
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
	if cfg.Sources.GitHub.WebhookPort == 0 {
		cfg.Sources.GitHub.WebhookPort = 8081
	}
	if cfg.Sources.GitHub.PollInterval == 0 {
		cfg.Sources.GitHub.PollInterval = 60 * time.Second
	}
	if cfg.Sources.PagerDuty.WebhookPort == 0 {
		cfg.Sources.PagerDuty.WebhookPort = 8082
	}
	if cfg.Metrics.Port == 0 {
		cfg.Metrics.Port = 9090
	}
}

func populateSecrets(cfg *Config) {
	if v := os.Getenv("OPERITAS_GITHUB_TOKEN"); v != "" {
		cfg.Sources.GitHub.Token = v
	}
	if v := os.Getenv("OPERITAS_GITHUB_WEBHOOK_SECRET"); v != "" {
		cfg.Sources.GitHub.WebhookSecret = v
	}
	if v := os.Getenv("OPERITAS_PD_SIGNING_SECRET"); v != "" {
		cfg.Sources.PagerDuty.SigningSecret = v
	}
	if v := os.Getenv("OPERITAS_REDACT_HASH_KEY"); v != "" {
		cfg.Redact.HashKey = v
	}
}

// euRegions is the set of AWS region names the collector permits for CloudTrail.
// Non-EU regions are rejected at startup to enforce the EU-only data path.
var euRegions = map[string]struct{}{
	"eu-central-1":  {},
	"eu-central-2":  {},
	"eu-west-1":     {},
	"eu-west-2":     {},
	"eu-west-3":     {},
	"eu-north-1":    {},
	"eu-south-1":    {},
	"eu-south-2":    {},
}

func validate(cfg *Config) error {
	var errs []error

	if cfg.TenantID == "" {
		errs = append(errs, errors.New("tenant_id is required"))
	}
	if cfg.CollectorID == "" {
		errs = append(errs, errors.New("collector_id is required"))
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

	// Validate that the configured endpoint does not resolve to a known non-EU
	// region name. This is a best-effort string check; network-level enforcement
	// relies on the NetworkPolicy in the Helm chart.
	if ep := cfg.Ingest.Endpoint; ep != "" {
		if isKnownNonEUEndpoint(ep) {
			errs = append(errs, fmt.Errorf("ingest.endpoint %q appears to be a non-EU endpoint; all customer-data paths must be EU-resident", ep))
		}
	}

	if cfg.Sources.CloudTrail.Enabled {
		if cfg.Sources.CloudTrail.BucketName == "" {
			errs = append(errs, errors.New("sources.cloudtrail.bucket_name is required when cloudtrail is enabled"))
		}
		if _, ok := euRegions[cfg.Sources.CloudTrail.BucketRegion]; !ok {
			errs = append(errs, fmt.Errorf("sources.cloudtrail.bucket_region %q is not an approved EU region", cfg.Sources.CloudTrail.BucketRegion))
		}
	}

	if cfg.Sources.GitHub.Enabled {
		if cfg.Sources.GitHub.Token == "" {
			errs = append(errs, errors.New("OPERITAS_GITHUB_TOKEN is required when github source is enabled"))
		}
	}

	if cfg.Sources.PagerDuty.Enabled {
		if cfg.Sources.PagerDuty.SigningSecret == "" {
			errs = append(errs, errors.New("OPERITAS_PD_SIGNING_SECRET is required when pagerduty source is enabled"))
		}
	}

	if cfg.Redact.HashPII && cfg.Redact.HashKey == "" {
		errs = append(errs, errors.New("OPERITAS_REDACT_HASH_KEY is required when redact.hash_pii is true"))
	}

	return errors.Join(errs...)
}

// isKnownNonEUEndpoint returns true if the endpoint URL string contains a
// recognisable non-EU AWS region name. This is a safeguard, not a firewall;
// the Helm NetworkPolicy is the real enforcement layer.
func isKnownNonEUEndpoint(ep string) bool {
	nonEUFragments := []string{
		"us-east-", "us-west-", "ap-", "sa-east-", "ca-central-",
		"me-", "af-south-", "il-central-",
	}
	lower := strings.ToLower(ep)
	for _, frag := range nonEUFragments {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}
