package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"operitas.eu/collector/internal/config"
)

// writeMinimalConfig writes a config YAML to a temp file with the given
// content appended to a minimal base. It returns the file path.
// TLS cert and key paths point to /nonexistent so the key-pair load always
// fails; tests that call Load() will always get a validation error. What
// varies across tests is whether OPERITAS_INGEST_API_KEY appears in that error.
func writeMinimalConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "tenant_id: \"aaaaaaaa-0000-0000-0000-000000000001\"\n" +
		"collector_id: \"bbbbbbbb-0000-0000-0000-000000000001\"\n" +
		"ingest:\n" +
		"  tls_cert_file: \"/nonexistent/tls.crt\"\n" +
		"  tls_key_file:  \"/nonexistent/tls.key\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestStartupFailsWithoutAPIKey verifies that config.Load returns an error
// when OPERITAS_INGEST_API_KEY is not set, and that the error message guides
// the operator to the portal enrollment flow.
func TestStartupFailsWithoutAPIKey(t *testing.T) {
	t.Setenv("OPERITAS_INGEST_API_KEY", "")
	path := writeMinimalConfig(t)

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when OPERITAS_INGEST_API_KEY is empty, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "OPERITAS_INGEST_API_KEY") {
		t.Errorf("error message does not mention OPERITAS_INGEST_API_KEY: %q", msg)
	}
	if !strings.Contains(msg, "portal") {
		t.Errorf("error message does not point to the portal enrollment flow: %q", msg)
	}
	t.Logf("config validation error (expected): %v", err)
}

// TestAPIKeyPopulatedFromEnv verifies that OPERITAS_INGEST_API_KEY is consumed
// by populateSecrets. When a non-empty key is set, the error set must NOT
// contain the "OPERITAS_INGEST_API_KEY is required" message (even though Load
// still errors on the missing TLS cert/key).
func TestAPIKeyPopulatedFromEnv(t *testing.T) {
	t.Setenv("OPERITAS_INGEST_API_KEY", "testid0000000000.dGVzdHNlY3JldA")
	path := writeMinimalConfig(t)

	_, err := config.Load(path)
	// We expect an error here because the TLS cert/key files do not exist.
	// But the error must NOT complain about a missing API key.
	if err == nil {
		// Unexpectedly succeeded — fine, key was accepted.
		return
	}
	if strings.Contains(err.Error(), "OPERITAS_INGEST_API_KEY is required") {
		t.Errorf("API key was set in env but config still reports it missing: %v", err)
	}
}

// TestGitLabRequiresToken verifies that enabling the gitlab source without
// OPERITAS_GITLAB_TOKEN produces a guidance error pointing at that env var.
func TestGitLabRequiresToken(t *testing.T) {
	t.Setenv("OPERITAS_INGEST_API_KEY", "testid0000000000.dGVzdA")
	t.Setenv("OPERITAS_GITLAB_TOKEN", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "tenant_id: \"aaaaaaaa-0000-0000-0000-000000000001\"\n" +
		"collector_id: \"bbbbbbbb-0000-0000-0000-000000000001\"\n" +
		"ingest:\n" +
		"  tls_cert_file: \"/nonexistent/tls.crt\"\n" +
		"  tls_key_file:  \"/nonexistent/tls.key\"\n" +
		"sources:\n" +
		"  gitlab:\n" +
		"    enabled: true\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error when gitlab is enabled without a token")
	}
	if !strings.Contains(err.Error(), "OPERITAS_GITLAB_TOKEN") {
		t.Errorf("error does not mention OPERITAS_GITLAB_TOKEN: %v", err)
	}
}

// TestGitLabRejectsNonEUBaseURL verifies the non-EU heuristic fires for the
// gitlab source's base URL when an obvious US-region fragment is present.
func TestGitLabRejectsNonEUBaseURL(t *testing.T) {
	t.Setenv("OPERITAS_INGEST_API_KEY", "testid0000000000.dGVzdA")
	t.Setenv("OPERITAS_GITLAB_TOKEN", "glpat-x")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "tenant_id: \"aaaaaaaa-0000-0000-0000-000000000001\"\n" +
		"collector_id: \"bbbbbbbb-0000-0000-0000-000000000001\"\n" +
		"ingest:\n" +
		"  tls_cert_file: \"/nonexistent/tls.crt\"\n" +
		"  tls_key_file:  \"/nonexistent/tls.key\"\n" +
		"sources:\n" +
		"  gitlab:\n" +
		"    enabled: true\n" +
		"    base_url: \"https://gitlab.us-east-1.example.com/api/v4\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for non-EU gitlab base_url")
	}
	if !strings.Contains(err.Error(), "non-EU") {
		t.Errorf("error does not mention non-EU: %v", err)
	}
}

// TestRedactHashKeyValidHexPassesStartup verifies that a valid hex key with
// hash_pii=true does not produce a redact-related validation error.
func TestRedactHashKeyValidHexPassesStartup(t *testing.T) {
	t.Setenv("OPERITAS_INGEST_API_KEY", "testid0000000000.dGVzdA")
	// 32-byte key expressed as 64 hex characters.
	t.Setenv("OPERITAS_REDACT_HASH_KEY", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "tenant_id: \"aaaaaaaa-0000-0000-0000-000000000001\"\n" +
		"collector_id: \"bbbbbbbb-0000-0000-0000-000000000001\"\n" +
		"ingest:\n" +
		"  tls_cert_file: \"/nonexistent/tls.crt\"\n" +
		"  tls_key_file:  \"/nonexistent/tls.key\"\n" +
		"redact:\n" +
		"  hash_pii: true\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	// Load may still error (missing TLS files), but it must NOT mention the
	// hash key — that means the hex was accepted at the validation layer.
	if err != nil && strings.Contains(err.Error(), "OPERITAS_REDACT_HASH_KEY") {
		t.Errorf("valid hex key triggered a redact validation error: %v", err)
	}
}

// TestRedactHashKeyBadHexFailsStartup verifies that an invalid hex key with
// hash_pii=true causes config.Load to return a non-empty error that names the
// env var. A missing key must also fail.
func TestRedactHashKeyBadHexFailsStartup(t *testing.T) {
	t.Setenv("OPERITAS_INGEST_API_KEY", "testid0000000000.dGVzdA")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "tenant_id: \"aaaaaaaa-0000-0000-0000-000000000001\"\n" +
		"collector_id: \"bbbbbbbb-0000-0000-0000-000000000001\"\n" +
		"ingest:\n" +
		"  tls_cert_file: \"/nonexistent/tls.crt\"\n" +
		"  tls_key_file:  \"/nonexistent/tls.key\"\n" +
		"redact:\n" +
		"  hash_pii: true\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("missing_key", func(t *testing.T) {
		t.Setenv("OPERITAS_REDACT_HASH_KEY", "")
		_, err := config.Load(path)
		if err == nil {
			t.Fatal("expected error when hash_pii=true and key is missing, got nil")
		}
		if !strings.Contains(err.Error(), "OPERITAS_REDACT_HASH_KEY") {
			t.Errorf("error does not name OPERITAS_REDACT_HASH_KEY: %v", err)
		}
	})

	t.Run("bad_hex", func(t *testing.T) {
		t.Setenv("OPERITAS_REDACT_HASH_KEY", "not-valid-hex!!")
		_, err := config.Load(path)
		if err == nil {
			t.Fatal("expected error when hash_pii=true and key is invalid hex, got nil")
		}
		if !strings.Contains(err.Error(), "OPERITAS_REDACT_HASH_KEY") {
			t.Errorf("error does not name OPERITAS_REDACT_HASH_KEY: %v", err)
		}
	})
}

// TestUnknownEndpointFailsClosedWithoutFlag verifies that an unrecognised host
// (neither in the non-EU deny-list nor in the known-acceptable allowlist) causes
// config.Load to fail when OPERITAS_ALLOW_NON_EU_ENDPOINT is not set.
// This is the eu-residency-1 fail-closed requirement.
func TestUnknownEndpointFailsClosedWithoutFlag(t *testing.T) {
	t.Setenv("OPERITAS_INGEST_API_KEY", "testid0000000000.dGVzdA")
	t.Setenv("OPERITAS_GITLAB_TOKEN", "glpat-x")
	t.Setenv("OPERITAS_ALLOW_NON_EU_ENDPOINT", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Use a custom ArgoCD base_url with a host that is not on any allowlist and
	// is not recognisably non-EU either — an "unknown" vanity domain.
	content := "tenant_id: \"aaaaaaaa-0000-0000-0000-000000000001\"\n" +
		"collector_id: \"bbbbbbbb-0000-0000-0000-000000000001\"\n" +
		"ingest:\n" +
		"  tls_cert_file: \"/nonexistent/tls.crt\"\n" +
		"  tls_key_file:  \"/nonexistent/tls.key\"\n" +
		"sources:\n" +
		"  argocd:\n" +
		"    enabled: true\n" +
		"    base_url: \"https://argocd.internal.example.com\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPERITAS_ARGOCD_WEBHOOK_SECRET", "secret")
	t.Setenv("OPERITAS_ARGOCD_TOKEN", "token")

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for unrecognised non-EU endpoint without OPERITAS_ALLOW_NON_EU_ENDPOINT=1, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be automatically verified as EU-resident") {
		t.Errorf("error should mention EU-residency verification failure; got: %v", err)
	}
}

// TestUnknownEndpointPassesWithAcknowledgementFlag verifies that setting
// OPERITAS_ALLOW_NON_EU_ENDPOINT=1 allows an unrecognised host through the
// fail-closed check. The error from config.Load is expected to mention the TLS
// cert (not the EU check) since the TLS file doesn't exist.
func TestUnknownEndpointPassesWithAcknowledgementFlag(t *testing.T) {
	t.Setenv("OPERITAS_INGEST_API_KEY", "testid0000000000.dGVzdA")
	t.Setenv("OPERITAS_ALLOW_NON_EU_ENDPOINT", "1")
	t.Setenv("OPERITAS_ARGOCD_WEBHOOK_SECRET", "secret")
	t.Setenv("OPERITAS_ARGOCD_TOKEN", "token")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "tenant_id: \"aaaaaaaa-0000-0000-0000-000000000001\"\n" +
		"collector_id: \"bbbbbbbb-0000-0000-0000-000000000001\"\n" +
		"ingest:\n" +
		"  tls_cert_file: \"/nonexistent/tls.crt\"\n" +
		"  tls_key_file:  \"/nonexistent/tls.key\"\n" +
		"sources:\n" +
		"  argocd:\n" +
		"    enabled: true\n" +
		"    base_url: \"https://argocd.internal.example.com\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := config.Load(path)
	// Load may still error on the TLS cert/key (non-existent), but it must NOT
	// mention "cannot be automatically verified as EU-resident".
	if err != nil && strings.Contains(err.Error(), "cannot be automatically verified as EU-resident") {
		t.Errorf("OPERITAS_ALLOW_NON_EU_ENDPOINT=1 should suppress the EU-residency error; got: %v", err)
	}
}

// TestKnownEUEndpointsPassWithoutFlag verifies that the 16 supported sources'
// default EU endpoints do not require OPERITAS_ALLOW_NON_EU_ENDPOINT=1.
// Each is on the known-acceptable list in isKnownAcceptableEndpoint.
func TestKnownEUEndpointsPassWithoutFlag(t *testing.T) {
	t.Setenv("OPERITAS_ALLOW_NON_EU_ENDPOINT", "")

	endpoints := []struct {
		name    string
		host    string
		wantErr bool // true if the host itself should trigger an EU error
	}{
		{"operitas-ingest", "https://ingest.operitas.eu/v1/events:batch", false},
		{"datadog-eu", "https://api.datadoghq.eu", false},
		{"datadog-eu1", "https://api.eu1.datadoghq.com", false},
		{"opsgenie-eu", "https://api.eu.opsgenie.com/v2", false},
		{"incidentio", "https://api.incident.io/v2", false},
		{"gitlab-saas", "https://gitlab.com/api/v4", false},
		{"atlassian-net", "https://mycompany.atlassian.net", false},
		{"service-now", "https://myinstance.service-now.com", false},
		{"bitbucket-cloud", "https://api.bitbucket.org/2.0", false},
		{"custom-eu-host", "https://argocd.example.eu", false},
	}
	for _, tc := range endpoints {
		t.Run(tc.name, func(t *testing.T) {
			got := config.IsKnownAcceptableEndpointForTest(tc.host)
			nonEU := config.IsKnownNonEUEndpointForTest(tc.host)
			// The endpoint must be on the acceptable list OR not on the non-EU list.
			if nonEU {
				t.Errorf("endpoint %q incorrectly flagged as non-EU", tc.host)
			}
			if !got && !tc.wantErr {
				t.Errorf("endpoint %q should be on the known-acceptable list", tc.host)
			}
		})
	}
}

// TestNewNonEUDenyListPatterns verifies every new deny-list fragment added in
// PR-C2 is correctly detected as non-EU. These patterns are new and were not
// covered by the earlier TestKnownEUEndpointsPassWithoutFlag test.
// IsKnownNonEUEndpointForTest is defined in export_test.go.
func TestNewNonEUDenyListPatterns(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool // true means the host must be rejected as non-EU
	}{
		// US GovCloud fragments
		{"us-gov prefix", "https://s3.us-gov-west-1.amazonaws.com/bucket", true},
		{"us-gov-east", "https://sts.us-gov-east-1.amazonaws.com", true},

		// China region fragments
		{"cn-north", "https://s3.cn-north-1.amazonaws.com.cn/bucket", true},
		{"cn-northwest", "https://s3.cn-northwest-1.amazonaws.com.cn/bucket", true},

		// .us. / .us: / .us/ dot-separated fragments
		{"dot-us-dot", "https://ingest.us.example.com/events", true},
		{"dot-us-slash", "https://ingest.us/events", true},
		{"dot-us-colon", "https://ingest.us:8443/events", true},

		// -us. / -us/ dash-separated fragments
		{"dash-us-dot", "https://api-us.example.com/v1", true},
		{"dash-us-slash", "https://api-us/events", true},

		// us1.–us5. numeric regional variants
		{"us1 prefix", "https://us1.example.com/api", true},
		{"us2 prefix", "https://us2.example.com/api", true},
		{"us3 prefix", "https://us3.example.com/api", true},
		{"us4 prefix", "https://us4.example.com/api", true},
		{"us5 prefix", "https://us5.example.com/api", true},

		// Datadog US guard (datadoghq.com without .eu or eu1. prefix)
		{"datadoghq-us", "https://api.datadoghq.com/api/v1", true},
		{"datadoghq-us-subdomain", "https://app.datadoghq.com/logs", true},

		// Negative cases — these must NOT be flagged as non-EU
		{"eu-tld fine", "https://argocd.example.eu", false},
		{"datadoghq-eu fine", "https://api.datadoghq.eu", false},
		{"datadoghq-eu1 fine", "https://api.eu1.datadoghq.com", false},
		{"atlassian-net fine", "https://company.atlassian.net", false},
		{"us in path only", "https://api.example.com/api/us/events", false},
		{"username fine", "https://api.example.eu/api", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := config.IsKnownNonEUEndpointForTest(tc.host)
			if got != tc.want {
				t.Errorf("IsKnownNonEUEndpoint(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// TestAPIKeyNeverAppearsInValidationError ensures that the raw key value is
// never echoed back in any error string. The validation only checks for
// presence, not format, so there is no format-error path that could leak the
// value — but we document and enforce this explicitly.
func TestAPIKeyNeverAppearsInValidationError(t *testing.T) {
	const sentinelKey = "leak-detector-key-abc123"
	t.Setenv("OPERITAS_INGEST_API_KEY", sentinelKey)
	path := writeMinimalConfig(t)

	_, err := config.Load(path)
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), sentinelKey) {
		t.Errorf("API key value leaked into error message: %v", err)
	}
}
