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
