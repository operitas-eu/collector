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
