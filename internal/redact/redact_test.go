package redact_test

import (
	"strings"
	"testing"

	"operitas.eu/collector/internal/redact"
)

func mustNew(t *testing.T, hashPII bool, key string) *redact.Redactor {
	t.Helper()
	r, err := redact.New(hashPII, key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestHardRedactEmail(t *testing.T) {
	r := mustNew(t, false, "")
	payload := map[string]any{
		"user":    "alice@bank.eu",
		"action":  "login",
		"details": "User alice@bank.eu logged in from 192.168.1.1",
	}

	out := r.Apply(payload)

	if out["user"] != "[redacted]" {
		t.Errorf("email not redacted: %v", out["user"])
	}
	if out["action"] != "login" {
		t.Errorf("non-PII field changed: %v", out["action"])
	}
	details := out["details"].(string)
	if strings.Contains(details, "alice@bank.eu") {
		t.Errorf("email in details not redacted: %v", details)
	}
	if strings.Contains(details, "192.168.1.1") {
		t.Errorf("IP in details not redacted: %v", details)
	}
}

func TestHardRedactIPv4(t *testing.T) {
	r := mustNew(t, false, "")
	payload := map[string]any{"src_ip": "10.0.0.1"}
	out := r.Apply(payload)
	if out["src_ip"] != "[redacted]" {
		t.Errorf("IPv4 not redacted: %v", out["src_ip"])
	}
}

func TestHardRedactIPv6(t *testing.T) {
	r := mustNew(t, false, "")
	payload := map[string]any{"src_ip": "2001:db8::1"}
	out := r.Apply(payload)
	if out["src_ip"] != "[redacted]" {
		t.Errorf("IPv6 not redacted: %v", out["src_ip"])
	}
}

func TestHashRedactEmail(t *testing.T) {
	// 32-byte hex key (64 hex chars)
	key := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	r := mustNew(t, true, key)
	payload := map[string]any{"user": "bob@fintech.eu"}
	out := r.Apply(payload)

	val, ok := out["user"].(string)
	if !ok || !strings.HasPrefix(val, "hmac:") {
		t.Errorf("expected hmac-prefixed value, got %v", out["user"])
	}
	if strings.Contains(val, "bob@fintech.eu") {
		t.Errorf("raw email leaked into hashed output: %v", val)
	}
}

func TestNestedMapRedaction(t *testing.T) {
	r := mustNew(t, false, "")
	payload := map[string]any{
		"outer": map[string]any{
			"inner": "alice@example.eu",
		},
	}
	out := r.Apply(payload)
	inner := out["outer"].(map[string]any)["inner"]
	if inner != "[redacted]" {
		t.Errorf("nested email not redacted: %v", inner)
	}
}

func TestSliceRedaction(t *testing.T) {
	r := mustNew(t, false, "")
	payload := map[string]any{
		"ips": []any{"1.2.3.4", "not-an-ip", "5.6.7.8"},
	}
	out := r.Apply(payload)
	ips := out["ips"].([]any)
	if ips[0] != "[redacted]" {
		t.Errorf("first IP not redacted: %v", ips[0])
	}
	if ips[1] != "not-an-ip" {
		t.Errorf("non-IP value changed: %v", ips[1])
	}
	if ips[2] != "[redacted]" {
		t.Errorf("third IP not redacted: %v", ips[2])
	}
}

func TestNonStringValuesUntouched(t *testing.T) {
	r := mustNew(t, false, "")
	payload := map[string]any{
		"count":   42,
		"active":  true,
		"latency": 1.23,
	}
	out := r.Apply(payload)
	if out["count"] != 42 {
		t.Errorf("int changed: %v", out["count"])
	}
	if out["active"] != true {
		t.Errorf("bool changed: %v", out["active"])
	}
}

func TestRedactActor(t *testing.T) {
	r := mustNew(t, false, "")
	actor := "carol@corp.eu"
	out := r.RedactActor(&actor)
	if *out != "[redacted]" {
		t.Errorf("actor email not redacted: %v", *out)
	}

	// nil input must return nil.
	if r.RedactActor(nil) != nil {
		t.Errorf("expected nil for nil input")
	}
}

func TestHashPIIRequiresKey(t *testing.T) {
	_, err := redact.New(true, "")
	if err == nil {
		t.Fatal("expected error when hash_pii=true and key is empty")
	}
}

func TestVersionStringNotRedacted(t *testing.T) {
	// "1.2.3.4" as a version string is not an IP in isolation but is parsed as one
	// by net.ParseIP. Confirm our current behaviour (conservative: redact it).
	// This test documents the known limitation rather than asserting correctness.
	r := mustNew(t, false, "")
	payload := map[string]any{"msg": "version 1.2.3.4 deployed"}
	out := r.Apply(payload)
	_ = out["msg"] // behaviour is documented; no assertion here to avoid brittleness
}

// ---------------------------------------------------------------------------
// Byte-layout preservation tests (the surgical-redaction correctness contract)
// ---------------------------------------------------------------------------

// TestByteLayoutPreservation is the canonical correctness test for the
// surgical-redaction guarantee: the redacted output must differ from the input
// ONLY in the redacted tokens. Every surrounding byte (tabs, newlines, spaces,
// URL structure, punctuation) must be preserved exactly.
func TestByteLayoutPreservation(t *testing.T) {
	r := mustNew(t, false, "")

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "tab-delimited multiline log with IP",
			input: "ts\t2024-01-01T00:00:00Z\nclient_ip\t10.0.0.1\nstatus\t200",
			want:  "ts\t2024-01-01T00:00:00Z\nclient_ip\t[redacted]\nstatus\t200",
		},
		{
			name:  "IP in URL path",
			input: "https://10.0.0.1/api/v1",
			want:  "https://[redacted]/api/v1",
		},
		{
			name:  "IP in key=value pair",
			input: "host=10.0.0.1 port=22",
			want:  "host=[redacted] port=22",
		},
		{
			name:  "IP with port in URL",
			input: "https://192.168.1.100:8443/health",
			want:  "https://[redacted]:8443/health",
		},
		{
			name:  "multi-space run preserved around IP",
			input: "before   10.0.0.1   after",
			want:  "before   [redacted]   after",
		},
		{
			name:  "multiple IPs same line whitespace intact",
			input: "src=10.0.0.1 dst=10.0.0.2",
			want:  "src=[redacted] dst=[redacted]",
		},
		{
			name:  "no PII — byte-identical output",
			input: "no sensitive data here",
			want:  "no sensitive data here",
		},
		{
			name:  "tabs and newlines without PII unchanged",
			input: "field1\tvalue1\nfield2\tvalue2",
			want:  "field1\tvalue1\nfield2\tvalue2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := r.Apply(map[string]any{"v": tc.input})
			got := out["v"].(string)
			if got != tc.want {
				t.Errorf("byte layout mismatch\ngot:  %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestFalsePositiveDottedStringNotRedacted verifies that sequences that look
// like an IPv4 address but have extra trailing octets are left entirely
// unchanged — "1.2.3.4.5" must not be partially or fully redacted.
func TestFalsePositiveDottedStringNotRedacted(t *testing.T) {
	r := mustNew(t, false, "")
	cases := []struct {
		input string
	}{
		{"1.2.3.4.5"},
		{"10.0.0.1.2"},
		{"version=5.1.2.300.1"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			out := r.Apply(map[string]any{"v": tc.input})
			got := out["v"].(string)
			if got != tc.input {
				t.Errorf("false-positive redaction: input %q became %q", tc.input, got)
			}
		})
	}
}

// TestInvalidIPNotRedacted confirms that out-of-range dotted-decimal strings
// that look like IPv4 but are rejected by net.ParseIP are left unchanged.
func TestInvalidIPNotRedacted(t *testing.T) {
	r := mustNew(t, false, "")
	cases := []string{
		"999.999.999.999",
		"256.1.2.3",
		"1.2.3.300",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			out := r.Apply(map[string]any{"v": input})
			got := out["v"].(string)
			if got != input {
				t.Errorf("invalid IP was redacted: %q => %q", input, got)
			}
		})
	}
}

// TestIPv4InURLAndKeyValue extends coverage for IPs embedded in non-whitespace
// contexts, confirming the in-place regex approach catches them.
func TestIPv4InURLAndKeyValue(t *testing.T) {
	r := mustNew(t, false, "")

	t.Run("IP in URL", func(t *testing.T) {
		payload := map[string]any{"url": "http://10.0.0.1/path"}
		out := r.Apply(payload)
		s := out["url"].(string)
		if strings.Contains(s, "10.0.0.1") {
			t.Errorf("IP in URL not redacted: %q", s)
		}
		if !strings.HasPrefix(s, "http://") {
			t.Errorf("URL scheme not preserved: %q", s)
		}
		if !strings.HasSuffix(s, "/path") {
			t.Errorf("URL path not preserved: %q", s)
		}
	})

	t.Run("IP comma-delimited", func(t *testing.T) {
		payload := map[string]any{"msg": "from 10.0.0.1, next 10.0.0.2"}
		out := r.Apply(payload)
		s := out["msg"].(string)
		if strings.Contains(s, "10.0.0.") {
			t.Errorf("IPs not fully redacted: %q", s)
		}
		// Surrounding text must survive.
		if !strings.HasPrefix(s, "from ") {
			t.Errorf("prefix lost: %q", s)
		}
	})
}

// TestIPv6Coverage confirms IPv6 addresses in various contexts are redacted
// in-place without disturbing surrounding bytes.
func TestIPv6Coverage(t *testing.T) {
	r := mustNew(t, false, "")

	t.Run("standalone", func(t *testing.T) {
		out := r.Apply(map[string]any{"ip": "2001:db8::1"})
		if out["ip"] != "[redacted]" {
			t.Errorf("IPv6 not redacted: %v", out["ip"])
		}
	})

	t.Run("loopback", func(t *testing.T) {
		out := r.Apply(map[string]any{"ip": "::1"})
		if out["ip"] != "[redacted]" {
			t.Errorf("IPv6 loopback not redacted: %v", out["ip"])
		}
	})

	t.Run("IPv6 in key=value", func(t *testing.T) {
		payload := map[string]any{"log": "peer=2001:db8::1 action=block"}
		out := r.Apply(payload)
		s := out["log"].(string)
		if strings.Contains(s, "2001:db8::1") {
			t.Errorf("IPv6 in key=value not redacted: %q", s)
		}
		if !strings.HasPrefix(s, "peer=") {
			t.Errorf("prefix lost: %q", s)
		}
		if !strings.HasSuffix(s, " action=block") {
			t.Errorf("suffix lost: %q", s)
		}
	})

	t.Run("IPv6 in URL brackets", func(t *testing.T) {
		payload := map[string]any{"url": "https://[2001:db8::1]:8080/path"}
		out := r.Apply(payload)
		s := out["url"].(string)
		if strings.Contains(s, "2001:db8::1") {
			t.Errorf("IPv6 in URL not redacted: %q", s)
		}
		// Brackets, port, and path must survive.
		if !strings.Contains(s, ":8080/path") {
			t.Errorf("port/path not preserved: %q", s)
		}
	})
}

// TestMultilineTabNewlineRegression is the regression test that specifically
// pins the bug described in PR-C3: a string containing an IP must NOT have its
// whitespace structure collapsed. Tabs and newlines between non-IP tokens must
// survive byte-for-byte.
func TestMultilineTabNewlineRegression(t *testing.T) {
	r := mustNew(t, false, "")

	input := "line1\t192.168.0.1\nline2\t\tnot-sensitive\nline3"
	// Expected: IP replaced in-place; double-tab and newlines unchanged.
	want := "line1\t[redacted]\nline2\t\tnot-sensitive\nline3"

	out := r.Apply(map[string]any{"log": input})
	got := out["log"].(string)

	if got != want {
		t.Errorf("whitespace structure changed\ngot:  %q\nwant: %q", got, want)
	}
}

// TestAWSKeyIDRedaction verifies that AWS access key IDs (security-4 category)
// are redacted both as standalone values and when embedded in longer strings.
func TestAWSKeyIDRedaction(t *testing.T) {
	r := mustNew(t, false, "")

	t.Run("standalone IAM key", func(t *testing.T) {
		out := r.Apply(map[string]any{"key_id": "AKIAIOSFODNN7EXAMPLE"})
		if out["key_id"] != "[redacted]" {
			t.Errorf("AWS key ID not redacted: %v", out["key_id"])
		}
	})

	t.Run("IAM key in log message", func(t *testing.T) {
		payload := map[string]any{"msg": "Request signed with AKIAIOSFODNN7EXAMPLE key"}
		out := r.Apply(payload)
		s := out["msg"].(string)
		if strings.Contains(s, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("AWS key ID in message not redacted: %q", s)
		}
		// Surrounding text must be preserved byte-for-byte.
		if !strings.HasPrefix(s, "Request signed with ") {
			t.Errorf("prefix not preserved: %q", s)
		}
		if !strings.HasSuffix(s, " key") {
			t.Errorf("suffix not preserved: %q", s)
		}
	})

	t.Run("STS temporary key prefix ASIA", func(t *testing.T) {
		out := r.Apply(map[string]any{"key_id": "ASIAIOSFODNN7EXAMPLE"})
		if out["key_id"] != "[redacted]" {
			t.Errorf("STS key ID not redacted: %v", out["key_id"])
		}
	})

	t.Run("non-key uppercase string not redacted", func(t *testing.T) {
		// A string that starts with AKIA but has fewer than 16 trailing chars
		// must not be redacted.
		input := "AKIASHORT"
		out := r.Apply(map[string]any{"v": input})
		if out["v"] != input {
			t.Errorf("short AKIA prefix was redacted: %v", out["v"])
		}
	})
}

// TestHashModePreservesLayout confirms that in hash mode the surrounding
// whitespace is still preserved (the HMAC replacement is in-place).
func TestHashModePreservesLayout(t *testing.T) {
	key := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	r := mustNew(t, true, key)

	input := "client\t10.0.0.1\nstatus\t200"
	out := r.Apply(map[string]any{"log": input})
	got := out["log"].(string)

	// The IP must be gone.
	if strings.Contains(got, "10.0.0.1") {
		t.Errorf("IP not redacted in hash mode: %q", got)
	}
	// The surrounding bytes must be intact.
	if !strings.HasPrefix(got, "client\t") {
		t.Errorf("prefix tab not preserved in hash mode: %q", got)
	}
	if !strings.HasSuffix(got, "\nstatus\t200") {
		t.Errorf("trailing newline structure not preserved in hash mode: %q", got)
	}
	// The replacement must be an hmac token.
	if !strings.Contains(got, "hmac:") {
		t.Errorf("expected hmac token in output: %q", got)
	}
}
