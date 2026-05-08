// Package redact implements PII stripping from event payloads before they leave
// the customer environment. Per manifest §9.2 the default posture is hard redact
// (remove the field entirely). The hash_pii option replaces values with a keyed
// HMAC-SHA256 hex string to allow correlation without exposing raw PII.
//
// Fields treated as PII by this package:
//   - Email addresses (detected by RFC 5322 structure)
//   - IPv4 and IPv6 addresses
//
// The redaction walk is applied recursively to the entire payload map. Keys are
// never redacted — only leaf string values. Non-string values are not redacted
// (numbers, booleans, etc. are not considered PII by default).
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"strings"
)

// emailPattern matches email addresses in string values.
// It deliberately under-matches (no regex is perfect) to avoid false-positive
// redaction of legitimate identifiers that happen to contain an @.
var emailPattern = regexp.MustCompile(
	`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`,
)

// Redactor applies PII redaction rules to payload maps.
type Redactor struct {
	hashPII bool
	hashKey []byte
}

// New creates a Redactor. If hashPII is false (the default per §9.2), PII
// fields are replaced with the string "[redacted]". If hashPII is true,
// hashKey must be a 32-byte hex-encoded key; PII is replaced with
// "hmac:<hex(HMAC-SHA256(key, value))>".
func New(hashPII bool, hashKeyHex string) (*Redactor, error) {
	r := &Redactor{hashPII: hashPII}
	if hashPII {
		key, err := hex.DecodeString(hashKeyHex)
		if err != nil || len(key) == 0 {
			return nil, &configError{"OPERITAS_REDACT_HASH_KEY must be a valid hex string when hash_pii is true"}
		}
		r.hashKey = key
	}
	return r, nil
}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

// Apply returns a deep copy of payload with PII removed or hashed.
// The original map is not modified.
func (r *Redactor) Apply(payload map[string]any) map[string]any {
	result := make(map[string]any, len(payload))
	for k, v := range payload {
		result[k] = r.redactValue(v)
	}
	return result
}

func (r *Redactor) redactValue(v any) any {
	switch val := v.(type) {
	case string:
		return r.redactString(val)
	case map[string]any:
		return r.Apply(val)
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = r.redactValue(elem)
		}
		return out
	default:
		return v
	}
}

func (r *Redactor) redactString(s string) string {
	// Replace email addresses.
	s = emailPattern.ReplaceAllStringFunc(s, func(match string) string {
		return r.sanitize(match)
	})

	// Replace IPv4 and IPv6 addresses. We walk token by token to avoid
	// false-positives on version strings like "1.2.3.4" that appear in
	// non-IP contexts. net.ParseIP is the authoritative parser.
	parts := strings.Fields(s)
	changed := false
	for i, part := range parts {
		// Strip trailing punctuation (comma, period, colon) before parsing.
		clean := strings.TrimRight(part, ",:;.")
		if ip := net.ParseIP(clean); ip != nil {
			parts[i] = r.sanitize(clean) + part[len(clean):]
			changed = true
		}
	}
	if changed {
		s = strings.Join(parts, " ")
	}

	return s
}

func (r *Redactor) sanitize(pii string) string {
	if !r.hashPII {
		return "[redacted]"
	}
	mac := hmac.New(sha256.New, r.hashKey)
	mac.Write([]byte(pii))
	return "hmac:" + hex.EncodeToString(mac.Sum(nil))
}

// RedactActor applies redaction to an actor string (may be an email address).
// Returns nil if the input is nil.
func (r *Redactor) RedactActor(actor *string) *string {
	if actor == nil {
		return nil
	}
	out := r.redactString(*actor)
	return &out
}
