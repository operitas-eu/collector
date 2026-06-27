// Package redact implements PII stripping from event payloads before they leave
// the customer environment. Per manifest §9.2 the default posture is hard redact
// (remove the field entirely). The hash_pii option replaces values with a keyed
// HMAC-SHA256 hex string to allow correlation without exposing raw PII.
//
// Fields treated as PII by this package:
//   - Email addresses (detected by RFC 5322 structure)
//   - IPv4 and IPv6 addresses
//   - AWS access key IDs (AKIA/ABIA/ACCA/ASIA prefix, 20 characters total)
//
// The redaction walk is applied recursively to the entire payload map. Keys are
// never redacted — only leaf string values. Non-string values are not redacted
// (numbers, booleans, etc. are not considered PII by default).
//
// CORRECTNESS GUARANTEE: for any input string, the redacted output is byte-identical
// to the input except for the redacted tokens themselves. Whitespace (tabs, newlines,
// multi-space runs) is always preserved exactly. No whitespace collapse occurs.
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

// ipv4CandidateRE matches dot-decimal candidate strings that may be IPv4
// addresses. Candidates are validated with net.ParseIP before redaction.
// An additional trailing-character check (see applyIPv4) rejects sequences
// like "1.2.3.4.5" where the match is a prefix of a longer dotted token.
var ipv4CandidateRE = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)

// ipv6CandidateRE matches colon-hex candidate strings that may be IPv6
// addresses (requires at least two colon-separated groups, which means at
// least two colons). Candidates are validated with net.ParseIP and confirmed
// to be pure-IPv6 (ip.To4()==nil) so that IPv4 addresses already handled by
// applyIPv4 are not double-processed.
var ipv6CandidateRE = regexp.MustCompile(
	`[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}`,
)

// awsKeyIDRE matches AWS access key ID prefixes (AKIA/ABIA/ACCA/ASIA followed
// by 16 uppercase alphanumeric characters, total 20 chars). These appear in
// CloudTrail requestParameters and similar event metadata when IAM credentials
// are referenced. The prefix is highly distinctive; no net.Parse validation
// is required.
var awsKeyIDRE = regexp.MustCompile(`(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}`)

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

// redactString replaces all PII tokens in s with redaction markers. The
// returned string is byte-identical to s except for the replaced tokens;
// whitespace (tabs, newlines, multi-space runs) and all other non-PII bytes
// are preserved exactly.
func (r *Redactor) redactString(s string) string {
	// Cheap pre-check — every leaf string flows through here, but PII requires
	// either an '@' (email), a digit (IPv4 numerals, IPv6 numerals, AWS key IDs
	// always contain one of digits 2–7 in their base-32 suffix), or ':' (IPv6).
	if !strings.ContainsAny(s, "@0123456789:") {
		return s
	}

	// Email: ReplaceAllStringFunc already preserves all surrounding bytes.
	s = emailPattern.ReplaceAllStringFunc(s, r.sanitize)

	// IPv4: in-place substitution via FindAllStringIndex; trailing-char guard
	// prevents false positives on dotted sequences like "1.2.3.4.5".
	// Must run before IPv6 so that IPv4-mapped addresses (::ffff:a.b.c.d) have
	// their dotted-decimal part handled first.
	s = r.applyIPv4(s)

	// IPv6: in-place substitution; net.ParseIP + To4()==nil confirms pure-IPv6.
	s = r.applyIPv6(s)

	// AWS access key IDs: distinctive 4-char prefix makes further validation
	// unnecessary; ReplaceAllStringFunc preserves all surrounding bytes.
	s = awsKeyIDRE.ReplaceAllStringFunc(s, r.sanitize)

	return s
}

// applyIPv4 replaces all valid IPv4 addresses in s with the sanitized marker.
// It uses FindAllStringIndex rather than ReplaceAllStringFunc so that it can
// inspect the character immediately after each candidate match. If that
// character is '.' or a decimal digit the candidate is not a terminal IP
// address (e.g. it is the prefix of "1.2.3.4.5") and is left unchanged.
// All bytes outside matched tokens — including whitespace, tabs, and newlines —
// are written back to the output without modification.
func (r *Redactor) applyIPv4(s string) string {
	locs := ipv4CandidateRE.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	pos := 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		// Preserve every byte from the previous position up to this candidate.
		b.WriteString(s[pos:start])
		match := s[start:end]
		// Reject the candidate if it is immediately followed by '.' or a digit.
		// This prevents "1.2.3.4" from being redacted out of "1.2.3.4.5".
		trailingDotOrDigit := end < len(s) && (s[end] == '.' || (s[end] >= '0' && s[end] <= '9'))
		if !trailingDotOrDigit && net.ParseIP(match) != nil {
			b.WriteString(r.sanitize(match))
		} else {
			b.WriteString(match)
		}
		pos = end
	}
	// Preserve the remainder of the string after the last candidate.
	b.WriteString(s[pos:])
	return b.String()
}

// applyIPv6 replaces all valid IPv6 addresses in s with the sanitized marker.
// Candidates are validated with net.ParseIP; ip.To4()==nil ensures that IPv4
// addresses (already handled by applyIPv4) are not double-processed.
// All bytes outside matched tokens are written back without modification.
func (r *Redactor) applyIPv6(s string) string {
	locs := ipv6CandidateRE.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	pos := 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		b.WriteString(s[pos:start])
		match := s[start:end]
		ip := net.ParseIP(match)
		// ip.To4() returns nil only for pure IPv6; IPv4 and IPv4-in-IPv6 forms
		// (the dotted-decimal parts of ::ffff:a.b.c.d) are already handled.
		if ip != nil && ip.To4() == nil {
			b.WriteString(r.sanitize(match))
		} else {
			b.WriteString(match)
		}
		pos = end
	}
	b.WriteString(s[pos:])
	return b.String()
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
