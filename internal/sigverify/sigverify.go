// Package sigverify provides constant-time HMAC-SHA256 signature verification
// for webhook senders that sign with a hex-encoded MAC and a leading scheme
// prefix (e.g. "sha256=" for GitHub, "v1=" for PagerDuty).
package sigverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// HexHMAC reports whether hexSig is a valid HMAC-SHA256 of body using secret.
// hexSig must be the bare hex string (no scheme prefix). Returns false on any
// decoding error or length mismatch — never panics.
func HexHMAC(secret, body []byte, hexSig string) bool {
	sigBytes, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), sigBytes)
}

// HexHMACPrefixed strips prefix from header and returns true if the remainder
// is a valid hex HMAC-SHA256 of body. Returns false if the prefix is missing.
func HexHMACPrefixed(secret, body []byte, header, prefix string) bool {
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	return HexHMAC(secret, body, header[len(prefix):])
}

// SecretEqual reports whether got equals want in constant time. Use this for
// webhook senders that authenticate with a plain shared secret rather than an
// HMAC signature (e.g. GitLab's X-Gitlab-Token header). Returns false if either
// input is empty so a misconfigured secret cannot accidentally accept any
// request.
func SecretEqual(want, got string) bool {
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}
