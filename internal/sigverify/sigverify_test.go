package sigverify_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"operitas.eu/collector/internal/sigverify"
)

func TestHexHMACPrefixed(t *testing.T) {
	secret := []byte("topsecret")
	body := []byte(`{"a":1}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !sigverify.HexHMACPrefixed(secret, body, good, "sha256=") {
		t.Error("valid signature rejected")
	}
	if sigverify.HexHMACPrefixed(secret, body, good, "v1=") {
		t.Error("wrong prefix accepted")
	}
	if sigverify.HexHMACPrefixed(secret, []byte("tampered"), good, "sha256=") {
		t.Error("tampered body accepted")
	}
}

func TestSecretEqual(t *testing.T) {
	tests := []struct {
		name      string
		want, got string
		expect    bool
	}{
		{"match", "abc123", "abc123", true},
		{"mismatch", "abc123", "abc124", false},
		{"empty want", "", "abc123", false},
		{"empty got", "abc123", "", false},
		{"both empty", "", "", false},
		{"length mismatch", "abc", "abcd", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sigverify.SecretEqual(tc.want, tc.got); got != tc.expect {
				t.Errorf("SecretEqual(%q,%q)=%v, want %v", tc.want, tc.got, got, tc.expect)
			}
		})
	}
}
