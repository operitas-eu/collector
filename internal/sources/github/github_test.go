package github_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"operitas.eu/collector/internal/sources/github"
)

func signBody(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature(t *testing.T) {
	secret := []byte("test-webhook-secret-32-bytes!!")
	payload := []byte(`{"action":"closed","pull_request":{"number":42}}`)

	tests := []struct {
		name      string
		signature string
		want      bool
	}{
		{
			name:      "valid signature",
			signature: signBody(secret, payload),
			want:      true,
		},
		{
			name:      "wrong signature",
			signature: "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			want:      false,
		},
		{
			name:      "missing sha256 prefix",
			signature: hex.EncodeToString([]byte("nope")),
			want:      false,
		},
		{
			name:      "empty signature",
			signature: "",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := github.VerifySignature(secret, payload, tc.signature)
			if got != tc.want {
				t.Errorf("VerifySignature() = %v, want %v", got, tc.want)
			}
		})
	}
}
