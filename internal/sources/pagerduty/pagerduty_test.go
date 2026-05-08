package pagerduty_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"operitas.eu/collector/internal/sources/pagerduty"
)

func signPD(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyPDSignature(t *testing.T) {
	secret := []byte("pagerduty-signing-secret")
	body := []byte(`{"messages":[{"event":"incident.triggered","created_at":"2026-05-07T08:14:02Z"}]}`)

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{
			name:   "valid single signature",
			header: signPD(secret, body),
			want:   true,
		},
		{
			name:   "valid in multi-value header",
			header: "v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef," + signPD(secret, body),
			want:   true,
		},
		{
			name:   "all invalid",
			header: "v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			want:   false,
		},
		{
			name:   "empty header",
			header: "",
			want:   false,
		},
		{
			name:   "wrong prefix",
			header: "sha256=" + hex.EncodeToString([]byte("nope")),
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pagerduty.VerifySignature(secret, body, tc.header)
			if got != tc.want {
				t.Errorf("VerifySignature() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMapPDEventType(t *testing.T) {
	tests := []struct {
		pdEvent string
		want    string
		ok      bool
	}{
		{"incident.triggered", "incident.opened", true},
		{"incident.acknowledged", "incident.acknowledged", true},
		{"incident.resolved", "incident.resolved", true},
		{"incident.escalated", "incident.escalated", true},
		{"incident.reopened", "incident.opened", true},
		{"service.updated", "", false},
		{"", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.pdEvent, func(t *testing.T) {
			got, ok := pagerduty.MapEventType(tc.pdEvent)
			if ok != tc.ok {
				t.Errorf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("MapEventType(%q) = %q, want %q", tc.pdEvent, got, tc.want)
			}
		})
	}
}
