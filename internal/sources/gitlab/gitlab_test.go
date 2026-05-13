package gitlab_test

import (
	"testing"

	"operitas.eu/collector/internal/sources/gitlab"
)

func TestVerifyToken(t *testing.T) {
	tests := []struct {
		name string
		want string
		got  string
		ok   bool
	}{
		{"valid", "shhh", "shhh", true},
		{"mismatch", "shhh", "guess", false},
		{"empty got", "shhh", "", false},
		{"empty want", "", "shhh", false},
		{"length mismatch", "abc", "abcd", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := gitlab.VerifyToken(tc.want, tc.got); got != tc.ok {
				t.Errorf("VerifyToken(%q,%q)=%v want %v", tc.want, tc.got, got, tc.ok)
			}
		})
	}
}
