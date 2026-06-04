package jira_test

import (
	"testing"

	"operitas.eu/collector/internal/sources/jira"
)

func TestMapIssueEventType(t *testing.T) {
	tests := []struct {
		statusName    string
		issueTypeName string
		want          string
	}{
		{"Done", "Story", "change.approved"},
		{"Closed", "Bug", "change.approved"},
		{"Resolved", "Task", "change.approved"},
		{"In Progress", "Story", "change.opened"},
		{"In Review", "Story", "change.opened"},
		{"Open", "Bug", "change.opened"},
		{"To Do", "Story", "change.opened"},
		{"Backlog", "Epic", "change.opened"},
		{"Deploy to Staging", "Story", "deploy.started"},
		{"Released", "Story", "deploy.completed"},
		{"Custom Status", "Task", "change.approved"},
	}

	for _, tc := range tests {
		t.Run(tc.statusName, func(t *testing.T) {
			got := jira.MapIssueEventType(tc.statusName, tc.issueTypeName)
			if got != tc.want {
				t.Errorf("MapIssueEventType(%q, %q) = %q, want %q",
					tc.statusName, tc.issueTypeName, got, tc.want)
			}
		})
	}
}

func TestMapWebhookEventType(t *testing.T) {
	tests := []struct {
		webhookEvent string
		wantType     string
		wantOK       bool
	}{
		{"jira:issue_created", "change.opened", true},
		{"jira:issue_deleted", "change.closed", true},
		{"jira:version_released", "deploy.completed", true},
		{"jira:version_created", "deploy.started", true},
		{"jira:issue_updated", "change.approved", true},
		{"unknown_event", "", false},
		{"sprint_started", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.webhookEvent, func(t *testing.T) {
			got, ok := jira.MapWebhookEventType(tc.webhookEvent, nil)
			if ok != tc.wantOK {
				t.Errorf("MapWebhookEventType(%q) ok=%v, want ok=%v", tc.webhookEvent, ok, tc.wantOK)
			}
			if ok && got != tc.wantType {
				t.Errorf("MapWebhookEventType(%q) = %q, want %q", tc.webhookEvent, got, tc.wantType)
			}
		})
	}
}

func TestVerifyWebhookSecret(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		authHeader string
		want       bool
	}{
		{"valid bearer", "mysecret", "Bearer mysecret", true},
		{"wrong secret", "mysecret", "Bearer wrongsecret", false},
		{"empty secret rejects", "mysecret", "Bearer ", false},
		{"empty both rejects", "", "", false},
		{"no bearer prefix", "mysecret", "mysecret", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := jira.VerifyWebhookSecret(tc.secret, tc.authHeader)
			if got != tc.want {
				t.Errorf("VerifyWebhookSecret(%q, %q) = %v, want %v",
					tc.secret, tc.authHeader, got, tc.want)
			}
		})
	}
}
