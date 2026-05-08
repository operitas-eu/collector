package awscloudtrail_test

import (
	"testing"

	"operitas.eu/collector/internal/sources/awscloudtrail"
)

// mapEventType is package-private; we test the normalizeRecord behaviour
// by exercising the exported Run path. For unit tests we test the mapping
// logic via the internal test package below.

func TestMapEventType(t *testing.T) {
	tests := []struct {
		name      string
		eventName string
		source    string
		want      string
	}{
		{"assume role", "AssumeRole", "sts.amazonaws.com", "auth.role_assumed"},
		{"console login", "ConsoleLogin", "signin.amazonaws.com", "auth.privileged_access"},
		{"disable MFA", "DisableMFADevice", "iam.amazonaws.com", "auth.mfa_failed"},
		{"cloudformation create", "CreateStack", "cloudformation.amazonaws.com", "deploy.started"},
		{"lambda deploy", "UpdateFunctionCode", "lambda.amazonaws.com", "deploy.completed"},
		{"execute change set", "ExecuteChangeSet", "cloudformation.amazonaws.com", "deploy.completed"},
		{"s3 get", "GetObject", "s3.amazonaws.com", "data.bulk_access"},
		{"unknown", "DescribeInstances", "ec2.amazonaws.com", "change.iac_applied"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := awscloudtrail.MapEventType(tc.eventName, tc.source)
			if got != tc.want {
				t.Errorf("MapEventType(%q, %q) = %q, want %q", tc.eventName, tc.source, got, tc.want)
			}
		})
	}
}
