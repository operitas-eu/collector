// Package awscloudtrail reads CloudTrail log files from a customer-owned S3 bucket
// and converts them to canonical envelope events.
//
// Read-only API calls only:
//   - s3:ListObjectsV2  (list log files by prefix/date)
//   - s3:GetObject      (download a single log file)
//
// The collector never calls s3:PutObject, s3:DeleteObject, or any write variant.
// The IAM policy template in the Helm chart enforces this at the AWS layer too.
//
// CloudTrail logs are written as gzip-compressed JSON files. Each file contains
// a top-level "Records" array. We normalize each record into a canonical event:
//
//   - event_type: derived from eventName (see mapEventType)
//   - event_source: "aws.cloudtrail"
//   - actor: userIdentity.arn (redacted per §9.2 before transmission)
//   - resource: first resource ARN in the records.resources list, or the
//     eventSource + "/" + resourceName
//   - payload: a subset of the CloudTrail record (see normalizeRecord)
package awscloudtrail

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/ptrs"
	"operitas.eu/collector/internal/redact"
	internalrt "operitas.eu/collector/internal/runtime"
)

// Source polls an S3 bucket for CloudTrail log files and emits canonical events.
type Source struct {
	cfg        config.CloudTrailConfig
	s3         *s3.Client
	redact     *redact.Redactor
	emit       func(envelope.Event)
	cursorPath string
	// lastKey is the last S3 object key processed; persisted to cursorPath.
	lastKey string
}

// New constructs a CloudTrail source. It loads AWS credentials from the
// environment (IAM role assumed via IRSA in the Helm chart).
func New(ctx context.Context, cfg config.CloudTrailConfig, r *redact.Redactor, emit func(envelope.Event)) (*Source, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.BucketRegion),
	)
	if err != nil {
		return nil, fmt.Errorf("cloudtrail: load aws config: %w", err)
	}

	s := &Source{
		cfg:        cfg,
		s3:         s3.NewFromConfig(awsCfg),
		redact:     r,
		emit:       emit,
		cursorPath: cfg.CursorPath,
	}
	if data, err := os.ReadFile(s.cursorPath); err == nil {
		s.lastKey = strings.TrimSpace(string(data))
	} else if !os.IsNotExist(err) {
		slog.Warn("cloudtrail: cursor read failed; starting from beginning", "path", s.cursorPath, "err", err)
	}
	return s, nil
}

func (s *Source) writeCursor() {
	if s.cursorPath == "" {
		return
	}
	tmp := s.cursorPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(s.lastKey), 0o600); err != nil {
		slog.Warn("cloudtrail: cursor write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cursorPath); err != nil {
		slog.Warn("cloudtrail: cursor rename failed", "err", err)
	}
}

// Run polls the S3 bucket on the configured interval until ctx is cancelled.
func (s *Source) Run(ctx context.Context) error {
	slog.Info("cloudtrail source started",
		"bucket", s.cfg.BucketName,
		"region", s.cfg.BucketRegion,
		"poll_interval", s.cfg.PollInterval,
	)
	return internalrt.PollLoop(ctx, s.cfg.PollInterval, "cloudtrail", s.poll)
}

func (s *Source) poll(ctx context.Context) error {
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.cfg.BucketName),
		Prefix: aws.String(s.cfg.Prefix),
	}
	// Skip already-seen keys server-side rather than filtering after the fact.
	if s.lastKey != "" {
		input.StartAfter = aws.String(s.lastKey)
	}
	paginator := s3.NewListObjectsV2Paginator(s.s3, input)

	const maxConcurrent = 8

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("cloudtrail: list objects: %w", err)
		}

		var keys []string
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if !strings.HasSuffix(key, ".json.gz") {
				continue
			}
			keys = append(keys, key)
		}

		sem := make(chan struct{}, maxConcurrent)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var maxKey string
		for _, key := range keys {
			wg.Add(1)
			sem <- struct{}{}
			go func(key string) {
				defer wg.Done()
				defer func() { <-sem }()
				if err := s.processObject(ctx, key); err != nil {
					slog.Error("cloudtrail: process object failed", "key", key, "err", err)
					return
				}
				mu.Lock()
				if key > maxKey {
					maxKey = key
				}
				mu.Unlock()
			}(key)
		}
		wg.Wait()
		if maxKey > s.lastKey {
			s.lastKey = maxKey
			s.writeCursor()
		}
	}
	return nil
}

func (s *Source) processObject(ctx context.Context, key string) error {
	// GetObject — read-only S3 call.
	out, err := s.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("get object %q: %w", key, err)
	}
	defer out.Body.Close()

	gz, err := gzip.NewReader(out.Body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	body, err := io.ReadAll(io.LimitReader(gz, 50*1024*1024)) // 50 MB safety limit
	if err != nil {
		return fmt.Errorf("read gzip body: %w", err)
	}

	var logFile cloudTrailLog
	if err := json.Unmarshal(body, &logFile); err != nil {
		return fmt.Errorf("unmarshal cloudtrail log: %w", err)
	}

	slog.Debug("cloudtrail: processing object", "key", key, "record_count", len(logFile.Records))

	for _, rec := range logFile.Records {
		ev, ok := s.normalizeRecord(rec)
		if !ok {
			continue
		}
		s.emit(ev)
	}
	return nil
}

// cloudTrailLog is the top-level structure of a CloudTrail log file.
type cloudTrailLog struct {
	Records []cloudTrailRecord `json:"Records"`
}

// cloudTrailRecord is the minimal set of fields we read from each CloudTrail record.
// We do not unmarshal the full record to avoid binding to the full CloudTrail schema.
type cloudTrailRecord struct {
	EventTime         string         `json:"eventTime"`
	EventName         string         `json:"eventName"`
	EventSource       string         `json:"eventSource"`
	AWSRegion         string         `json:"awsRegion"`
	SourceIPAddress   string         `json:"sourceIPAddress"`
	UserAgent         string         `json:"userAgent"`
	UserIdentity      ctUserIdentity `json:"userIdentity"`
	Resources         []ctResource   `json:"resources"`
	RequestParameters map[string]any `json:"requestParameters"`
	ResponseElements  map[string]any `json:"responseElements"`
	ErrorCode         string         `json:"errorCode"`
	ErrorMessage      string         `json:"errorMessage"`
}

type ctUserIdentity struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	ARN         string `json:"arn"`
	AccountID   string `json:"accountId"`
	UserName    string `json:"userName"`
}

type ctResource struct {
	ARN          string `json:"ARN"`
	AccountID    string `json:"accountId"`
	ResourceType string `json:"type"`
}

func (s *Source) normalizeRecord(rec cloudTrailRecord) (envelope.Event, bool) {
	t, err := time.Parse(time.RFC3339, rec.EventTime)
	if err != nil {
		slog.Warn("cloudtrail: cannot parse eventTime", "eventTime", rec.EventTime)
		return envelope.Event{}, false
	}
	t = t.UTC()

	evType := MapEventType(rec.EventName, rec.EventSource)

	// Actor is the IAM ARN — may contain account IDs but not email PII
	// unless it is a user identity. Apply redaction.
	actorRaw := rec.UserIdentity.ARN
	if actorRaw == "" {
		actorRaw = rec.UserIdentity.UserName
	}
	actorRedacted := s.redact.RedactActor(ptrs.String(actorRaw))

	// Resource: first resource ARN, or synthesized from event source + name.
	var resource *string
	if len(rec.Resources) > 0 && rec.Resources[0].ARN != "" {
		resource = ptrs.String(rec.Resources[0].ARN)
	} else if rec.EventSource != "" {
		resource = ptrs.String(rec.EventSource)
	}

	// Build a minimal payload — omit request/response params to keep size down.
	// Raw requestParameters and responseElements are excluded at INFO per §12.13;
	// they are included in the payload that goes to the encrypted ledger.
	payload := map[string]any{
		"event_name":    rec.EventName,
		"event_source":  rec.EventSource,
		"aws_region":    rec.AWSRegion,
		"error_code":    rec.ErrorCode,
		"error_message": rec.ErrorMessage,
	}

	// Redact PII from the payload before it leaves the customer environment.
	payload = s.redact.Apply(payload)

	return envelope.Event{
		OccurredAt:  t,
		EventType:   evType,
		EventSource: envelope.SourceAWSCloudTrail,
		Actor:       actorRedacted,
		Resource:    resource,
		Payload:     payload,
	}, true
}

// MapEventType converts a CloudTrail eventName + eventSource to a canonical
// event type from manifest §4.5. Unknown events fall back to "change.iac_applied"
// so they are still ingested and visible in the ledger.
// Exported for testing.
func MapEventType(eventName, eventSource string) string {
	name := strings.ToLower(eventName)
	src := strings.ToLower(eventSource)

	// Auth events.
	authEvents := map[string]string{
		"assumerolewithwebidentity": "auth.role_assumed",
		"assumerole":                "auth.role_assumed",
		"getfederationtoken":        "auth.role_assumed",
		"consolelogin":              "auth.privileged_access",
		"enablemfadevice":           "auth.privileged_access",
		"disablemfadevice":          "auth.mfa_failed",
	}
	if t, ok := authEvents[name]; ok {
		return t
	}

	// Deploy-adjacent events.
	deployEvents := map[string]string{
		"createstack":         "deploy.started",
		"updatestack":         "deploy.started",
		"deletestack":         "deploy.started",
		"createchangeset":     "deploy.started",
		"executechangeset":    "deploy.completed",
		"createfunction":      "deploy.completed",
		"updatefunctioncode":  "deploy.completed",
		"publishlayerversion": "deploy.completed",
	}
	if t, ok := deployEvents[name]; ok {
		return t
	}

	// Data events.
	if strings.Contains(src, "s3") && (strings.HasPrefix(name, "get") || strings.HasPrefix(name, "list")) {
		return "data.bulk_access"
	}

	// Default: treat unknown CloudTrail events as change events.
	return "change.iac_applied"
}
