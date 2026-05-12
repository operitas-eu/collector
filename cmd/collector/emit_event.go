package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/transport"
)

// emitEventFlags holds the parsed CLI flags for --emit-event mode.
type emitEventFlags struct {
	tenantID    string
	eventType   string
	eventSource string
	actor       string
	resource    string
	payloadFile string
}

// parseEmitEventFlags registers --emit-event sub-flags on fs and returns a
// pointer to the populated struct. Call after flag.Parse() has been called on
// the top-level FlagSet so that the values are populated.
func parseEmitEventFlags(fs *flag.FlagSet, args []string) (*emitEventFlags, error) {
	f := &emitEventFlags{}
	fs.StringVar(&f.tenantID, "tenant-id", "", "tenant UUID (required)")
	fs.StringVar(&f.eventType, "event-type", "", "event type in lower.dot.notation, e.g. vendor.outage (required)")
	fs.StringVar(&f.eventSource, "event-source", "", "event source enum value, e.g. aws.cloudtrail (required)")
	fs.StringVar(&f.actor, "actor", "", "IAM principal, user, or bot name (optional)")
	fs.StringVar(&f.resource, "resource", "", "affected resource identifier (optional)")
	fs.StringVar(&f.payloadFile, "payload-file", "", "path to a JSON object file; defaults to {} (optional)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return f, nil
}

// validateEmitEventFlags returns an error describing every missing or invalid flag.
func validateEmitEventFlags(f *emitEventFlags) error {
	var errs []error
	if f.tenantID == "" {
		errs = append(errs, errors.New("--tenant-id is required"))
	} else if _, err := uuid.Parse(f.tenantID); err != nil {
		errs = append(errs, fmt.Errorf("--tenant-id %q is not a valid UUID", f.tenantID))
	}
	if f.eventType == "" {
		errs = append(errs, errors.New("--event-type is required"))
	}
	if f.eventSource == "" {
		errs = append(errs, errors.New("--event-source is required"))
	}
	return errors.Join(errs...)
}

// runEmitEvent implements the --emit-event one-shot mode. It builds a canonical
// envelope from the provided flags, ships it via the transport client (exercising
// WAL, redaction, retry, and DLQ paths), logs structured events at each stage,
// and returns nil on HTTP 200 or a non-nil error on any failure (including DLQ).
//
// Config is assembled directly from environment variables so the operator does
// not need a full config file — useful for ad-hoc test-box invocations.
// Required env vars:
//
//	OPERITAS_INGEST_API_KEY   — bearer token
//	OPERITAS_INGEST_URL       — POST endpoint (defaults to https://api.operitas.eu/v1/events:batch)
//	OPERITAS_COLLECTOR_ID     — collector UUID (defaults to a fresh UUID if absent)
func runEmitEvent(ctx context.Context, f *emitEventFlags) error {
	// ---- assemble payload -----------------------------------------------
	payload := map[string]any{}
	if f.payloadFile != "" {
		data, err := os.ReadFile(f.payloadFile)
		if err != nil {
			return fmt.Errorf("read payload file %q: %w", f.payloadFile, err)
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return fmt.Errorf("parse payload file %q: %w", f.payloadFile, err)
		}
	}

	// ---- build event -----------------------------------------------------
	ev := envelope.Event{
		OccurredAt:  time.Now().UTC(),
		EventType:   f.eventType,
		EventSource: envelope.EventSource(f.eventSource),
		Payload:     payload,
	}
	if f.actor != "" {
		s := f.actor
		ev.Actor = &s
	}
	if f.resource != "" {
		s := f.resource
		ev.Resource = &s
	}

	if err := ev.Validate(); err != nil {
		return fmt.Errorf("event validation failed: %w", err)
	}

	// ---- assemble transport config from env vars -------------------------
	apiKey := os.Getenv("OPERITAS_INGEST_API_KEY")
	if apiKey == "" {
		return errors.New("OPERITAS_INGEST_API_KEY is required")
	}

	endpoint := os.Getenv("OPERITAS_INGEST_URL")
	if endpoint == "" {
		endpoint = "https://api.operitas.eu/v1/events:batch"
	}

	collectorID := os.Getenv("OPERITAS_COLLECTOR_ID")
	if collectorID == "" {
		collectorID = uuid.NewString()
		slog.Info("emit_event_start: no OPERITAS_COLLECTOR_ID set; using ephemeral collector ID",
			"collector_id", collectorID,
		)
	}

	walDir := os.Getenv("OPERITAS_WAL_DIR")
	if walDir == "" {
		walDir = config.WALDir
	}
	dlqDir := os.Getenv("OPERITAS_DLQ_DIR")
	if dlqDir == "" {
		dlqDir = config.DLQDir
	}

	cfg := transport.ClientConfig{
		Endpoint:       endpoint,
		APIKey:         apiKey,
		CollectorID:    collectorID,
		TenantID:       f.tenantID,
		WALDir:         walDir,
		DLQDir:         dlqDir,
		BackoffInitial: 1 * time.Second,
		BackoffMax:     5 * time.Minute,
		// BatchMax* fields are unused by SendOnce but set to safe values.
		BatchMaxEvents:     1,
		BatchMaxBytes:      1 * 1024 * 1024,
		BatchFlushInterval: 250 * time.Millisecond,
	}

	// ---- deliver ---------------------------------------------------------
	slog.Info("emit_event_start",
		"tenant_id", f.tenantID,
		"event_type", f.eventType,
		"event_source", f.eventSource,
		"endpoint", endpoint,
	)

	client, err := transport.NewClientNoMTLS(cfg)
	if err != nil {
		return fmt.Errorf("transport init: %w", err)
	}

	if err := client.SendOnce(ctx, ev); err != nil {
		if errors.Is(err, transport.ErrBatchDLQed) {
			slog.Error("emit_event_failed",
				"reason", "batch routed to DLQ (schema validation or oversized event)",
				"tenant_id", f.tenantID,
				"event_type", f.eventType,
				"event_source", f.eventSource,
			)
			return err
		}
		slog.Error("emit_event_failed",
			"reason", err.Error(),
			"tenant_id", f.tenantID,
			"event_type", f.eventType,
			"event_source", f.eventSource,
		)
		return err
	}

	slog.Info("emit_event_sent",
		"tenant_id", f.tenantID,
		"event_type", f.eventType,
		"event_source", f.eventSource,
		"endpoint", endpoint,
	)
	return nil
}
