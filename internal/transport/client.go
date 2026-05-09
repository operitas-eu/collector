package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"operitas.eu/collector/internal/envelope"
)

// idempotencyKeyTTL is the collector-side retry deadline for a batch. It must
// be shorter than the server's idempotency cache TTL (24h per
// internal/idempotency/redis.go in the operitas-eu/operitas monorepo) so that
// a replayed Idempotency-Key always hits the cache and never double-writes.
// 12h is well within the 24h server window and also within the WAL prune age (14 days).
const idempotencyKeyTTL = 12 * time.Hour

// Client batches events, persists them to the WAL, and ships them to the
// ingest API with mTLS and exponential backoff.
//
// The zero value is not usable; construct with NewClient.
type Client struct {
	cfg      ClientConfig
	httpCl   *http.Client
	mu       sync.Mutex
	buf      []envelope.Event
	bufBytes int

	// deauthorized is set to 1 when the server returns 401. Once set, the
	// flush loop stops delivering batches and surfaces a loud log on every
	// tick so that the operator sees the problem without drowning in retries.
	deauthorized atomic.Bool

	// flushCh signals the flush loop that a batch is ready.
	flushCh chan struct{}
	done    chan struct{}
	wg      sync.WaitGroup
}

// ClientConfig is a subset of the full Config needed by the transport layer.
type ClientConfig struct {
	Endpoint           string
	TLSCertFile        string
	TLSKeyFile         string
	TLSCAFile          string
	CollectorID        string
	TenantID           string
	WALDir             string
	BatchMaxEvents     int
	BatchMaxBytes      int
	BatchFlushInterval time.Duration
	BackoffInitial     time.Duration
	BackoffMax         time.Duration
}

// NewClient builds an mTLS HTTP client and starts the background flush loop.
// It also replays any WAL entries from a previous run before accepting new events.
func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: build TLS config: %w", err)
	}

	c := &Client{
		cfg: cfg,
		httpCl: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
				// Conservative timeouts; the connection is long-lived within a single
				// flush cycle but we do not want runaway goroutines on network failures.
				ResponseHeaderTimeout: 30 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
			},
			Timeout: 60 * time.Second,
		},
		flushCh: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}

	// Drop stale or oversized WAL entries before replaying.
	if err := walPrune(cfg.WALDir, 14*24*time.Hour, 1<<30); err != nil {
		slog.Warn("wal prune failed", "err", err)
	}

	if err := c.replayWAL(ctx); err != nil {
		// Non-fatal: log and continue. Incomplete batches will be retried
		// in the next run if they are still in the WAL.
		slog.Error("wal replay failed", "err", err)
	}

	c.wg.Add(1)
	go c.flushLoop(ctx)

	return c, nil
}

// Deauthorized reports whether the collector has been told to stop by a 401
// response. Callers can expose this via a health endpoint.
func (c *Client) Deauthorized() bool {
	return c.deauthorized.Load()
}

// Send enqueues an event for batched delivery. If the buffer is full by count
// or byte size, it signals the flush loop immediately.
func (c *Client) Send(ev envelope.Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		slog.Error("transport: drop event — marshal failed",
			"event_type", ev.EventType,
			"event_source", ev.EventSource,
			"err", err,
		)
		return
	}
	evBytes := len(data)

	c.mu.Lock()
	c.buf = append(c.buf, ev)
	c.bufBytes += evBytes
	// Cap at BatchMaxEvents (must be <= 1000 per schema maxItems constraint).
	shouldFlush := len(c.buf) >= c.cfg.BatchMaxEvents || c.bufBytes >= c.cfg.BatchMaxBytes
	c.mu.Unlock()

	if shouldFlush {
		select {
		case c.flushCh <- struct{}{}:
		default:
		}
	}
}

// Close flushes remaining events and shuts down the flush loop.
func (c *Client) Close(ctx context.Context) error {
	close(c.done)
	c.wg.Wait()
	// Final flush of anything remaining in the buffer.
	return c.flush(ctx)
}

func (c *Client) flushLoop(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(c.cfg.BatchFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-ticker.C:
			if c.deauthorized.Load() {
				// 401 received — stop delivering. Surface a loud log on every
				// tick so the operator can see the problem without log flooding.
				slog.Error("collector deauthorized: token revoked or missing — stop delivering batches; rotate the API key and restart the collector",
					"endpoint", c.cfg.Endpoint,
				)
				continue
			}
			if err := c.flush(ctx); err != nil {
				slog.Error("flush error", "err", err)
			}
		case <-c.flushCh:
			if c.deauthorized.Load() {
				continue
			}
			if err := c.flush(ctx); err != nil {
				slog.Error("flush error", "err", err)
			}
		}
	}
}

func (c *Client) flush(ctx context.Context) error {
	c.mu.Lock()
	if len(c.buf) == 0 {
		c.mu.Unlock()
		return nil
	}
	events := c.buf
	c.buf = nil
	c.bufBytes = 0
	c.mu.Unlock()

	batch := envelope.NewBatch(c.cfg.CollectorID, c.cfg.TenantID, events)
	if err := envelope.ValidateBatch(batch); err != nil {
		// A validation failure here is a programmer error; log it with event
		// metadata (no payloads) and drop the batch.
		slog.Error("batch validation failed — dropping batch",
			"err", err,
			"event_count", len(events),
		)
		return nil
	}

	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}

	idempotencyKey := uuid.NewString()

	if err := walWrite(c.cfg.WALDir, idempotencyKey, payload); err != nil {
		// If we cannot write the WAL we still attempt delivery, but log the failure
		// so the operator knows events are not durably spooled.
		slog.Error("wal write failed; events not durably spooled", "err", err)
	}

	outcome, err := c.deliverWithRetry(ctx, idempotencyKey, payload, len(events))
	if err != nil {
		// Events remain in the WAL for replay on next startup.
		return fmt.Errorf("deliver batch (key=%s): %w", idempotencyKey, err)
	}
	if outcome == deliveryDLQ || outcome == deliveryOK {
		_ = walDelete(c.cfg.WALDir, idempotencyKey)
	}
	// deliveryDeauthorized: leave WAL intact — operator must investigate.
	return nil
}

// deliveryOutcome is the result of a delivery attempt after all retries.
type deliveryOutcome int

const (
	deliveryOK             deliveryOutcome = iota // 200: cursor advanced, WAL entry deleted
	deliveryDLQ                                   // 422/413 single-event: routed to DLQ, WAL entry deleted
	deliveryDeauthorized                          // 401: stop loop, WAL entry kept
	deliveryTransientError                        // 5xx/TLS: caller leaves WAL intact
)

// deliverWithRetry sends the payload to the ingest API with exponential backoff.
// It handles all the status code semantics from ADR 0003 and docs/api/ingest-batch.md:
//
//   - 200: accept, advance WAL cursor
//   - 401: deauthorize, stop
//   - 413: split-batch retry (see deliverSplit)
//   - 422: DLQ (never retry)
//   - 429: honor Retry-After
//   - 5xx: exponential backoff with jitter
//   - TLS error: fail-closed, no retry
func (c *Client) deliverWithRetry(ctx context.Context, idempotencyKey string, payload []byte, eventCount int) (deliveryOutcome, error) {
	delay := c.cfg.BackoffInitial
	for attempt := 0; ; attempt++ {
		outcome, err := c.deliver(ctx, idempotencyKey, payload, eventCount)
		if err == nil {
			return outcome, nil
		}

		// Fail closed on TLS errors — no retry; WAL entry left for investigation.
		if isTLSError(err) {
			return deliveryTransientError, fmt.Errorf("tls error (fail-closed): %w", err)
		}

		// 413 split-batch is handled inside deliver; if it returns an error the
		// split itself failed transiently — fall through to backoff.

		slog.Warn("ingest delivery failed; will retry",
			"attempt", attempt+1,
			"delay", delay,
			"idempotency_key", idempotencyKey,
			"err", err,
		)

		select {
		case <-ctx.Done():
			return deliveryTransientError, ctx.Err()
		case <-time.After(delay):
		}

		// Exponential backoff with ±10% jitter.
		delay = time.Duration(float64(delay) * 2.0)
		if delay > c.cfg.BackoffMax {
			delay = c.cfg.BackoffMax
		}
		jitter := time.Duration(float64(delay) * 0.1 * (rand.Float64()*2 - 1)) //nolint:gosec // jitter timing is not security-sensitive
		delay += jitter
		if delay < 0 {
			delay = c.cfg.BackoffInitial
		}
	}
}

func (c *Client) deliver(ctx context.Context, idempotencyKey string, payload []byte, eventCount int) (deliveryOutcome, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return deliveryTransientError, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	req.Header.Set("X-Collector-ID", c.cfg.CollectorID)
	req.Header.Set("X-Tenant-ID", c.cfg.TenantID)

	resp, err := c.httpCl.Do(req)
	if err != nil {
		return deliveryTransientError, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return c.handleOK(resp, idempotencyKey, eventCount)

	case http.StatusUnauthorized:
		// 401: token revoked or missing — stop all delivery, surface loud alert.
		// Do NOT delete the WAL entry; operator must rotate key and restart.
		c.deauthorized.Store(true)
		slog.Error("collector deauthorized: ingest returned 401 — token revoked or missing; rotate API key and restart collector",
			"idempotency_key", idempotencyKey,
			"endpoint", c.cfg.Endpoint,
		)
		return deliveryDeauthorized, nil

	case http.StatusForbidden:
		// 403: body tenant_id does not match credential — security signal (manifest §9.1).
		// Treat like 401: stop and alert.
		c.deauthorized.Store(true)
		slog.Error("collector stopped: ingest returned 403 — body tenant_id does not match credential; check configuration",
			"idempotency_key", idempotencyKey,
			"endpoint", c.cfg.Endpoint,
		)
		return deliveryDeauthorized, nil

	case http.StatusRequestEntityTooLarge:
		// 413: batch too large — split and retry. ADR 0003: never retry as-is.
		return c.deliverSplit(ctx, idempotencyKey, payload, eventCount)

	case http.StatusUnprocessableEntity:
		// 422: schema validation failure — route to DLQ, never retry.
		return c.handle422(resp, idempotencyKey)

	case http.StatusTooManyRequests:
		// 429: honor Retry-After header then signal the caller to retry.
		return c.handle429(ctx, resp)

	case http.StatusConflict:
		// 409: idempotency key in flight — wait for the reservation to expire
		// (server TTL is 60s) then retry. Signal transient so caller retries.
		slog.Warn("idempotency key in flight (409); will retry after backoff",
			"idempotency_key", idempotencyKey,
		)
		return deliveryTransientError, fmt.Errorf("ingest returned 409 (idempotency key in flight)")
	}

	// 5xx or any other unexpected code: transient — caller retries with backoff.
	return deliveryTransientError, fmt.Errorf("ingest returned %d", resp.StatusCode)
}

// handleOK processes a 200 response. It reads and validates the response body,
// then asserts the seq-count invariant per ADR 0003 before signaling WAL cursor
// advance. This is a defensive check — a violation surfaces a server bug without
// silently advancing the cursor to a wrong position.
func (c *Client) handleOK(resp *http.Response, idempotencyKey string, eventCount int) (deliveryOutcome, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		// Body read failure on 200 is unusual. Log but still treat as success —
		// the server committed; we advance the WAL cursor.
		slog.Warn("failed to read 200 response body; treating as accepted",
			"idempotency_key", idempotencyKey,
			"err", err,
		)
		return deliveryOK, nil
	}

	var br envelope.BatchResponse
	if err := json.Unmarshal(body, &br); err != nil {
		slog.Warn("failed to decode 200 response body; treating as accepted",
			"idempotency_key", idempotencyKey,
			"err", err,
		)
		return deliveryOK, nil
	}

	// Defensive invariant: last_seq - first_seq + 1 must equal the number of
	// events in the batch. A violation means the server accepted a different
	// number of events than we sent — a server bug; do not advance cursor blindly.
	if br.FirstSeq > 0 || br.LastSeq > 0 {
		seqSpan := br.LastSeq - br.FirstSeq + 1
		if int64(eventCount) != seqSpan {
			slog.Error("seq-span invariant violated — server may have partial-accepted; not advancing WAL cursor",
				"idempotency_key", idempotencyKey,
				"expected_events", eventCount,
				"first_seq", br.FirstSeq,
				"last_seq", br.LastSeq,
				"seq_span", seqSpan,
			)
			// Return a transient error so the caller retries (same idempotency key
			// will get the cached 200 back from the server, which will hit the
			// same invariant again — operator will see repeated loud logs).
			return deliveryTransientError, fmt.Errorf("seq-span invariant violated: events=%d first_seq=%d last_seq=%d span=%d",
				eventCount, br.FirstSeq, br.LastSeq, seqSpan)
		}
	}

	slog.Info("batch accepted",
		"idempotency_key", idempotencyKey,
		"accepted", br.Accepted,
		"first_seq", br.FirstSeq,
		"last_seq", br.LastSeq,
	)
	return deliveryOK, nil
}

// handle422 logs the per-event errors from the 422 body (metadata only, no
// payload content per manifest §12.13) and routes the batch to the DLQ.
func (c *Client) handle422(resp *http.Response, idempotencyKey string) (deliveryOutcome, error) {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var ve envelope.ValidationError422
	if err := json.Unmarshal(body, &ve); err != nil {
		slog.Warn("422 response: failed to decode error body",
			"idempotency_key", idempotencyKey,
			"raw", string(body),
		)
	} else {
		if len(ve.EnvelopeErrors) > 0 {
			slog.Warn("422 envelope-level validation errors — routing to DLQ",
				"idempotency_key", idempotencyKey,
				"envelope_errors", ve.EnvelopeErrors,
			)
		}
		for _, ev := range ve.Events {
			// Log event_type and event_source are not in the 422 body (server only
			// echoes index + error strings). Log index + errors only; no payload.
			slog.Warn("422 per-event validation error — routing to DLQ",
				"idempotency_key", idempotencyKey,
				"event_index", ev.Index,
				"errors", ev.Errors,
			)
		}
	}
	slog.Error("batch failed schema validation (422): routing to DLQ — do not retry; check for schema drift between collector and ingest validators (manifest §0 P1)",
		"idempotency_key", idempotencyKey,
	)
	// TODO: write to a DLQ file under /var/lib/operitas/dlq/ when DLQ is implemented.
	// For now we delete the WAL entry (the batch is poison and cannot be fixed by retry).
	return deliveryDLQ, nil
}

// handle429 reads the Retry-After header and sleeps for that duration before
// returning a transient error so deliverWithRetry will re-attempt.
func (c *Client) handle429(ctx context.Context, resp *http.Response) (deliveryOutcome, error) {
	retryAfter := resp.Header.Get("Retry-After")
	var wait time.Duration
	if secs, err := strconv.Atoi(retryAfter); err == nil && secs > 0 {
		wait = time.Duration(secs) * time.Second
	} else {
		// Retry-After absent or unparseable — fall back to 60s.
		wait = 60 * time.Second
	}
	slog.Warn("rate limited (429); honoring Retry-After",
		"retry_after_header", retryAfter,
		"wait", wait,
	)
	select {
	case <-ctx.Done():
		return deliveryTransientError, ctx.Err()
	case <-time.After(wait):
	}
	return deliveryTransientError, errors.New("ingest returned 429 (throttled)")
}

// deliverSplit implements the 413 split-batch retry. It halves the batch
// recursively until each half is accepted or a single-event batch hits 413
// (in which case that event is routed to the DLQ).
//
// Each half gets a fresh idempotency key because the split produces a
// structurally different payload.
func (c *Client) deliverSplit(ctx context.Context, originalKey string, payload []byte, eventCount int) (deliveryOutcome, error) {
	if eventCount <= 1 {
		// A single event that exceeds 32 MiB is pathological. DLQ it.
		slog.Error("single-event batch returned 413 — event exceeds server size limit; routing to DLQ",
			"original_idempotency_key", originalKey,
		)
		// TODO: write to DLQ file.
		return deliveryDLQ, nil
	}

	// Re-decode the original batch payload to split it.
	var orig envelope.BatchRequest
	if err := json.Unmarshal(payload, &orig); err != nil {
		return deliveryTransientError, fmt.Errorf("split: decode original payload: %w", err)
	}

	mid := len(orig.Events) / 2
	halves := [][]envelope.Event{
		orig.Events[:mid],
		orig.Events[mid:],
	}

	for _, half := range halves {
		halfBatch := envelope.NewBatch(orig.CollectorID, orig.TenantID, half)
		halfPayload, err := json.Marshal(halfBatch)
		if err != nil {
			return deliveryTransientError, fmt.Errorf("split: marshal half: %w", err)
		}
		halfKey := uuid.NewString()
		if err := walWrite(c.cfg.WALDir, halfKey, halfPayload); err != nil {
			slog.Error("split: wal write failed for half; events not durably spooled",
				"original_key", originalKey,
				"half_key", halfKey,
				"err", err,
			)
		}
		outcome, err := c.deliverWithRetry(ctx, halfKey, halfPayload, len(half))
		if err != nil {
			return deliveryTransientError, fmt.Errorf("split delivery failed: %w", err)
		}
		_ = walDelete(c.cfg.WALDir, halfKey)
		if outcome == deliveryDeauthorized {
			return deliveryDeauthorized, nil
		}
	}
	// Original WAL entry is superseded by the two halves; signal OK so caller
	// deletes the original entry.
	return deliveryOK, nil
}

func (c *Client) replayWAL(ctx context.Context) error {
	entries, err := walRecover(c.cfg.WALDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		slog.Info("replaying wal entry", "idempotency_key", entry.IdempotencyKey)
		// Determine event count from the WAL payload for the seq-span check.
		var batch envelope.BatchRequest
		eventCount := 0
		if err := json.Unmarshal(entry.Payload, &batch); err != nil {
			slog.Warn("wal replay: cannot decode payload to get event count; seq-span check skipped",
				"idempotency_key", entry.IdempotencyKey,
				"err", err,
			)
		} else {
			eventCount = len(batch.Events)
		}
		outcome, err := c.deliverWithRetry(ctx, entry.IdempotencyKey, entry.Payload, eventCount)
		if err != nil {
			slog.Error("wal replay failed for entry", "idempotency_key", entry.IdempotencyKey, "err", err)
			continue
		}
		if outcome == deliveryOK || outcome == deliveryDLQ {
			_ = walDelete(c.cfg.WALDir, entry.IdempotencyKey)
		}
	}
	return nil
}

func buildTLSConfig(cfg ClientConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if cfg.TLSCAFile != "" {
		caPEM, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certificates in CA file %q", cfg.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

// isTLSError checks whether an error is a TLS/certificate error that warrants
// fail-closed behaviour (no retry, alert operator). Uses errors.As against the
// concrete x509/tls error types instead of substring matching.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	var unknownAuthority x509.UnknownAuthorityError
	var certInvalid x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	var systemRoots x509.SystemRootsError
	var recordHeader tls.RecordHeaderError
	var certVerify *tls.CertificateVerificationError
	switch {
	case errors.As(err, &unknownAuthority),
		errors.As(err, &certInvalid),
		errors.As(err, &hostnameErr),
		errors.As(err, &systemRoots),
		errors.As(err, &recordHeader),
		errors.As(err, &certVerify):
		return true
	}
	return false
}
