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

// ErrBatchDLQed is returned by FlushOnce when the event was routed to the
// dead-letter queue (HTTP 422 or single-event 413). The event was not accepted
// by the ingest API and will not be retried automatically.
var ErrBatchDLQed = fmt.Errorf("batch was routed to DLQ (schema validation failure or oversized single event)")

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
	Endpoint    string
	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string
	CollectorID string
	TenantID    string
	// APIKey is the bearer token sent in the Authorization header on every request.
	// Format: <key_id>.<secret> (as minted by the Operitas portal enrollment flow).
	// This value must never appear in logs, error messages, or any stored state.
	APIKey             string
	WALDir             string
	DLQDir             string
	BatchMaxEvents     int
	BatchMaxBytes      int
	BatchFlushInterval time.Duration
	BackoffInitial     time.Duration
	BackoffMax         time.Duration

	// PruneInterval controls how often walPrune and dlqPrune run during a
	// live flush loop (perf-6). The prune policy enforces the 1 GiB / 14-day
	// cap on disk usage even during long-running collector sessions.
	// Zero means use the default of 4 hours.
	PruneInterval time.Duration
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

	// Drop stale or oversized WAL entries before replaying. Any entry pruned
	// here was never acknowledged by the ingest ledger; log the count loudly
	// so operators are aware of potential evidence loss on startup.
	if walDropped, err := walPrune(cfg.WALDir, 14*24*time.Hour, 1<<30); err != nil {
		slog.Warn("wal prune failed", "err", err)
	} else if walDropped > 0 {
		slog.Warn("startup: dropped undelivered WAL entries before replay; evidence dropped before delivery",
			"dropped_count", walDropped)
	}
	// Prune DLQ with identical policy: 14-day age + 1 GiB cap.
	if dlqDropped, err := dlqPrune(cfg.DLQDir, dlqMaxAge, dlqMaxBytes); err != nil {
		slog.Warn("dlq prune failed", "err", err)
	} else if dlqDropped > 0 {
		slog.Warn("startup: dropped DLQ entries; evidence dropped before delivery",
			"dropped_count", dlqDropped)
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

// SendOnce builds a single-event batch from ev, writes it to the WAL, delivers
// it to the ingest API with full retry/backoff semantics, then returns:
//   - nil on HTTP 200
//   - ErrBatchDLQed on 422 or single-event 413 (event written to DLQ)
//   - a descriptive error for 401/403 or unrecoverable transport failure
//
// The WAL entry is deleted on deliveryOK or deliveryDLQ so a subsequent normal
// collector run does not replay the same event. On any other outcome the WAL
// entry is left in place for operator investigation.
//
// SendOnce is intended for one-shot CLI modes such as --emit-event. It does not
// interact with the background flush loop; callers should use NewClientNoMTLS
// (which does not start the loop) rather than NewClient.
func (c *Client) SendOnce(ctx context.Context, ev envelope.Event) error {
	batch := envelope.NewBatch(c.cfg.CollectorID, c.cfg.TenantID, []envelope.Event{ev})
	if err := envelope.ValidateBatch(batch); err != nil {
		return fmt.Errorf("envelope validation failed: %w", err)
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}
	idempotencyKey := uuid.NewString()
	if err := walWrite(c.cfg.WALDir, idempotencyKey, payload); err != nil {
		// Non-fatal: proceed with delivery even if the WAL write failed.
		slog.Error("emit-event: wal write failed; event not durably spooled", "err", err)
	}
	outcome, err := c.deliverWithRetry(ctx, idempotencyKey, payload, 1)
	if err != nil {
		return fmt.Errorf("delivery failed: %w", err)
	}
	switch outcome {
	case deliveryOK:
		_ = walDelete(c.cfg.WALDir, idempotencyKey)
		return nil
	case deliveryDLQ:
		_ = walDelete(c.cfg.WALDir, idempotencyKey)
		return ErrBatchDLQed
	case deliveryDeauthorized:
		return fmt.Errorf("collector deauthorized: ingest returned 401/403 — check API key and tenant configuration")
	default:
		return fmt.Errorf("delivery ended in unexpected outcome %d", outcome)
	}
}

// NewClientNoMTLS builds a Client that uses plain HTTPS with the system CA pool
// (no mTLS client certificate). This is the transport used by the --emit-event
// one-shot mode when no client certificate is configured. All other transport
// behaviour (WAL, DLQ, backoff, retry semantics) is identical to NewClient.
//
// The background flush loop is NOT started; callers should use SendOnce for
// one-shot delivery.
func NewClientNoMTLS(cfg ClientConfig) (*Client, error) {
	httpCl := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
		},
		Timeout: 60 * time.Second,
	}

	c := &Client{
		cfg:     cfg,
		httpCl:  httpCl,
		flushCh: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}

	if walDropped, err := walPrune(cfg.WALDir, 14*24*time.Hour, 1<<30); err != nil {
		slog.Warn("wal prune failed", "err", err)
	} else if walDropped > 0 {
		slog.Warn("startup: dropped undelivered WAL entries before replay; evidence dropped before delivery",
			"dropped_count", walDropped)
	}
	if dlqDropped, err := dlqPrune(cfg.DLQDir, dlqMaxAge, dlqMaxBytes); err != nil {
		slog.Warn("dlq prune failed", "err", err)
	} else if dlqDropped > 0 {
		slog.Warn("startup: dropped DLQ entries; evidence dropped before delivery",
			"dropped_count", dlqDropped)
	}

	return c, nil
}

func (c *Client) flushLoop(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(c.cfg.BatchFlushInterval)
	defer ticker.Stop()

	// perf-6: periodic WAL/DLQ prune so the 1 GiB / 14-day cap is enforced
	// live, not only at startup. Default to 4 hours if not explicitly set.
	pruneInterval := c.cfg.PruneInterval
	if pruneInterval <= 0 {
		pruneInterval = 4 * time.Hour
	}
	pruneTicker := time.NewTicker(pruneInterval)
	defer pruneTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return

		case <-pruneTicker.C:
			c.runPrune()

		case <-ticker.C:
			if c.deauthorized.Load() {
				// perf-5: spill any in-memory events to the WAL so they survive
				// the deauth period and can be replayed after the operator rotates
				// the API key and restarts. This prevents an unbounded in-memory
				// buffer accumulation when the collector is deauthorized.
				if err := c.spillToWAL(); err != nil {
					slog.Error("post-deauth wal spill failed", "err", err)
				}
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
				// perf-5: same WAL spill path for signal-triggered flushes.
				if err := c.spillToWAL(); err != nil {
					slog.Error("post-deauth wal spill failed (flushCh)", "err", err)
				}
				continue
			}
			if err := c.flush(ctx); err != nil {
				slog.Error("flush error", "err", err)
			}
		}
	}
}

// spillToWAL drains the in-memory event buffer into the WAL directory so that
// events accumulated after a 401 deauthorization survive a restart and can be
// replayed once the operator rotates the API key.
//
// This prevents the in-memory buffer from growing without bound during the
// deauth period (perf-5). Each call writes at most one WAL entry covering
// whatever is currently in the buffer.
func (c *Client) spillToWAL() error {
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
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("spill: marshal batch: %w", err)
	}
	key := uuid.NewString()
	if err := walWrite(c.cfg.WALDir, key, payload); err != nil {
		return fmt.Errorf("spill: wal write (key=%s): %w", key, err)
	}
	slog.Warn("post-deauth: spilled in-memory events to WAL for replay after key rotation",
		"event_count", len(events),
		"idempotency_key", key,
	)
	return nil
}

// runPrune enforces the 1 GiB / 14-day retention cap on the WAL and DLQ
// directories during a live run (perf-6). Errors are logged and not fatal.
//
// Evidence-window implication: entries pruned here were never acknowledged by
// the ingest ledger. Combined with the post-deauth WAL spill (perf-5), a
// collector that stays deauthorized for more than 14 days will lose evidence
// permanently. The WARN below is intentionally loud so operators notice before
// the window expires. The operitas_collector_wal_pruned_total counter tracks
// cumulative counts for alerting.
func (c *Client) runPrune() {
	walDropped, err := walPrune(c.cfg.WALDir, 14*24*time.Hour, 1<<30)
	if err != nil {
		slog.Warn("live wal prune failed", "err", err)
	}
	dlqDropped, err := dlqPrune(c.cfg.DLQDir, dlqMaxAge, dlqMaxBytes)
	if err != nil {
		slog.Warn("live dlq prune failed", "err", err)
	}
	if walDropped+dlqDropped > 0 {
		// This is the primary loss signal. It fires once per prune cycle that
		// actually drops entries, so the log is loud but not spammy.
		slog.Warn("evidence dropped before delivery: WAL/DLQ entries pruned without acknowledgement by the ingest ledger; this data cannot be recovered — rotate the API key and restart the collector to prevent further loss",
			"wal_dropped", walDropped,
			"dlq_dropped", dlqDropped,
		)
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
	// Authorization header is set on every attempt (including retries) because
	// deliver() is called from deliverWithRetry on each attempt. The APIKey
	// value must never appear in logs or error strings — only in this header.
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
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
		return c.handle422(resp, idempotencyKey, payload)

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
// requestBody is the serialised BatchRequest that was sent; it is written to
// the DLQ file (already PII-redacted). It must NOT appear in log lines.
func (c *Client) handle422(resp *http.Response, idempotencyKey string, requestBody []byte) (deliveryOutcome, error) {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var ve envelope.ValidationError422
	eventCount := 0
	if err := json.Unmarshal(body, &ve); err != nil {
		slog.Warn("422 response: failed to decode error body",
			"idempotency_key", idempotencyKey,
		)
	} else {
		if len(ve.EnvelopeErrors) > 0 {
			slog.Warn("422 envelope-level validation errors — routing to DLQ",
				"idempotency_key", idempotencyKey,
				"envelope_errors", ve.EnvelopeErrors,
			)
		}
		for _, ev := range ve.Events {
			// event_type and event_source are not echoed by the server; log
			// index + error strings only. No payload content in logs.
			slog.Warn("422 per-event validation error — routing to DLQ",
				"idempotency_key", idempotencyKey,
				"event_index", ev.Index,
				"errors", ev.Errors,
			)
			eventCount++
		}
	}

	dlqPath := c.writeToDLQ(idempotencyKey, http.StatusUnprocessableEntity, body, requestBody, eventCount)
	slog.Warn("batch failed schema validation (422): routed to DLQ — do not retry; check for schema drift between collector and ingest validators (manifest §0 P1)",
		"idempotency_key", idempotencyKey,
		"dlq_path", dlqPath,
		"status_code", http.StatusUnprocessableEntity,
		"event_count", eventCount,
	)
	return deliveryDLQ, nil
}

// writeToDLQ writes the failed batch to the DLQ directory and increments the
// per-status-code metric counter. It returns the full path of the written file
// (or an empty string if the write failed, in which case an error is logged).
//
// responseBody may be nil (e.g. for a 413 where the body is not meaningful).
// requestBody is the serialised BatchRequest — already PII-redacted — and must
// not be included in any log line. Its content goes only into the DLQ file.
func (c *Client) writeToDLQ(idempotencyKey string, statusCode int, responseBody []byte, requestBody []byte, eventCount int) string {
	// Truncate response body to 64 KiB before writing to the DLQ file.
	const maxRespBody = 1 << 16
	if len(responseBody) > maxRespBody {
		responseBody = responseBody[:maxRespBody]
	}
	path, err := dlqWrite(c.cfg.DLQDir, idempotencyKey, statusCode, responseBody, requestBody)
	if err != nil {
		slog.Error("dlq write failed; batch permanently dropped",
			"idempotency_key", idempotencyKey,
			"status_code", statusCode,
			"event_count", eventCount,
			"err", err,
		)
		return ""
	}
	incDLQCounter(statusCode)
	return path
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
		// A single event that exceeds the server size limit is pathological. DLQ it.
		dlqPath := c.writeToDLQ(originalKey, http.StatusRequestEntityTooLarge, nil, payload, eventCount)
		slog.Warn("single-event batch returned 413 — event exceeds server size limit; routed to DLQ",
			"idempotency_key", originalKey,
			"dlq_path", dlqPath,
			"status_code", http.StatusRequestEntityTooLarge,
			"event_count", eventCount,
		)
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
		incWALReplays()
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
