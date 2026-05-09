package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"operitas.eu/collector/internal/envelope"
)

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
			if err := c.flush(ctx); err != nil {
				slog.Error("flush error", "err", err)
			}
		case <-c.flushCh:
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

	if err := c.deliverWithRetry(ctx, idempotencyKey, payload); err != nil {
		// Events remain in the WAL for replay on next startup.
		return fmt.Errorf("deliver batch (key=%s): %w", idempotencyKey, err)
	}

	_ = walDelete(c.cfg.WALDir, idempotencyKey)
	return nil
}

// deliverWithRetry sends the payload to the ingest API with exponential backoff.
// It fails closed on TLS errors: any certificate or handshake error terminates
// the retry loop immediately without persisting the payload in cleartext.
func (c *Client) deliverWithRetry(ctx context.Context, idempotencyKey string, payload []byte) error {
	delay := c.cfg.BackoffInitial
	for attempt := 0; ; attempt++ {
		err := c.deliver(ctx, idempotencyKey, payload)
		if err == nil {
			return nil
		}

		// Fail closed on TLS errors — do not retry; returning the error leaves
		// the WAL entry intact for operator investigation.
		if isTLSError(err) {
			return fmt.Errorf("tls error (fail-closed): %w", err)
		}

		slog.Warn("ingest delivery failed; will retry",
			"attempt", attempt+1,
			"delay", delay,
			"idempotency_key", idempotencyKey,
			"err", err,
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
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

func (c *Client) deliver(ctx context.Context, idempotencyKey string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	req.Header.Set("X-Collector-ID", c.cfg.CollectorID)
	req.Header.Set("X-Tenant-ID", c.cfg.TenantID)

	resp, err := c.httpCl.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	// 2xx is success.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// 4xx (except 429) are permanent failures — log and drop rather than retry.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		slog.Error("ingest rejected batch (permanent); dropping",
			"status", resp.StatusCode,
			"idempotency_key", idempotencyKey,
		)
		// Delete the WAL entry since retrying a 4xx will not help.
		_ = walDelete(c.cfg.WALDir, idempotencyKey)
		return nil
	}

	return fmt.Errorf("ingest returned %d", resp.StatusCode)
}

func (c *Client) replayWAL(ctx context.Context) error {
	entries, err := walRecover(c.cfg.WALDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		slog.Info("replaying wal entry", "idempotency_key", entry.IdempotencyKey)
		if err := c.deliverWithRetry(ctx, entry.IdempotencyKey, entry.Payload); err != nil {
			slog.Error("wal replay failed for entry", "idempotency_key", entry.IdempotencyKey, "err", err)
			continue
		}
		_ = walDelete(c.cfg.WALDir, entry.IdempotencyKey)
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
