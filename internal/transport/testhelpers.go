//go:build !production

// testhelpers.go exposes types and constructors needed by the transport package
// tests. The build tag ensures nothing here ships in a production binary.
package transport

import (
	"context"
	"net/http"
	"time"
)

// TestAPIKey is the API key value used in unit tests. It is not a real
// credential and must never appear in production configuration.
const TestAPIKey = "testid0000000000.dGVzdHNlY3JldA"

// TestClientConfig returns a ClientConfig suitable for unit tests.
// It uses the given URL and WAL dir, with fast flush/backoff settings.
// The DLQDir is set to walDir + "/dlq" so tests can inspect DLQ files
// without needing a separate directory argument.
func TestClientConfig(url, walDir string) ClientConfig {
	return ClientConfig{
		Endpoint:           url,
		CollectorID:        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		TenantID:           "b1b2c3d4-e5f6-7890-abcd-ef1234567890",
		APIKey:             TestAPIKey,
		WALDir:             walDir,
		DLQDir:             walDir + "/dlq",
		BatchMaxEvents:     1000,
		BatchMaxBytes:      1 * 1024 * 1024,
		BatchFlushInterval: 100 * time.Millisecond,
		BackoffInitial:     50 * time.Millisecond,
		BackoffMax:         200 * time.Millisecond,
		// Short prune interval so perf-6 tests can verify live pruning
		// without waiting hours.
		PruneInterval: 200 * time.Millisecond,
	}
}

// NewTestClient creates a Client that uses the provided http.Client instead of
// building an mTLS one. Intended for integration tests against httptest servers.
func NewTestClient(ctx context.Context, cfg ClientConfig, httpClient *http.Client) (*Client, error) {
	c := &Client{
		cfg:     cfg,
		httpCl:  httpClient,
		flushCh: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	if err := c.replayWAL(ctx); err != nil {
		return nil, err
	}
	c.wg.Add(1)
	go c.flushLoop(ctx)
	return c, nil
}

// NewTestClientNoMTLS creates a Client that uses the provided http.Client and
// does NOT start the background flush loop. Intended for tests that call
// SendOnce directly (one-shot --emit-event style tests).
func NewTestClientNoMTLS(httpClient *http.Client, cfg ClientConfig) (*Client, error) {
	c := &Client{
		cfg:     cfg,
		httpCl:  httpClient,
		flushCh: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	return c, nil
}
