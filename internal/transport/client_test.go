package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/transport"
)

// newFakeIngest starts an HTTPS test server that records received batches and
// returns the provided status code. The server uses the httptest self-signed
// cert so we configure the client with InsecureSkipVerify for unit tests only.
func newFakeIngest(t *testing.T, statusCode int, received *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("missing Idempotency-Key header")
		}
		var batch envelope.BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received.Add(int64(len(batch.Events)))
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(envelope.BatchResponse{
			Accepted: len(batch.Events),
		})
	}))
	return srv
}

func TestBatchingAndDelivery(t *testing.T) {
	var received atomic.Int64
	srv := newFakeIngest(t, http.StatusOK, &received)
	defer srv.Close()

	walDir := t.TempDir()

	// Write dummy cert/key pair using the test server's cert.
	certFile := writeTempFile(t, srv.Certificate().Raw)
	// For unit test we use the httptest default TLS client which has InsecureSkipVerify.
	// We stub the cert/key pair by writing any PEM data; the actual TLS validation
	// is done by the test server's built-in client.
	_ = certFile

	// Use the httptest client's transport directly to bypass mTLS for unit tests.
	cfg := transport.TestClientConfig(srv.URL, walDir)
	cl, err := transport.NewTestClient(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		cl.Send(envelope.Event{
			OccurredAt:  now,
			EventType:   "deploy.completed",
			EventSource: envelope.SourceGitHub,
			Payload:     map[string]any{"i": i},
		})
	}

	// Allow the flush interval to fire.
	time.Sleep(400 * time.Millisecond)

	if err := cl.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := received.Load(); got != 5 {
		t.Errorf("expected 5 events delivered, got %d", got)
	}

	// WAL must be empty after successful delivery.
	entries, _ := os.ReadDir(walDir)
	if len(entries) != 0 {
		t.Errorf("expected empty WAL, got %d entries", len(entries))
	}
}

func TestRetryOn503(t *testing.T) {
	var received atomic.Int64
	attempts := &atomic.Int64{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var batch envelope.BatchRequest
		_ = json.NewDecoder(r.Body).Decode(&batch)
		received.Add(int64(len(batch.Events)))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(envelope.BatchResponse{Accepted: len(batch.Events)})
	}))
	defer srv.Close()

	walDir := t.TempDir()
	cfg := transport.TestClientConfig(srv.URL, walDir)
	cfg.BackoffInitial = 20 * time.Millisecond
	cfg.BackoffMax = 100 * time.Millisecond

	cl, err := transport.NewTestClient(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}

	now := time.Now().UTC()
	cl.Send(envelope.Event{
		OccurredAt:  now,
		EventType:   "incident.opened",
		EventSource: envelope.SourcePagerDuty,
		Payload:     map[string]any{"id": "P1"},
	})

	time.Sleep(600 * time.Millisecond)
	if err := cl.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := received.Load(); got != 1 {
		t.Errorf("expected 1 event after retries, got %d", got)
	}
	if got := attempts.Load(); got < 3 {
		t.Errorf("expected at least 3 attempts, got %d", got)
	}
}

func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "cert*.der")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(data)
	_ = f.Close()
	return f.Name()
}
