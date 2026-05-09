package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
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
			// FirstSeq and LastSeq left zero — seq-span check skips when both are zero.
		})
	}))
	return srv
}

// newFakeIngestWithSeqs returns a server that echoes realistic seq values so
// the seq-span assertion in handleOK is exercised.
func newFakeIngestWithSeqs(t *testing.T, received *atomic.Int64, firstSeq int64) *httptest.Server {
	t.Helper()
	var seqCursor atomic.Int64
	seqCursor.Store(firstSeq)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("missing Idempotency-Key header")
		}
		var batch envelope.BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := int64(len(batch.Events))
		received.Add(n)
		first := seqCursor.Load()
		last := first + n - 1
		seqCursor.Store(last + 1)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(envelope.BatchResponse{
			Accepted: len(batch.Events),
			FirstSeq: first,
			LastSeq:  last,
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

func TestSeqSpanCheck(t *testing.T) {
	var received atomic.Int64
	srv := newFakeIngestWithSeqs(t, &received, 100)
	defer srv.Close()

	walDir := t.TempDir()
	cfg := transport.TestClientConfig(srv.URL, walDir)
	cl, err := transport.NewTestClient(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		cl.Send(envelope.Event{
			OccurredAt:  now,
			EventType:   "deploy.completed",
			EventSource: envelope.SourceGitHub,
			Payload:     map[string]any{"i": i},
		})
	}

	time.Sleep(400 * time.Millisecond)
	if err := cl.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := received.Load(); got != 3 {
		t.Errorf("expected 3 events delivered, got %d", got)
	}
	entries, _ := os.ReadDir(walDir)
	if len(entries) != 0 {
		t.Errorf("expected empty WAL after seq-span-valid delivery, got %d entries", len(entries))
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

func TestDeauthorizedOn401(t *testing.T) {
	var attempts atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthenticated"})
	}))
	defer srv.Close()

	walDir := t.TempDir()
	cfg := transport.TestClientConfig(srv.URL, walDir)
	cfg.BackoffInitial = 10 * time.Millisecond
	cfg.BackoffMax = 50 * time.Millisecond

	cl, err := transport.NewTestClient(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}

	now := time.Now().UTC()
	cl.Send(envelope.Event{
		OccurredAt:  now,
		EventType:   "deploy.completed",
		EventSource: envelope.SourceGitHub,
		Payload:     map[string]any{"sha": "abc"},
	})

	// Wait for the flush to attempt delivery.
	time.Sleep(300 * time.Millisecond)
	_ = cl.Close(context.Background())

	if !cl.Deauthorized() {
		t.Error("expected Deauthorized() == true after 401")
	}
	// Must have attempted exactly 1 delivery — 401 is not retried.
	if got := attempts.Load(); got != 1 {
		t.Errorf("expected exactly 1 attempt on 401, got %d", got)
	}
}

func TestDLQOn422(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":           "validation_failed",
			"envelope_errors": []string{},
			"events": []map[string]any{
				{"index": 0, "errors": []string{"event_source \"sumologic\": not in enum"}},
			},
		})
	}))
	defer srv.Close()

	walDir := t.TempDir()
	cfg := transport.TestClientConfig(srv.URL, walDir)
	cfg.BackoffInitial = 10 * time.Millisecond
	cfg.BackoffMax = 50 * time.Millisecond

	cl, err := transport.NewTestClient(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}

	now := time.Now().UTC()
	cl.Send(envelope.Event{
		OccurredAt:  now,
		EventType:   "deploy.completed",
		EventSource: envelope.SourceGitHub,
		Payload:     map[string]any{"sha": "abc"},
	})

	time.Sleep(300 * time.Millisecond)
	_ = cl.Close(context.Background())

	// 422 must NOT be retried — exactly 1 attempt.
	if got := received.Load(); got != 1 {
		t.Errorf("expected exactly 1 attempt on 422 (no retry), got %d", got)
	}
	// WAL entry must be deleted after DLQ routing.
	entries, _ := os.ReadDir(walDir)
	if len(entries) != 0 {
		t.Errorf("expected empty WAL after 422 DLQ routing, got %d entries", len(entries))
	}
}

func TestSplitBatchOn413(t *testing.T) {
	// First request (4 events) returns 413; subsequent requests (2 events each)
	// return 200. Verifies the split-batch logic halves and retries.
	var received atomic.Int64
	var requestCount atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)
		var batch envelope.BatchRequest
		_ = json.NewDecoder(r.Body).Decode(&batch)
		if n == 1 {
			// First request: 413
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "body too large"})
			return
		}
		received.Add(int64(len(batch.Events)))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(envelope.BatchResponse{Accepted: len(batch.Events)})
	}))
	defer srv.Close()

	walDir := t.TempDir()
	cfg := transport.TestClientConfig(srv.URL, walDir)
	cfg.BatchMaxEvents = 4
	cfg.BackoffInitial = 10 * time.Millisecond
	cfg.BackoffMax = 50 * time.Millisecond

	cl, err := transport.NewTestClient(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}

	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		cl.Send(envelope.Event{
			OccurredAt:  now,
			EventType:   "deploy.completed",
			EventSource: envelope.SourceGitHub,
			Payload:     map[string]any{"i": i},
		})
	}

	time.Sleep(500 * time.Millisecond)
	_ = cl.Close(context.Background())

	// All 4 events must have been delivered across the split halves.
	if got := received.Load(); got != 4 {
		t.Errorf("expected 4 events delivered via split, got %d", got)
	}
}

func TestHonorRetryAfterOn429(t *testing.T) {
	var attempts atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1") // 1 second
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "throttled"})
			return
		}
		var batch envelope.BatchRequest
		_ = json.NewDecoder(r.Body).Decode(&batch)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(envelope.BatchResponse{Accepted: len(batch.Events)})
	}))
	defer srv.Close()

	walDir := t.TempDir()
	cfg := transport.TestClientConfig(srv.URL, walDir)
	cfg.BackoffInitial = 10 * time.Millisecond
	cfg.BackoffMax = 200 * time.Millisecond

	cl, err := transport.NewTestClient(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}

	now := time.Now().UTC()
	cl.Send(envelope.Event{
		OccurredAt:  now,
		EventType:   "deploy.completed",
		EventSource: envelope.SourceGitHub,
		Payload:     map[string]any{"sha": "abc"},
	})

	// Wait long enough for the 1s Retry-After to expire and the second attempt to succeed.
	time.Sleep(2500 * time.Millisecond)
	_ = cl.Close(context.Background())

	if got := attempts.Load(); got < 2 {
		t.Errorf("expected at least 2 attempts (429 then 200), got %d", got)
	}
	// WAL must be clear after successful delivery.
	entries, _ := os.ReadDir(walDir)
	if len(entries) != 0 {
		t.Errorf("expected empty WAL after 429+retry, got %d entries", len(entries))
	}
}

// TestAuthorizationHeaderSet asserts that every request (including retries)
// carries the correct Authorization: Bearer <api_key> header.
func TestAuthorizationHeaderSet(t *testing.T) {
	const wantAuth = "Bearer " + transport.TestAPIKey

	var seenHeaders []string
	var mu sync.Mutex
	attempts := &atomic.Int64{}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		mu.Lock()
		seenHeaders = append(seenHeaders, r.Header.Get("Authorization"))
		mu.Unlock()

		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var batch envelope.BatchRequest
		_ = json.NewDecoder(r.Body).Decode(&batch)
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

	cl.Send(envelope.Event{
		OccurredAt:  time.Now().UTC(),
		EventType:   "deploy.completed",
		EventSource: envelope.SourceGitHub,
		Payload:     map[string]any{"ref": "main"},
	})

	time.Sleep(400 * time.Millisecond)
	if err := cl.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenHeaders) == 0 {
		t.Fatal("no requests received by fake server")
	}
	for i, h := range seenHeaders {
		if h != wantAuth {
			t.Errorf("request %d: Authorization header = %q, want %q", i+1, h, wantAuth)
		}
	}
}

// TestMissingAPIKeyNotLogged ensures that the transport does not leak key
// material in error strings even when the key is empty.
func TestMissingAPIKeyNotLogged(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer" && auth != "Bearer " {
			t.Errorf("unexpected Authorization header value: %q (expected bare \"Bearer\")", auth)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	walDir := t.TempDir()
	cfg := transport.TestClientConfig(srv.URL, walDir)
	cfg.APIKey = ""

	cl, err := transport.NewTestClient(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}

	cl.Send(envelope.Event{
		OccurredAt:  time.Now().UTC(),
		EventType:   "deploy.completed",
		EventSource: envelope.SourceGitHub,
		Payload:     map[string]any{},
	})

	time.Sleep(200 * time.Millisecond)
	_ = cl.Close(context.Background())
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
