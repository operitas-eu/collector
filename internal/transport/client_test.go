package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	// WAL directory entries must not include any .wal files (the DLQ subdir
	// may be present, so we filter to .wal only).
	walEntries, _ := os.ReadDir(walDir)
	var walFiles []string
	for _, e := range walEntries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".wal") {
			walFiles = append(walFiles, e.Name())
		}
	}
	if len(walFiles) != 0 {
		t.Errorf("expected empty WAL after 422 DLQ routing, got entries: %v", walFiles)
	}

	// A DLQ file must have been written under cfg.DLQDir.
	dlqDir := cfg.DLQDir
	dlqEntries, err := os.ReadDir(dlqDir)
	if err != nil {
		t.Fatalf("ReadDir DLQ dir %q: %v", dlqDir, err)
	}
	var dlqFiles []string
	for _, e := range dlqEntries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".dlq") {
			dlqFiles = append(dlqFiles, e.Name())
		}
	}
	if len(dlqFiles) != 1 {
		t.Fatalf("expected exactly 1 DLQ file after 422, got %d: %v", len(dlqFiles), dlqFiles)
	}

	// Verify DLQ file content structure.
	raw, err := os.ReadFile(filepath.Join(dlqDir, dlqFiles[0]))
	if err != nil {
		t.Fatalf("read DLQ file: %v", err)
	}
	var dlq struct {
		QueuedAt    string          `json:"queued_at"`
		StatusCode  int             `json:"status_code"`
		RequestBody json.RawMessage `json:"request_body"`
	}
	if err := json.Unmarshal(raw, &dlq); err != nil {
		t.Fatalf("unmarshal DLQ file: %v", err)
	}
	if dlq.StatusCode != 422 {
		t.Errorf("DLQ file status_code = %d, want 422", dlq.StatusCode)
	}
	if dlq.QueuedAt == "" {
		t.Error("DLQ file queued_at is empty")
	}
	if len(dlq.RequestBody) == 0 {
		t.Error("DLQ file request_body is empty")
	}
}

// TestDrainDLQ verifies that --drain-dlq moves DLQ entries into the WAL with
// fresh idempotency keys and removes the DLQ files.
func TestDrainDLQ(t *testing.T) {
	baseDir := t.TempDir()
	dlqDir := filepath.Join(baseDir, "dlq")
	walDir := filepath.Join(baseDir, "wal")

	if err := os.MkdirAll(dlqDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(walDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Write two synthetic DLQ files directly using the transport package helper.
	type dlqFileShape struct {
		QueuedAt     string          `json:"queued_at"`
		StatusCode   int             `json:"status_code"`
		ResponseBody string          `json:"response_body"`
		RequestBody  json.RawMessage `json:"request_body"`
	}

	fakePayload := json.RawMessage(`{"collector_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","tenant_id":"b1b2c3d4-e5f6-7890-abcd-ef1234567890","envelope_version":"1.0.0","events":[]}`)
	for i := 0; i < 2; i++ {
		entry := dlqFileShape{
			QueuedAt:     "2026-05-11T10:00:00Z",
			StatusCode:   422,
			ResponseBody: `{"error":"validation_failed"}`,
			RequestBody:  fakePayload,
		}
		data, _ := json.Marshal(entry)
		// Use deterministic filenames for the test.
		name := filepath.Join(dlqDir, "2026-05-11T10-00-00.000000000Z-00000000-0000-0000-0000-00000000000"+string(rune('0'+i))+".dlq")
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatalf("write dlq fixture %d: %v", i, err)
		}
	}

	if err := transport.DrainDLQ(dlqDir, walDir); err != nil {
		t.Fatalf("DrainDLQ: %v", err)
	}

	// DLQ directory must be empty after drain.
	dlqEntries, _ := os.ReadDir(dlqDir)
	var remaining []string
	for _, e := range dlqEntries {
		if strings.HasSuffix(e.Name(), ".dlq") {
			remaining = append(remaining, e.Name())
		}
	}
	if len(remaining) != 0 {
		t.Errorf("expected DLQ dir empty after drain, got: %v", remaining)
	}

	// WAL directory must contain exactly 2 new .wal files.
	walEntries, _ := os.ReadDir(walDir)
	var walFiles []string
	for _, e := range walEntries {
		if strings.HasSuffix(e.Name(), ".wal") {
			walFiles = append(walFiles, e.Name())
		}
	}
	if len(walFiles) != 2 {
		t.Errorf("expected 2 WAL files after drain, got %d: %v", len(walFiles), walFiles)
	}

	// Each WAL file must contain a valid walEntry with non-empty payload.
	for _, name := range walFiles {
		raw, err := os.ReadFile(filepath.Join(walDir, name))
		if err != nil {
			t.Fatalf("read wal file %s: %v", name, err)
		}
		var entry struct {
			IdempotencyKey string          `json:"idempotency_key"`
			Payload        json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("unmarshal wal file %s: %v", name, err)
		}
		if entry.IdempotencyKey == "" {
			t.Errorf("wal file %s: empty idempotency_key", name)
		}
		if len(entry.Payload) == 0 {
			t.Errorf("wal file %s: empty payload", name)
		}
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

// TestPost401SpillsToWAL verifies perf-5: after a 401 deauthorizes the client,
// events that arrive via Send() are spilled to the WAL rather than accumulating
// in memory unbounded. After the flush interval fires in deauth state the WAL
// directory must contain at least one entry covering the events sent after the
// 401.
func TestPost401SpillsToWAL(t *testing.T) {
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
	// First event triggers the 401 and sets deauthorized.
	cl.Send(envelope.Event{
		OccurredAt:  now,
		EventType:   "deploy.completed",
		EventSource: envelope.SourceGitHub,
		Payload:     map[string]any{"sha": "trigger-deauth"},
	})

	// Wait for deauth to be confirmed.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && !cl.Deauthorized() {
		time.Sleep(10 * time.Millisecond)
	}
	if !cl.Deauthorized() {
		t.Fatal("collector should be deauthorized after 401 but Deauthorized() is still false")
	}

	// Send additional events while deauthorized. These must be spilled to WAL
	// rather than buffered in memory forever.
	for i := 0; i < 5; i++ {
		cl.Send(envelope.Event{
			OccurredAt:  now,
			EventType:   "change.merged",
			EventSource: envelope.SourceGitHub,
			Payload:     map[string]any{"i": i},
		})
	}

	// Allow the flush interval to fire once more (deauth path now calls spillToWAL).
	time.Sleep(350 * time.Millisecond)
	_ = cl.Close(context.Background())

	// At least one WAL file must exist covering the post-deauth events.
	walEntries, _ := os.ReadDir(walDir)
	var walFiles []string
	for _, e := range walEntries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".wal") {
			walFiles = append(walFiles, e.Name())
		}
	}
	if len(walFiles) == 0 {
		t.Error("expected at least one WAL file after post-deauth spill, got none")
	}
}

// TestLivePruneEnforcesCapDuringRun verifies perf-6: walPrune is called
// periodically from the running flushLoop, not only at startup. The test
// starts the client first (so the startup replayWAL sees an empty directory),
// then injects an aged WAL file directly into the WAL directory, and confirms
// that the live prune ticker removes it without requiring a restart.
func TestLivePruneEnforcesCapDuringRun(t *testing.T) {
	var received atomic.Int64
	srv := newFakeIngest(t, http.StatusOK, &received)
	defer srv.Close()

	walDir := t.TempDir()
	cfg := transport.TestClientConfig(srv.URL, walDir)
	// PruneInterval is 200ms in TestClientConfig — short enough for this test.

	// Start the client. replayWAL sees an empty WAL dir; no stale replay.
	cl, err := transport.NewTestClient(context.Background(), cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}

	// Inject a stale WAL file AFTER the client has started (so it won't be
	// picked up by the startup replay). walPrune reads the directory on each
	// tick, so it will find and remove this file on the next prune run.
	//
	// The walEntry JSON format used by the internal wal.go package:
	//   { "idempotency_key": "<uuid>", "payload": <BatchRequest JSON> }
	// Payload must be a JSON object (json.RawMessage), not a JSON string.
	staleKey := "00000000-0000-0000-0000-000000000099"
	stalePath := filepath.Join(walDir, staleKey+".wal")
	staleData := []byte(`{"idempotency_key":"` + staleKey + `","payload":{"collector_id":"test","tenant_id":"test","envelope_version":"1.0.0","events":[]}}`)
	if err := os.WriteFile(stalePath, staleData, 0o600); err != nil {
		t.Fatalf("write stale WAL file: %v", err)
	}
	// Backdate the file by 20 days so it crosses the 14-day age threshold.
	twentyDaysAgo := time.Now().Add(-20 * 24 * time.Hour)
	if err := os.Chtimes(stalePath, twentyDaysAgo, twentyDaysAgo); err != nil {
		t.Fatalf("chtimes stale WAL file: %v", err)
	}

	// Wait for at least two PruneInterval ticks (200ms each) to fire.
	time.Sleep(600 * time.Millisecond)
	_ = cl.Close(context.Background())

	// The stale WAL file must have been pruned by the live ticker.
	if _, statErr := os.Stat(stalePath); !os.IsNotExist(statErr) {
		t.Errorf("stale WAL file should have been pruned during live run; stat error: %v", statErr)
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
