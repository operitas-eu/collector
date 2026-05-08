// Package transport provides the mTLS client, batch buffer, exponential backoff
// retry loop, and on-disk WAL spool that ship events to the ingest service.
//
// All disk writes are scoped to /var/lib/operitas/wal/ (hard failure rule 3).
// The WAL uses one file per batch (named by idempotency key) so that a restart
// can replay any batch that was not yet acknowledged by the server.
package transport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const walExt = ".wal"

// walEntry is the on-disk record for one pending batch.
type walEntry struct {
	IdempotencyKey string          `json:"idempotency_key"`
	Payload        json.RawMessage `json:"payload"`
}

// walWrite persists a batch to the WAL directory before attempting delivery.
// The file name is the idempotency key so that it is both unique and
// recoverable on restart.
func walWrite(dir, idempotencyKey string, payload []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("wal mkdir: %w", err)
	}
	entry := walEntry{IdempotencyKey: idempotencyKey, Payload: json.RawMessage(payload)}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("wal marshal: %w", err)
	}
	path := filepath.Join(dir, idempotencyKey+walExt)
	// Write to a temp file then rename for atomicity.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("wal write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("wal rename: %w", err)
	}
	return nil
}

// walDelete removes a WAL entry once the batch has been successfully delivered.
func walDelete(dir, idempotencyKey string) error {
	path := filepath.Join(dir, idempotencyKey+walExt)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("wal delete: %w", err)
	}
	return nil
}

// walRecover reads all pending WAL entries. Called on startup to replay
// batches that were written but not acknowledged before a crash.
func walRecover(dir string) ([]walEntry, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("wal mkdir on recover: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("wal readdir: %w", err)
	}
	var result []walEntry
	for _, de := range entries {
		if de.IsDir() || filepath.Ext(de.Name()) != walExt {
			continue
		}
		path := filepath.Join(dir, de.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			// Log and skip; do not abort recovery because of one corrupt entry.
			continue
		}
		var entry walEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		result = append(result, entry)
	}
	return result, nil
}
