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
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"
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
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("wal open tmp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("wal write tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("wal fsync tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("wal close tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("wal rename: %w", err)
	}
	// fsync the directory so the rename is durable across crashes.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	incWALWrites()
	return nil
}

// walDelete removes a WAL entry once the batch has been successfully delivered.
// The metrics counter is only incremented when a file is actually removed —
// a missing file is treated as a no-op (caller may call delete on an entry
// that walPrune already evicted) and not double-counted.
func walDelete(dir, idempotencyKey string) error {
	path := filepath.Join(dir, idempotencyKey+walExt)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("wal delete: %w", err)
	}
	incWALDeletes()
	return nil
}

// walPrune removes WAL entries older than maxAge and, if the spool exceeds
// maxBytes, deletes oldest-first until under cap. A WAL spool that grows
// without bound is a worse failure mode than dropping ancient batches the
// ingest API would reject as stale anyway.
func walPrune(dir string, maxAge time.Duration, maxBytes int64) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("wal prune readdir: %w", err)
	}
	type fileInfo struct {
		path    string
		size    int64
		modTime time.Time
	}
	var files []fileInfo
	cutoff := time.Now().Add(-maxAge)
	for _, de := range entries {
		if de.IsDir() || filepath.Ext(de.Name()) != walExt {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(dir, de.Name())
		if maxAge > 0 && info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err != nil {
				slog.Warn("wal: prune by age failed", "path", path, "err", err)
				continue
			}
			incWALPrunedByAge()
			slog.Info("wal: pruned aged entry", "path", path, "age", time.Since(info.ModTime()))
			continue
		}
		files = append(files, fileInfo{path: path, size: info.Size(), modTime: info.ModTime()})
	}
	if maxBytes <= 0 {
		return nil
	}
	var total int64
	for _, f := range files {
		total += f.size
	}
	if total <= maxBytes {
		return nil
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.Before(files[j].modTime) })
	for _, f := range files {
		if total <= maxBytes {
			break
		}
		if err := os.Remove(f.path); err != nil {
			slog.Warn("wal: prune by size failed", "path", f.path, "err", err)
			continue
		}
		incWALPrunedBySize()
		slog.Info("wal: pruned oversized spool entry", "path", f.path, "size", f.size)
		total -= f.size
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
			slog.Warn("wal: skipping unreadable entry", "path", path, "err", err)
			continue
		}
		var entry walEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			slog.Warn("wal: skipping corrupt entry", "path", path, "err", err)
			continue
		}
		result = append(result, entry)
	}
	return result, nil
}
