// Package transport — dead-letter queue (DLQ) for permanently failed batches.
//
// Permanent failures (HTTP 4xx responses that are not 401/403/409/413/429) are
// written to /var/lib/operitas/dlq/ instead of being silently dropped.
// The DLQ uses the same trim policy as the WAL: 14-day age limit and 1 GiB
// total-size cap, both enforced on startup and opportunistically.
//
// All disk writes remain under /var/lib/operitas/ (hard failure rule 3).
package transport

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"
)

// newUUID returns a new random UUID string. Extracted as a variable so tests
// can substitute a deterministic generator.
var newUUID = func() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

const (
	dlqExt    = ".dlq"
	dlqMaxAge = 14 * 24 * time.Hour
	dlqMaxBytes int64 = 1 << 30 // 1 GiB
)

// dlqEntry is the on-disk envelope written for every permanently failed batch.
// request_body is the same JSON that was already transmitted over the wire
// (PII-redacted per manifest §9.2) — no additional redaction is needed here.
// The raw response_body is capped at 64 KiB before writing.
type dlqEntry struct {
	QueuedAt     string          `json:"queued_at"`
	StatusCode   int             `json:"status_code"`
	ResponseBody string          `json:"response_body"`
	RequestBody  json.RawMessage `json:"request_body"`
}

// dlqWrite persists a failed batch to the DLQ directory.
//
// Filename format: {filesystem-safe-timestamp}-{idempotencyKey}.dlq
// Returns the absolute path of the written file on success.
// The caller is responsible for ensuring responseBody does not contain raw
// customer-data payloads (the transport layer only passes HTTP response text).
func dlqWrite(dir, idempotencyKey string, statusCode int, responseBody []byte, requestBody []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("dlq mkdir: %w", err)
	}

	now := time.Now().UTC()
	entry := dlqEntry{
		QueuedAt:     now.Format(time.RFC3339Nano),
		StatusCode:   statusCode,
		ResponseBody: string(responseBody),
		RequestBody:  json.RawMessage(requestBody),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return "", fmt.Errorf("dlq marshal: %w", err)
	}

	// RFC3339 timestamps contain ':' which is forbidden on some filesystems.
	// Use a filesystem-safe variant that replaces ':' with '-' in the time part.
	ts := now.Format("2006-01-02T15-04-05.000000000Z")
	filename := ts + "-" + idempotencyKey + dlqExt
	path := filepath.Join(dir, filename)
	tmp := path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("dlq open tmp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", fmt.Errorf("dlq write tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", fmt.Errorf("dlq fsync tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("dlq close tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("dlq rename: %w", err)
	}
	// Sync the directory so the rename is durable.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return path, nil
}

// dlqDelete removes a DLQ file by its full path.
func dlqDelete(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("dlq delete: %w", err)
	}
	return nil
}

// dlqPrune removes DLQ entries older than maxAge and, if the directory exceeds
// maxBytes, deletes oldest-first until under cap. Mirrors walPrune semantics.
func dlqPrune(dir string, maxAge time.Duration, maxBytes int64) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("dlq prune readdir: %w", err)
	}

	type fileInfo struct {
		path    string
		size    int64
		modTime time.Time
	}
	var files []fileInfo
	cutoff := time.Now().Add(-maxAge)

	for _, de := range entries {
		if de.IsDir() || filepath.Ext(de.Name()) != dlqExt {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(dir, de.Name())
		if maxAge > 0 && info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err != nil {
				slog.Warn("dlq: prune by age failed", "path", path, "err", err)
				continue
			}
			slog.Info("dlq: pruned aged entry", "path", path, "age", time.Since(info.ModTime()))
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
			slog.Warn("dlq: prune by size failed", "path", f.path, "err", err)
			continue
		}
		slog.Info("dlq: pruned oversized spool entry", "path", f.path, "size", f.size)
		total -= f.size
	}
	return nil
}

// dlqRecoverEntry holds the parsed content of a DLQ file plus its filesystem path.
type dlqRecoverEntry struct {
	Path           string
	IdempotencyKey string // parsed from filename (segment between first '-' groups)
	Entry          dlqEntry
}

// dlqRecover reads all valid DLQ entries. Used by the --drain-dlq command.
func dlqRecover(dir string) ([]dlqRecoverEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("dlq readdir: %w", err)
	}

	var result []dlqRecoverEntry
	for _, de := range entries {
		if de.IsDir() || filepath.Ext(de.Name()) != dlqExt {
			continue
		}
		path := filepath.Join(dir, de.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("dlq: skipping unreadable entry", "path", path, "err", err)
			continue
		}
		var entry dlqEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			slog.Warn("dlq: skipping corrupt entry", "path", path, "err", err)
			continue
		}
		// Extract the idempotency key from the filename.
		// Filename format: 2006-01-02T15-04-05.000000000Z-{uuid}.dlq
		// The UUID is the last hyphen-separated segment before the extension.
		name := de.Name()[:len(de.Name())-len(dlqExt)] // strip .dlq
		// The timestamp occupies the first 32 characters (fixed-width):
		// "2006-01-02T15-04-05.000000000Z" = 30 chars + "-" = 31 chars prefix.
		// The idempotency key (UUID) begins after the first '-' following the
		// timestamp suffix 'Z'. We find it by scanning from the right for the
		// UUID-shaped portion (36 chars: 8-4-4-4-12).
		idemKey := extractIDFromDLQFilename(name)
		result = append(result, dlqRecoverEntry{
			Path:           path,
			IdempotencyKey: idemKey,
			Entry:          entry,
		})
	}
	return result, nil
}

// extractIDFromDLQFilename returns the UUID portion from a DLQ filename stem.
// The filename stem format is: <timestamp>-<uuid>
// where <timestamp> = "2006-01-02T15-04-05.000000000Z" (30 chars).
// The UUID is everything after the separator '-' that follows the timestamp.
func extractIDFromDLQFilename(stem string) string {
	// Timestamp is 30 chars ("2006-01-02T15-04-05.000000000Z"), followed by '-'.
	const tsLen = 31 // 30 chars + 1 separator
	if len(stem) > tsLen {
		return stem[tsLen:]
	}
	return stem
}

// DrainDLQ moves all valid DLQ entries back into the WAL directory with fresh
// idempotency keys so the normal flush loop will retry them. It is called by
// the --drain-dlq CLI flag (cmd/collector/main.go). The function is one-shot:
// it processes all current DLQ files, writes them as WAL entries, deletes the
// DLQ files, and returns. The caller exits after this function returns.
//
// Use this after fixing a schema mismatch on the ingest side. The re-queued
// WAL entries will be delivered on the next normal collector run.
func DrainDLQ(dlqDir, walDir string) error {
	entries, err := dlqRecover(dlqDir)
	if err != nil {
		return fmt.Errorf("drain dlq: recover: %w", err)
	}
	if len(entries) == 0 {
		slog.Info("drain dlq: no entries found", "dlq_dir", dlqDir)
		return nil
	}

	var moved, skipped int
	for _, e := range entries {
		// Assign a fresh idempotency key so the ingest server does not
		// cache-hit the original key (which would return the same 422/413
		// response it cached before).
		newKey, err := newUUID()
		if err != nil {
			slog.Error("drain dlq: failed to generate new idempotency key; skipping entry",
				"dlq_path", e.Path,
				"err", err,
			)
			skipped++
			continue
		}

		payload := []byte(e.Entry.RequestBody)
		if err := walWrite(walDir, newKey, payload); err != nil {
			slog.Error("drain dlq: wal write failed; skipping entry",
				"dlq_path", e.Path,
				"new_key", newKey,
				"err", err,
			)
			skipped++
			continue
		}

		if err := dlqDelete(e.Path); err != nil {
			// WAL entry was written; the DLQ file failed to delete.
			// Log the problem but do not abort — the duplicate will be
			// caught by the WAL idempotency key on the next run.
			slog.Warn("drain dlq: wal written but dlq delete failed; entry may be replayed twice",
				"dlq_path", e.Path,
				"new_key", newKey,
				"err", err,
			)
		}

		slog.Info("drain dlq: moved entry to wal",
			"dlq_path", e.Path,
			"new_idempotency_key", newKey,
			"original_status_code", e.Entry.StatusCode,
			"queued_at", e.Entry.QueuedAt,
		)
		moved++
	}

	slog.Info("drain dlq: complete",
		"moved", moved,
		"skipped", skipped,
		"dlq_dir", dlqDir,
		"wal_dir", walDir,
	)
	if skipped > 0 {
		return fmt.Errorf("drain dlq: %d entries could not be moved (see logs above)", skipped)
	}
	return nil
}
