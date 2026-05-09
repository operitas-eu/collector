// Package runtime provides shared helpers for source pollers and webhook
// receivers that would otherwise duplicate the same goroutine scaffolding
// across every source package.
package runtime

import (
	"context"
	"log/slog"
	"time"
)

// PollLoop runs fn at the given interval until ctx is cancelled. fn is
// invoked once immediately; errors are logged with name as the source label
// and never abort the loop.
func PollLoop(ctx context.Context, interval time.Duration, name string, fn func(context.Context) error) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := fn(ctx); err != nil {
		slog.Error("poll error", "source", name, "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := fn(ctx); err != nil {
				slog.Error("poll error", "source", name, "err", err)
			}
		}
	}
}
