package runtime

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// RunWebhookServer runs an HTTP server with the given handler at addr until
// ctx is cancelled, then performs a graceful shutdown with a 5s timeout.
// Timeouts mirror the per-source defaults and are tuned for low-volume
// webhook traffic from GitHub / PagerDuty.
func RunWebhookServer(ctx context.Context, addr string, handler http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := srv.Shutdown(shutdownCtx)
		<-errCh
		return err
	case err := <-errCh:
		if err == nil {
			return nil
		}
		return fmt.Errorf("webhook server: %w", err)
	}
}
