// Package runtime provides shared helpers for source pollers and webhook receivers.
// This file implements the shared webhook router — a single HTTP server that all
// webhook-enabled sources register handlers on. Using one port (WEBHOOK_PORT,
// default 8090) avoids allocating a separate port per source.
//
// Migration note: the existing github (8081), gitlab (8083), and pagerduty (8082)
// sources continue to run on their own dedicated ports until they are explicitly
// migrated to RegisterWebhookHandler. New sources (jira, datadog, prometheus, and
// the 8 stubs) use the shared router exclusively. The transitional state is
// documented in helm/collector/README.md.
package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// SharedWebhookRouter is a single HTTP server that multiple sources register
// path handlers on. Each source calls RegisterWebhookHandler to add its path
// (e.g. "/webhook/jira") before the router is started with Run.
//
// The router must not be started before all handlers are registered. In practice,
// construct it, call Register for each enabled source, then call Run once in the
// main goroutine.
type SharedWebhookRouter struct {
	mux  *http.ServeMux
	port int
}

// NewSharedWebhookRouter creates a router that listens on the given port.
// If port is 0 the caller must set it before calling Run.
func NewSharedWebhookRouter(port int) *SharedWebhookRouter {
	mux := http.NewServeMux()
	// Built-in health check for the shared router itself.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return &SharedWebhookRouter{mux: mux, port: port}
}

// RegisterWebhookHandler registers handler at the given path. path must begin
// with a forward slash (e.g. "/webhook/jira"). Duplicate registrations panic
// because they indicate a source wiring error in main.go.
func (r *SharedWebhookRouter) RegisterWebhookHandler(path string, handler http.HandlerFunc) {
	slog.Debug("shared webhook router: registering handler", "path", path)
	r.mux.HandleFunc(path, handler)
}

// Run starts the HTTP server and blocks until ctx is cancelled. It performs a
// graceful 5-second shutdown on context cancellation, mirroring RunWebhookServer.
func (r *SharedWebhookRouter) Run(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", r.port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           r.mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	slog.Info("shared webhook router starting", "addr", addr)

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
		return fmt.Errorf("shared webhook router: %w", err)
	}
}
