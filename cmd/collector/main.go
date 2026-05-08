// Binary collector is the read-only DORA evidence collector.
// It runs inside the customer's infrastructure and ships normalized events
// to the Operitas control plane via mTLS.
//
// The collector never writes to customer systems. It only reads:
//   - AWS S3 (CloudTrail log files) via s3:ListObjectsV2 + s3:GetObject
//   - GitHub REST API (PRs, deployments) via GET endpoints
//   - GitHub webhook payloads (passive HTTP listener)
//   - PagerDuty webhook payloads (passive HTTP listener)
//
// All disk writes are scoped to /var/lib/operitas/ (WAL and cursor state).
// Logs are JSON to stdout; the container runtime handles capture and rotation.
// Prometheus metrics are exposed on :9090/metrics.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"operitas.eu/collector/internal/config"
	"operitas.eu/collector/internal/envelope"
	"operitas.eu/collector/internal/redact"
	"operitas.eu/collector/internal/sources/awscloudtrail"
	"operitas.eu/collector/internal/sources/github"
	"operitas.eu/collector/internal/sources/pagerduty"
	"operitas.eu/collector/internal/transport"
)

// version is set at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "dev"

func main() {
	// Structured JSON logs to stdout only. Never write logs to disk.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel(),
	})))

	slog.Info("collector starting", "version", version)

	cfgPath := os.Getenv("OPERITAS_CONFIG_FILE")
	if cfgPath == "" {
		cfgPath = config.DefaultConfigPath
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("configuration error", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	r, err := redact.New(cfg.Redact.HashPII, cfg.Redact.HashKey)
	if err != nil {
		slog.Error("redactor init failed", "err", err)
		os.Exit(1)
	}

	tcfg := transport.ClientConfig{
		Endpoint:           cfg.Ingest.Endpoint,
		TLSCertFile:        cfg.Ingest.TLSCertFile,
		TLSKeyFile:         cfg.Ingest.TLSKeyFile,
		TLSCAFile:          cfg.Ingest.TLSCAFile,
		CollectorID:        cfg.CollectorID,
		TenantID:           cfg.TenantID,
		WALDir:             config.WALDir,
		BatchMaxEvents:     cfg.Ingest.BatchMaxEvents,
		BatchMaxBytes:      cfg.Ingest.BatchMaxBytes,
		BatchFlushInterval: cfg.Ingest.BatchFlushInterval,
		BackoffInitial:     cfg.Ingest.BackoffInitial,
		BackoffMax:         cfg.Ingest.BackoffMax,
	}

	// NewClient also replays any WAL entries from a previous run.
	client, err := transport.NewClient(ctx, tcfg)
	if err != nil {
		slog.Error("transport client init failed", "err", err)
		os.Exit(1)
	}

	// emit is the single callback all source packages use to hand off a
	// normalized event. Injected at construction so sources do not depend
	// on the transport package directly.
	emit := func(ev envelope.Event) { client.Send(ev) }

	var wg sync.WaitGroup

	if cfg.Sources.CloudTrail.Enabled {
		ct, err := awscloudtrail.New(ctx, cfg.Sources.CloudTrail, r, emit)
		if err != nil {
			slog.Error("cloudtrail source init failed", "err", err)
			os.Exit(1)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ct.Run(ctx); err != nil {
				slog.Error("cloudtrail source exited with error", "err", err)
			}
		}()
	}

	if cfg.Sources.GitHub.Enabled {
		gh := github.New(cfg.Sources.GitHub, r, emit)

		if cfg.Sources.GitHub.WebhookSecret != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := gh.RunWebhook(ctx); err != nil {
					slog.Error("github webhook server exited with error", "err", err)
				}
			}()
		}

		if cfg.Sources.GitHub.Org != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := gh.RunPoller(ctx); err != nil {
					slog.Error("github poller exited with error", "err", err)
				}
			}()
		}
	}

	if cfg.Sources.PagerDuty.Enabled {
		pd := pagerduty.New(cfg.Sources.PagerDuty, r, emit)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pd.Run(ctx); err != nil {
				slog.Error("pagerduty webhook server exited with error", "err", err)
			}
		}()
	}

	// Metrics server on a dedicated port. NetworkPolicy restricts access to
	// within-cluster Prometheus scrapers only.
	metricsMux := http.NewServeMux()
	metricsMux.HandleFunc("/metrics", metricsHandler)
	metricsMux.HandleFunc("/healthz", healthzHandler)
	metricsSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Metrics.Port),
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server error", "err", err)
		}
	}()

	slog.Info("collector running",
		"tenant_id", cfg.TenantID,
		"collector_id", cfg.CollectorID,
		"cloudtrail_enabled", cfg.Sources.CloudTrail.Enabled,
		"github_enabled", cfg.Sources.GitHub.Enabled,
		"pagerduty_enabled", cfg.Sources.PagerDuty.Enabled,
	)

	<-ctx.Done()
	slog.Info("collector shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = metricsSrv.Shutdown(shutdownCtx)

	if err := client.Close(context.Background()); err != nil {
		slog.Error("transport close error", "err", err)
	}

	wg.Wait()
	slog.Info("collector stopped")
}

func slogLevel() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// metricsHandler serves minimal Prometheus text-format metrics.
// The prometheus/client_golang library is not yet an approved dependency
// (manifest §0 rule 2). This stub satisfies the NetworkPolicy template
// and the Helm readiness probe; a proper metrics integration is tracked as
// a follow-up once the library is approved.
func metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP operitas_collector_up 1 if the collector is running.\n")
	fmt.Fprintf(w, "# TYPE operitas_collector_up gauge\n")
	fmt.Fprintf(w, "operitas_collector_up 1\n")
	fmt.Fprintf(w, "# HELP operitas_collector_build_info Build version label.\n")
	fmt.Fprintf(w, "# TYPE operitas_collector_build_info gauge\n")
	fmt.Fprintf(w, "operitas_collector_build_info{version=%q} 1\n", version)
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
