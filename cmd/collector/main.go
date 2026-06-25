// Binary collector is the read-only DORA evidence collector.
// It runs inside the customer's infrastructure and ships normalized events
// to the Operitas control plane via mTLS.
//
// The collector never writes to customer systems. It only reads via GET
// endpoints or passive webhook receivers. All disk writes are scoped to
// /var/lib/operitas/ (WAL and cursor state). Logs are JSON to stdout.
// Prometheus metrics are exposed on :9090/metrics.
//
// Sources (16 implemented):
//
//	poll:    aws.cloudtrail, azure.activity
//	webhook: pagerduty, flux, spacelift, grafana, prometheus
//	hybrid:  github, gitlab, datadog, jira, argocd, bitbucket,
//	         incident.io, opsgenie, servicenow
//
// "hybrid" means webhook receiver preferred; REST polling as fallback.
// Two additional enum values are reserved in the schema but have no source
// package: k8s.audit, vendor.statuspage.
//
// Webhook routing: github (port 8081), gitlab (port 8083), pagerduty (port 8082)
// continue on their dedicated ports. All other webhook sources share a single
// server on WEBHOOK_PORT (default 8090, config key sources.shared_webhook_port).
// See internal/sources/CONTRACT.md and helm/collector/README.md for details.
package main

import (
	"context"
	"flag"
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
	internalrt "operitas.eu/collector/internal/runtime"
	"operitas.eu/collector/internal/sources/argocd"
	"operitas.eu/collector/internal/sources/awscloudtrail"
	"operitas.eu/collector/internal/sources/azureactivity"
	"operitas.eu/collector/internal/sources/bitbucket"
	"operitas.eu/collector/internal/sources/datadog"
	"operitas.eu/collector/internal/sources/flux"
	"operitas.eu/collector/internal/sources/github"
	"operitas.eu/collector/internal/sources/gitlab"
	"operitas.eu/collector/internal/sources/grafana"
	"operitas.eu/collector/internal/sources/incidentio"
	"operitas.eu/collector/internal/sources/jira"
	"operitas.eu/collector/internal/sources/opsgenie"
	"operitas.eu/collector/internal/sources/pagerduty"
	"operitas.eu/collector/internal/sources/prometheus"
	"operitas.eu/collector/internal/sources/servicenow"
	"operitas.eu/collector/internal/sources/spacelift"
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

	os.Exit(run(os.Args[1:]))
}

// run implements the top-level arg routing. It is separated from main so that
// tests can drive the real arg-parsing path with arbitrary []string inputs
// without forking a subprocess.
//
// Mode detection works by scanning args for --emit-event or --drain-dlq before
// any flag.Parse call. This avoids the flag.CommandLine ExitOnError parser
// choking on sub-flags (e.g. --tenant-id) that are not registered globally.
// Both the documented no-separator form:
//
//	collector --emit-event --tenant-id <uuid> ...
//
// and the legacy separator form:
//
//	collector --emit-event -- --tenant-id <uuid> ...
//
// are accepted.
func run(args []string) int {
	switch detectMode(args) {
	case modeDrainDLQ:
		// --drain-dlq: replay all DLQ entries back into the WAL with fresh
		// idempotency keys and exit. Run this after fixing a schema mismatch on
		// the ingest side. The flag is parsed before config so operators can run
		// it without a fully valid config (e.g. in an init container).
		slog.Info("drain-dlq mode: replaying DLQ entries into WAL",
			"dlq_dir", config.DLQDir,
			"wal_dir", config.WALDir,
		)
		if err := transport.DrainDLQ(config.DLQDir, config.WALDir); err != nil {
			slog.Error("drain-dlq failed", "err", err)
			return 1
		}
		slog.Info("drain-dlq complete")
		return 0

	case modeEmitEvent:
		// --emit-event: build one synthetic envelope from the supplied sub-flags and
		// ship it via the transport client, then exit. Used to validate the wire
		// contract against the production control plane without running a full
		// collector. Config comes from env vars (OPERITAS_INGEST_API_KEY,
		// OPERITAS_INGEST_URL, OPERITAS_COLLECTOR_ID); no config file required.
		subArgs := stripModeFlag(args, "--emit-event")
		subFlags := flag.NewFlagSet("emit-event", flag.ContinueOnError)
		f, err := parseEmitEventFlags(subFlags, subArgs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "emit-event: %v\n", err)
			return 2
		}
		if err := validateEmitEventFlags(f); err != nil {
			fmt.Fprintf(os.Stderr, "emit-event: %v\n", err)
			return 2
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		if err := runEmitEvent(ctx, f); err != nil {
			slog.Error("emit-event failed", "err", err)
			return 1
		}
		return 0
	}

	// Normal daemon mode: use the global flag set for the handful of top-level
	// flags and then start the collector.
	daemonFlags := flag.NewFlagSet("collector", flag.ExitOnError)
	daemonFlags.Parse(args) //nolint:errcheck // ExitOnError never returns non-nil

	slog.Info("collector starting", "version", version)

	cfgPath := os.Getenv("OPERITAS_CONFIG_FILE")
	if cfgPath == "" {
		cfgPath = config.DefaultConfigPath
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("configuration error", "err", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	r, err := redact.New(cfg.Redact.HashPII, cfg.Redact.HashKey)
	if err != nil {
		slog.Error("redactor init failed", "err", err)
		return 1
	}

	tcfg := transport.ClientConfig{
		Endpoint:    cfg.Ingest.Endpoint,
		TLSCertFile: cfg.Ingest.TLSCertFile,
		TLSKeyFile:  cfg.Ingest.TLSKeyFile,
		TLSCAFile:   cfg.Ingest.TLSCAFile,
		CollectorID: cfg.CollectorID,
		TenantID:    cfg.TenantID,
		// APIKey is never logged; it is read from OPERITAS_INGEST_API_KEY by config.Load.
		APIKey:             cfg.Ingest.APIKey,
		WALDir:             config.WALDir,
		DLQDir:             config.DLQDir,
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
		return 1
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
			return 1
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ct.Run(ctx); err != nil {
				slog.Error("cloudtrail source exited with error", "err", err)
			}
		}()
	}

	if cfg.Sources.AzureActivity.Enabled {
		az, err := azureactivity.New(cfg.Sources.AzureActivity, r, emit)
		if err != nil {
			slog.Error("azureactivity source init failed", "err", err)
			return 1
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := az.Run(ctx); err != nil {
				slog.Error("azureactivity source exited with error", "err", err)
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

	if cfg.Sources.GitLab.Enabled {
		gl := gitlab.New(cfg.Sources.GitLab, r, emit)

		if cfg.Sources.GitLab.WebhookSecret != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := gl.RunWebhook(ctx); err != nil {
					slog.Error("gitlab webhook server exited with error", "err", err)
				}
			}()
		}

		// Polling fallback runs whenever a token is present; cfg.Token is
		// already required by config.validate when GitLab is enabled.
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := gl.RunPoller(ctx); err != nil {
				slog.Error("gitlab poller exited with error", "err", err)
			}
		}()
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

	// Shared webhook router for all new sources (port 8090 by default).
	// github/gitlab/pagerduty retain their own dedicated ports in this release.
	sharedRouter := internalrt.NewSharedWebhookRouter(cfg.Sources.SharedWebhookPort)
	sharedRouterHasHandlers := false

	if cfg.Sources.Jira.Enabled {
		j := jira.New(cfg.Sources.Jira, r, emit)
		j.Register(sharedRouter)
		sharedRouterHasHandlers = true
		if cfg.Sources.Jira.Token != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := j.RunPoller(ctx); err != nil {
					slog.Error("jira poller exited with error", "err", err)
				}
			}()
		}
	}

	if cfg.Sources.Datadog.Enabled {
		dd := datadog.New(cfg.Sources.Datadog, r, emit)
		dd.Register(sharedRouter)
		sharedRouterHasHandlers = true
		if cfg.Sources.Datadog.APIKey != "" && cfg.Sources.Datadog.AppKey != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := dd.RunPoller(ctx); err != nil {
					slog.Error("datadog poller exited with error", "err", err)
				}
			}()
		}
	}

	if cfg.Sources.Prometheus.Enabled {
		prom := prometheus.New(cfg.Sources.Prometheus, r, emit)
		prom.Register(sharedRouter)
		sharedRouterHasHandlers = true
	}

	if cfg.Sources.Bitbucket.Enabled {
		bb := bitbucket.New(cfg.Sources.Bitbucket, r, emit)
		bb.Register(sharedRouter)
		sharedRouterHasHandlers = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := bb.RunPoller(ctx); err != nil {
				slog.Error("bitbucket poller exited with error", "err", err)
			}
		}()
	}

	if cfg.Sources.IncidentIO.Enabled {
		inc := incidentio.New(cfg.Sources.IncidentIO, r, emit)
		inc.Register(sharedRouter)
		sharedRouterHasHandlers = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := inc.RunPoller(ctx); err != nil {
				slog.Error("incidentio poller exited with error", "err", err)
			}
		}()
	}

	if cfg.Sources.Opsgenie.Enabled {
		og := opsgenie.New(cfg.Sources.Opsgenie, r, emit)
		og.Register(sharedRouter)
		sharedRouterHasHandlers = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := og.RunPoller(ctx); err != nil {
				slog.Error("opsgenie poller exited with error", "err", err)
			}
		}()
	}

	if cfg.Sources.ServiceNow.Enabled {
		sn := servicenow.New(cfg.Sources.ServiceNow, r, emit)
		sn.Register(sharedRouter)
		sharedRouterHasHandlers = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sn.RunPoller(ctx); err != nil {
				slog.Error("servicenow poller exited with error", "err", err)
			}
		}()
	}

	if cfg.Sources.ArgoCD.Enabled {
		acd := argocd.New(cfg.Sources.ArgoCD, r, emit)
		acd.Register(sharedRouter)
		sharedRouterHasHandlers = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := acd.RunPoller(ctx); err != nil {
				slog.Error("argocd poller exited with error", "err", err)
			}
		}()
	}

	if cfg.Sources.Flux.Enabled {
		fl := flux.New(cfg.Sources.Flux, r, emit)
		fl.Register(sharedRouter)
		sharedRouterHasHandlers = true
	}

	if cfg.Sources.Spacelift.Enabled {
		sl := spacelift.New(cfg.Sources.Spacelift, r, emit)
		sl.Register(sharedRouter)
		sharedRouterHasHandlers = true
	}

	if cfg.Sources.Grafana.Enabled {
		gr := grafana.New(cfg.Sources.Grafana, r, emit)
		gr.Register(sharedRouter)
		sharedRouterHasHandlers = true
	}

	// Start the shared router only if at least one source registered a handler.
	// This avoids opening an unnecessary port when no new sources are enabled.
	if sharedRouterHasHandlers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sharedRouter.Run(ctx); err != nil {
				slog.Error("shared webhook router exited with error", "err", err)
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
		"azure_activity_enabled", cfg.Sources.AzureActivity.Enabled,
		"github_enabled", cfg.Sources.GitHub.Enabled,
		"gitlab_enabled", cfg.Sources.GitLab.Enabled,
		"pagerduty_enabled", cfg.Sources.PagerDuty.Enabled,
		"jira_enabled", cfg.Sources.Jira.Enabled,
		"datadog_enabled", cfg.Sources.Datadog.Enabled,
		"prometheus_enabled", cfg.Sources.Prometheus.Enabled,
		"bitbucket_enabled", cfg.Sources.Bitbucket.Enabled,
		"incidentio_enabled", cfg.Sources.IncidentIO.Enabled,
		"opsgenie_enabled", cfg.Sources.Opsgenie.Enabled,
		"servicenow_enabled", cfg.Sources.ServiceNow.Enabled,
		"argocd_enabled", cfg.Sources.ArgoCD.Enabled,
		"flux_enabled", cfg.Sources.Flux.Enabled,
		"spacelift_enabled", cfg.Sources.Spacelift.Enabled,
		"grafana_enabled", cfg.Sources.Grafana.Enabled,
		"shared_webhook_port", cfg.Sources.SharedWebhookPort,
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
	return 0
}

// collectorMode is the operating mode selected by the first recognized flag.
type collectorMode int

const (
	modeDaemon    collectorMode = iota // default: run the full collector daemon
	modeEmitEvent                      // --emit-event: ship one synthetic event and exit
	modeDrainDLQ                       // --drain-dlq: replay DLQ into WAL and exit
)

// detectMode scans args for the first occurrence of --emit-event or --drain-dlq
// (with or without an = suffix) and returns the corresponding mode. A "--"
// separator, if present, is ignored — args after it are sub-flags for the mode.
func detectMode(args []string) collectorMode {
	for _, a := range args {
		switch a {
		case "--emit-event", "-emit-event":
			return modeEmitEvent
		case "--drain-dlq", "-drain-dlq":
			return modeDrainDLQ
		case "--":
			return modeDaemon
		}
	}
	return modeDaemon
}

// stripModeFlag removes the first occurrence of modeFlag from args, strips a
// leading "--" separator if present, and returns the remaining args for the
// sub-FlagSet. This supports both documented forms:
//
//	collector --emit-event --tenant-id uuid ...   (no separator)
//	collector --emit-event -- --tenant-id uuid ... (legacy separator)
func stripModeFlag(args []string, modeFlag string) []string {
	out := make([]string, 0, len(args))
	skippedMode := false
	for _, a := range args {
		if !skippedMode && (a == modeFlag || a == modeFlag[1:]) {
			skippedMode = true
			continue
		}
		if skippedMode && a == "--" {
			// drop the separator; remaining args go straight to sub-FlagSet
			skippedMode = false // already skipped; reset guard so loop continues
			continue
		}
		out = append(out, a)
	}
	return out
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
// (manifest §0 rule 2). Counters are maintained in-memory by the transport
// package and formatted here. A proper client_golang integration is tracked
// as a follow-up once the library is approved.
func metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP operitas_collector_up 1 if the collector is running.\n")
	fmt.Fprintf(w, "# TYPE operitas_collector_up gauge\n")
	fmt.Fprintf(w, "operitas_collector_up 1\n")
	fmt.Fprintf(w, "# HELP operitas_collector_build_info Build version label.\n")
	fmt.Fprintf(w, "# TYPE operitas_collector_build_info gauge\n")
	fmt.Fprintf(w, "operitas_collector_build_info{version=%q} 1\n", version)
	transport.WriteDLQMetrics(w)
	transport.WriteWALMetrics(w)
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
