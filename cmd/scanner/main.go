// Command scanner discovers public endpoints and scans them.
//
//	scanner run-once [--accept-drift]   one run, then exit
//	scanner serve                       run now and then every SCAN_INTERVAL_HOURS
//
// --accept-drift stores a run even if endpoints dropped sharply or a
// discovery source returned nothing (see max_endpoint_drop_pct).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/pipeline"
	"github.com/simonfrey/exposure-scanner/internal/store"
)

func main() {
	args := strings.Join(os.Args[1:], " ")
	if args != "run-once" && args != "run-once --accept-drift" && args != "serve" {
		fmt.Fprintln(os.Stderr, "usage: scanner run-once [--accept-drift] | serve")
		os.Exit(2)
	}
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning) // quiet the ProjectDiscovery libraries

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1], pipeline.RunOptions{AcceptDrift: strings.HasSuffix(args, "--accept-drift")}); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd string, opts pipeline.RunOptions) error {
	cfg, err := config.Load(env("CONFIG_PATH", "/config/config.yaml"))
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	st, err := store.Open(ctx, env("DATABASE_URL", ""))
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()
	if err := st.SetBaseline(ctx, os.Getenv("BASELINE_RUN_ID")); err != nil {
		return err
	}
	p, err := pipeline.New(cfg, st)
	if err != nil {
		return err
	}
	interval, err := hours("SCAN_INTERVAL_HOURS", "24")
	if err != nil {
		return err
	}
	timeout, err := hours("RUN_TIMEOUT_HOURS", "6")
	if err != nil {
		return err
	}
	every, err := strconv.Atoi(env("PROGRESS_LOG_SECONDS", "30"))
	if err != nil || every < 1 {
		return fmt.Errorf("PROGRESS_LOG_SECONDS must be a positive integer")
	}
	opts.ProgressEvery = time.Duration(every) * time.Second
	// A hung module must not block all future runs; the timed-out run is
	// recorded as failed and alerts.
	runOnce := func() error {
		rctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return p.Run(rctx, opts)
	}

	if cmd == "run-once" {
		return runOnce()
	}
	for {
		next := time.Now().Add(interval)
		if err := runOnce(); err != nil {
			slog.Error("run failed, retrying at next interval", "err", err) // recorded in runs table, Grafana alerts
		}
		slog.Info("sleeping", "next_run", next.Format(time.RFC3339))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Until(next)):
		}
	}
}

func hours(key, def string) (time.Duration, error) {
	h, err := strconv.Atoi(env(key, def))
	if err != nil || h < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return time.Duration(h) * time.Hour, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
