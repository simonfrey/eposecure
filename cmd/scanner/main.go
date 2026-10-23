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

	if cmd == "run-once" {
		return p.Run(ctx, opts)
	}

	hours, err := strconv.Atoi(env("SCAN_INTERVAL_HOURS", "24"))
	if err != nil || hours < 1 {
		return fmt.Errorf("SCAN_INTERVAL_HOURS must be a positive integer")
	}
	interval := time.Duration(hours) * time.Hour
	for {
		next := time.Now().Add(interval)
		if err := p.Run(ctx, opts); err != nil {
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

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
