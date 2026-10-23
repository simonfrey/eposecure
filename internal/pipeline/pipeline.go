// Package pipeline runs one scan: discover → scan → diff → store.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/diff"
	"github.com/simonfrey/exposure-scanner/internal/model"
	"github.com/simonfrey/exposure-scanner/internal/registry"
	"github.com/simonfrey/exposure-scanner/internal/store"
)

type Pipeline struct {
	discoverers []registry.Discoverer
	scanners    []registry.Scanner
	exclude     []string
	store       *store.Store
}

// New resolves all configured modules, failing fast on unknown names or bad options.
func New(cfg *config.Config, st *store.Store) (*Pipeline, error) {
	d, err := registry.Discoverers(cfg.Discovery)
	if err != nil {
		return nil, err
	}
	s, err := registry.Scanners(cfg.Scanners)
	if err != nil {
		return nil, err
	}
	return &Pipeline{discoverers: d, scanners: s, exclude: cfg.Exclude, store: st}, nil
}

// Run executes one full run and records it. A failing module fails the
// whole run and skips the diff: a partial inventory would look like closed ports.
func (p *Pipeline) Run(ctx context.Context) error {
	id, release, err := p.store.StartRun(ctx)
	if err != nil {
		return err
	}
	defer release()
	log := slog.With("run", id)
	start := time.Now()

	snap, err := p.scan(ctx, log)
	if err != nil {
		log.Error("run failed", "err", err)
		return errors.Join(err, p.store.FailRun(context.WithoutCancel(ctx), id, err))
	}
	prev, err := p.store.LastSnapshot(ctx)
	if err != nil {
		return err
	}
	events := diff.Compute(prev, snap)
	if err := p.store.FinishRun(ctx, id, snap, events); err != nil {
		return err
	}
	log.Info("run finished", "took", time.Since(start).Round(time.Second), "assets", len(snap.Assets),
		"endpoints", len(snap.Endpoints), "findings", len(snap.Findings), "events", len(events))
	return nil
}

func (p *Pipeline) scan(ctx context.Context, log *slog.Logger) (model.Snapshot, error) {
	var snap model.Snapshot

	results := make([][]model.Asset, len(p.discoverers))
	g, gctx := errgroup.WithContext(ctx)
	for i, d := range p.discoverers {
		g.Go(func() error {
			assets, err := d.Discover(gctx)
			if err != nil {
				return fmt.Errorf("discovery %s: %w", d.Name(), err)
			}
			for j := range assets {
				assets[j].Source = d.Name()
				assets[j].Target = normalize(assets[j].Target)
			}
			log.Info("discovered", "module", d.Name(), "assets", len(assets))
			results[i] = assets
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return snap, err
	}
	snap.Assets = slices.Concat(results...)

	sc := &model.ScanContext{Targets: targets(snap.Assets, p.exclude)}
	log.Info("scanning", "targets", len(sc.Targets))
	for _, s := range p.scanners {
		if err := s.Scan(ctx, sc); err != nil {
			return snap, fmt.Errorf("scanner %s: %w", s.Name(), err)
		}
		log.Info("scanned", "module", s.Name(), "endpoints", len(sc.Endpoints), "findings", len(sc.Findings))
	}
	snap.Endpoints, snap.Findings = sc.Endpoints, sc.Findings
	return snap, nil
}

// targets returns the unique scan targets, minus excluded IPs, CIDRs and hostnames.
func targets(assets []model.Asset, exclude []string) []string {
	var out []string
	for _, a := range assets {
		if a.Target != "" && !excluded(a.Target, exclude) {
			out = append(out, a.Target)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func excluded(target string, exclude []string) bool {
	ip, ipErr := netip.ParseAddr(target)
	for _, ex := range exclude {
		if strings.EqualFold(ex, target) {
			return true
		}
		if prefix, err := netip.ParsePrefix(ex); err == nil && ipErr == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// normalize reduces URLs (e.g. Cloud Run) to their host and lowercases hostnames.
func normalize(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			target = u.Hostname()
		}
	}
	return strings.TrimSuffix(strings.ToLower(target), ".")
}
