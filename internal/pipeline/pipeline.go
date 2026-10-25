// Package pipeline runs one scan: discover → scan → verify → diff → store.
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
	maxDropPct  int
	store       *store.Store
}

// RunOptions change the behavior of a single run.
type RunOptions struct {
	// AcceptDrift stores the run even if endpoints dropped sharply or a
	// discovery source came back empty, e.g. after a real decommission.
	AcceptDrift bool
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
	for _, sc := range s {
		if sa, ok := sc.(registry.StoreAware); ok {
			sa.SetStore(st)
		}
	}
	return &Pipeline{discoverers: d, scanners: s, exclude: cfg.Exclude, maxDropPct: cfg.MaxEndpointDropPct, store: st}, nil
}

// Run executes one full run and records it. A failing module fails the
// whole run and skips the diff: a partial inventory would look like closed ports.
// What was gathered until then is still stored under the failed run.
func (p *Pipeline) Run(ctx context.Context, opts RunOptions) error {
	id, release, err := p.store.StartRun(ctx)
	if err != nil {
		return err
	}
	defer release()
	log := slog.With("run", id)
	start := time.Now()

	snap, events, err := p.run(ctx, log, opts)
	if err == nil {
		err = p.store.FinishRun(ctx, id, snap, events)
	}
	if err != nil {
		log.Error("run failed", "err", err)
		return errors.Join(err, p.store.FailRun(context.WithoutCancel(ctx), id, err, snap))
	}
	log.Info("run finished", "took", time.Since(start).Round(time.Second), "assets", len(snap.Assets),
		"endpoints", len(snap.Endpoints), "findings", len(snap.Findings), "events", len(events))
	return nil
}

func (p *Pipeline) run(ctx context.Context, log *slog.Logger, opts RunOptions) (model.Snapshot, []model.Event, error) {
	prev, err := p.store.LastSnapshot(ctx)
	if err != nil {
		return model.Snapshot{}, nil, err
	}
	snap, names, err := p.scan(ctx, log)
	if err != nil {
		return snap, nil, err
	}
	if restored, findings := stillOpen(ctx, prev, snap.Endpoints, names); len(restored) > 0 {
		log.Warn("endpoints missed by the scan still accept connections, keeping them", "count", len(restored))
		snap.Endpoints = append(snap.Endpoints, restored...)
		snap.Findings = append(snap.Findings, findings...)
	}
	if !opts.AcceptDrift {
		if err := p.checkDrift(prev, snap); err != nil {
			return snap, nil, fmt.Errorf("%w; if this is expected, run once with --accept-drift", err)
		}
	}
	return snap, diff.Compute(prev, snap), nil
}

// scan returns the snapshot and the scanned names per IP.
func (p *Pipeline) scan(ctx context.Context, log *slog.Logger) (model.Snapshot, map[string][]string, error) {
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
	err := g.Wait()
	snap.Assets = slices.Concat(results...) // on error: what the other sources found
	if err != nil {
		return snap, nil, err
	}

	scan, takeover := splitTakeover(snap.Assets)
	sc := &model.ScanContext{TakeoverCandidates: targets(takeover, p.exclude)}
	sc.Targets, sc.Names = resolve(ctx, log, targets(scan, p.exclude), p.exclude)
	log.Info("scanning", "ips", len(sc.Targets), "takeover_candidates", len(sc.TakeoverCandidates))
	for _, s := range p.scanners {
		if err := s.Scan(ctx, sc); err != nil {
			snap.Endpoints, snap.Findings = sc.Endpoints, unique(sc.Findings)
			return snap, nil, fmt.Errorf("scanner %s: %w", s.Name(), err)
		}
		log.Info("scanned", "module", s.Name(), "endpoints", len(sc.Endpoints), "findings", len(sc.Findings))
	}
	snap.Endpoints, snap.Findings = sc.Endpoints, unique(sc.Findings)
	return snap, sc.Names, nil
}

// splitTakeover separates hostnames that only have a dangling CNAME (kind
// "takeover"): they cannot be port-scanned, only checked for takeover.
func splitTakeover(assets []model.Asset) (scan, takeover []model.Asset) {
	for _, a := range assets {
		if a.Kind == "takeover" {
			takeover = append(takeover, a)
		} else {
			scan = append(scan, a)
		}
	}
	return scan, takeover
}

// unique drops repeated findings (same id at the same place), which happens
// when scanners overlap, e.g. two nuclei passes that both include medium.
func unique(findings []model.Finding) []model.Finding {
	seen := map[string]bool{}
	return slices.DeleteFunc(findings, func(f model.Finding) bool {
		k := f.TemplateID + "|" + f.MatchedAt
		dup := seen[k]
		seen[k] = true
		return dup
	})
}

// checkDrift refuses results that look like a broken scan rather than a
// change: a discovery source that suddenly finds nothing (expired
// credentials), or a sharp drop in open endpoints (network trouble).
func (p *Pipeline) checkDrift(prev, cur model.Snapshot) error {
	count := func(assets []model.Asset) map[string]int {
		m := map[string]int{}
		for _, a := range assets {
			m[a.Source]++
		}
		return m
	}
	before, now := count(prev.Assets), count(cur.Assets)
	for _, d := range p.discoverers {
		if before[d.Name()] > 0 && now[d.Name()] == 0 {
			return fmt.Errorf("discovery %s returned 0 assets (previous run: %d)", d.Name(), before[d.Name()])
		}
	}
	was, is := len(prev.Endpoints), len(cur.Endpoints)
	if p.maxDropPct > 0 && was > 0 && (was-is)*100 > was*p.maxDropPct {
		return fmt.Errorf("endpoints dropped from %d to %d (%d%% > max_endpoint_drop_pct %d%%)",
			was, is, (was-is)*100/was, p.maxDropPct)
	}
	return nil
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
