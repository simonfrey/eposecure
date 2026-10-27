// Package dns finds subdomains of the configured root domains with subfinder
// (passive sources) and keeps those that resolve, using dnsx. Optionally it
// also finds the owner's other domains (see Related).
package dns

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"

	"github.com/simonfrey/eposecure/internal/config"
	"github.com/simonfrey/eposecure/internal/model"
	"github.com/simonfrey/eposecure/internal/store"
)

type DNS struct {
	RootDomains    []string `yaml:"root_domains"`
	MaxEnumMinutes int      `yaml:"max_enumeration_minutes"`
	Related        *Related `yaml:"related_domains"` // nil: off

	last snapshotter
}

// snapshotter loads the previous run (implemented by store.Store).
type snapshotter interface {
	LastSnapshot(ctx context.Context) (model.Snapshot, error)
}

func New(o config.Options) (*DNS, error) {
	d := &DNS{MaxEnumMinutes: 10}
	if err := o.Decode(d); err != nil {
		return nil, err
	}
	if len(d.RootDomains) == 0 {
		return nil, fmt.Errorf("dns: root_domains is empty")
	}
	if d.Related != nil {
		d.Related.init()
	}
	return d, nil
}

func (d *DNS) Name() string { return "dns" }

// SetStore lets related-domain discovery fall back to the last run.
func (d *DNS) SetStore(st *store.Store) {
	if st != nil {
		d.last = st
	}
}

func (d *DNS) Discover(ctx context.Context) ([]model.Asset, error) {
	sf, err := runner.NewRunner(&runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: d.MaxEnumMinutes,
		Silent:             true,
		DisableUpdateCheck: true,
		Output:             io.Discard,
	})
	if err != nil {
		return nil, err
	}
	opts := dnsx.DefaultOptions
	opts.QuestionTypes = []uint16{miekgdns.TypeA, miekgdns.TypeAAAA}
	resolver, err := dnsx.New(opts)
	if err != nil {
		return nil, err
	}

	var assets []model.Asset
	roots := d.RootDomains
	if d.Related != nil {
		related := d.related(ctx)
		assets = append(assets, related...)
		if d.Related.AutoScan {
			for _, a := range related {
				roots = append(roots, a.Target)
			}
		}
	}
	for _, root := range roots {
		found, err := sf.EnumerateSingleDomainWithCtx(ctx, root, []io.Writer{io.Discard})
		if err != nil {
			return nil, fmt.Errorf("subfinder %s: %w", root, err)
		}
		hosts := []string{root}
		for h := range found {
			hosts = append(hosts, strings.ToLower(h))
		}
		slices.Sort(hosts)
		for _, h := range slices.Compact(hosts) {
			data, err := resolver.QueryMultiple(h)
			if err != nil || data == nil {
				continue // lookup failed, not enough to act on
			}
			if len(data.A)+len(data.AAAA) == 0 {
				// Does not resolve. If it still points at a cloud resource via
				// CNAME, it is a takeover candidate: someone may be able to
				// claim that resource. Dead names without a CNAME are skipped.
				if len(data.CNAME) == 0 {
					continue
				}
				assets = append(assets, model.Asset{
					Provider: "dns",
					Account:  root,
					Kind:     "takeover",
					Name:     h,
					Target:   h,
				})
				continue
			}
			assets = append(assets, model.Asset{
				Provider: "dns",
				Account:  root,
				Kind:     "hostname",
				Name:     h,
				Target:   h,
			})
		}
	}
	return assets, nil
}

// related returns the owner's other domains as assets of kind
// related_domain, which are reported but not scanned. crt.sh is often slow or
// down; then the last run's related domains are kept, so an outage neither
// fails the run nor reports them all as removed.
func (d *DNS) related(ctx context.Context) []model.Asset {
	found, err := d.Related.find(ctx, d.RootDomains)
	var assets []model.Asset
	for _, r := range found {
		assets = append(assets, model.Asset{
			Provider: "dns",
			Account:  r.Seed,
			Kind:     "related_domain",
			Name:     r.Domain,
			Target:   r.Domain,
		})
	}
	if err == nil || ctx.Err() != nil {
		return assets
	}
	slog.Warn("related domains incomplete, keeping last run's", "module", d.Name(), "err", err)
	if d.last == nil {
		return assets
	}
	prev, perr := d.last.LastSnapshot(ctx)
	if perr != nil {
		slog.Warn("cannot load last run's related domains", "module", d.Name(), "err", perr)
		return assets
	}
	for _, a := range prev.Assets {
		if a.Source == d.Name() && a.Kind == "related_domain" &&
			!slices.ContainsFunc(assets, func(b model.Asset) bool { return b.Target == a.Target }) {
			assets = append(assets, a)
		}
	}
	return assets
}
