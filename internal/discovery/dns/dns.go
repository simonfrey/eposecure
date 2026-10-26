// Package dns finds subdomains of the configured root domains with subfinder
// (passive sources) and keeps those that resolve, using dnsx.
package dns

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"

	"github.com/simonfrey/eposecure/internal/config"
	"github.com/simonfrey/eposecure/internal/model"
)

type DNS struct {
	RootDomains    []string `yaml:"root_domains"`
	MaxEnumMinutes int      `yaml:"max_enumeration_minutes"`
}

func New(o config.Options) (*DNS, error) {
	d := &DNS{MaxEnumMinutes: 10}
	if err := o.Decode(d); err != nil {
		return nil, err
	}
	if len(d.RootDomains) == 0 {
		return nil, fmt.Errorf("dns: root_domains is empty")
	}
	return d, nil
}

func (d *DNS) Name() string { return "dns" }

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
	for _, root := range d.RootDomains {
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
