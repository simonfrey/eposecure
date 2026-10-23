// Package cloudlist discovers public assets with ProjectDiscovery's cloudlist.
// It is provider-agnostic: each entry under "providers" is passed to cloudlist
// unchanged, so GCP, AWS, Azure, Hetzner, ... are config, not code.
package cloudlist

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/cloudlist/pkg/inventory"
	"github.com/projectdiscovery/cloudlist/pkg/schema"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

// accountKeys are the metadata keys cloudlist providers use for the tenancy unit.
var accountKeys = []string{"project_id", "account_id", "subscription_id"}

type Cloudlist struct {
	providers schema.Options
}

func New(o config.Options) (*Cloudlist, error) {
	var opts struct {
		Providers []map[string]string `yaml:"providers"`
	}
	if err := o.Decode(&opts); err != nil {
		return nil, err
	}
	if len(opts.Providers) == 0 {
		return nil, fmt.Errorf("cloudlist: no providers configured")
	}
	c := &Cloudlist{}
	for i, p := range opts.Providers {
		if p["provider"] == "" {
			return nil, fmt.Errorf("cloudlist: providers[%d] has no 'provider' key", i)
		}
		c.providers = append(c.providers, schema.OptionBlock(p))
	}
	return c, nil
}

func (c *Cloudlist) Name() string { return "cloudlist" }

// Discover builds the cloudlist providers per run: some (e.g. AWS) call their
// API on construction, so a cloud outage fails the run instead of startup.
func (c *Cloudlist) Discover(ctx context.Context) ([]model.Asset, error) {
	inv, err := inventory.New(c.providers)
	if err != nil {
		return nil, err
	}
	var assets []model.Asset
	for _, p := range inv.Providers {
		res, err := p.Resources(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", p.Name(), p.ID(), err)
		}
		for _, r := range res.Items {
			if !r.Public {
				continue
			}
			for _, target := range []string{r.PublicIPv4, r.PublicIPv6, r.DNSName} {
				if target == "" {
					continue
				}
				assets = append(assets, model.Asset{
					Provider: r.Provider,
					Account:  account(r.Metadata),
					Kind:     r.Service,
					Name:     r.ID,
					Target:   target,
				})
			}
		}
	}
	return assets, nil
}

func account(meta map[string]string) string {
	for _, k := range accountKeys {
		if v := meta[k]; v != "" {
			return v
		}
	}
	return ""
}
