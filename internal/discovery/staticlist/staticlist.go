// Package staticlist turns a fixed list of IPs, CIDRs and hostnames from the
// config into assets. CIDRs are expanded to one asset per host address.
package staticlist

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/simonfrey/eposecure/internal/config"
	"github.com/simonfrey/eposecure/internal/model"
)

type StaticList struct {
	Targets []string `yaml:"targets"` // IPs, CIDRs or hostnames
	// MaxIPs caps how many addresses one CIDR may expand to, so a typo
	// ("10.0.0.0/8") cannot turn into a multi-million-target scan.
	MaxIPs int `yaml:"max_ips"`
}

func New(o config.Options) (*StaticList, error) {
	s := &StaticList{MaxIPs: 4096}
	if err := o.Decode(s); err != nil {
		return nil, err
	}
	for _, t := range s.Targets {
		if p, err := netip.ParsePrefix(t); err == nil {
			if n := hosts(p); n < 0 || n > s.MaxIPs {
				return nil, fmt.Errorf("static_list: %s is larger than max_ips %d; use a smaller CIDR or raise max_ips", t, s.MaxIPs)
			}
		}
	}
	return s, nil
}

func (s *StaticList) Name() string { return "static_list" }

func (s *StaticList) Discover(context.Context) ([]model.Asset, error) {
	assets := make([]model.Asset, 0, len(s.Targets))
	for _, t := range s.Targets {
		p, err := netip.ParsePrefix(t)
		if err != nil {
			assets = append(assets, model.Asset{Provider: "static", Kind: "target", Name: t, Target: t})
			continue
		}
		for _, ip := range expand(p) {
			assets = append(assets, model.Asset{Provider: "static", Kind: "target", Name: t, Target: ip.String()})
		}
	}
	return assets, nil
}

// hosts returns the number of addresses p expands to, or -1 if it is too
// large to count (more than 2^30).
func hosts(p netip.Prefix) int {
	bits := p.Addr().BitLen() - p.Bits()
	if bits > 30 {
		return -1
	}
	n := 1 << bits
	if p.Addr().Is4() && bits >= 2 {
		n -= 2 // network and broadcast address
	}
	return n
}

// expand lists the host addresses of p. For IPv4 prefixes larger than /31
// the network and broadcast addresses are skipped.
func expand(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	n := hosts(p)
	ip := p.Addr()
	if p.Addr().Is4() && p.Bits() < 31 {
		ip = ip.Next()
	}
	out := make([]netip.Addr, 0, n)
	for range n {
		out = append(out, ip)
		ip = ip.Next()
	}
	return out
}
