// Package naabu finds open ports on all targets with a TCP connect scan (no root needed).
// Each open port is reported once per inventory name behind the IP
// (model.ScanContext.Names), so later HTTP probes reach name-based (SNI /
// Host header) services.
package naabu

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

type Naabu struct {
	TopPorts   string `yaml:"top_ports"`   // 100, 1000 or full
	ExtraPorts string `yaml:"extra_ports"` // e.g. "8080,8443,9000-9100"
	Rate       int    `yaml:"rate"`        // packets per second, keep low for Cloud Armor
	Retries    int    `yaml:"retries"`
}

func New(o config.Options) (*Naabu, error) {
	n := &Naabu{TopPorts: "1000", Rate: 300, Retries: 3}
	return n, o.Decode(n)
}

func (n *Naabu) Name() string { return "naabu" }

func (n *Naabu) Scan(ctx context.Context, sc *model.ScanContext) error {
	if len(sc.Targets) == 0 {
		return nil
	}
	var mu sync.Mutex
	seen := map[string]bool{} // a name with several IPs is reported once per port
	r, err := runner.NewRunner(&runner.Options{
		Host:               goflags.StringSlice(sc.Targets),
		ScanType:           runner.ConnectScan,
		TopPorts:           n.TopPorts,
		Ports:              n.ExtraPorts,
		Rate:               n.Rate,
		Retries:            n.Retries,
		Timeout:            time.Second,
		Threads:            25,
		WarmUpTime:         2,
		IPVersion:          goflags.StringSlice{"4", "6"},
		Silent:             true,
		DisableStdout:      true,
		DisableUpdateCheck: true,
		OnResult: func(hr *result.HostResult) {
			mu.Lock()
			defer mu.Unlock()
			for _, p := range hr.Ports {
				for _, h := range sc.Names[hr.IP] {
					e := model.Endpoint{Host: h, IP: hr.IP, Port: p.Port, Scanner: n.Name()}
					if !seen[e.Addr()] {
						seen[e.Addr()] = true
						sc.Endpoints = append(sc.Endpoints, e)
					}
				}
			}
		},
	})
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	return r.RunEnumeration(ctx)
}
