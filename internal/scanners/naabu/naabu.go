// Package naabu finds open ports on all targets with a TCP connect scan (no root needed).
// Each open port is reported once per inventory name behind the IP
// (model.ScanContext.Names), so later HTTP probes reach name-based (SNI /
// Host header) services.
package naabu

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"golang.org/x/sync/errgroup"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

type Naabu struct {
	TopPorts   string `yaml:"top_ports"`   // 100, 1000 or full
	ExtraPorts string `yaml:"extra_ports"` // added to top_ports, e.g. "9000-9100"
	Rate       int    `yaml:"rate"`        // packets per second, keep low for Cloud Armor
	Retries    int    `yaml:"retries"`
	// ParallelHosts is how many IPs are scanned at once; rate is split between them.
	ParallelHosts int `yaml:"parallel_hosts"`
}

func New(o config.Options) (*Naabu, error) {
	n := &Naabu{TopPorts: "1000", ExtraPorts: cloudPorts, Rate: 300, Retries: 3, ParallelHosts: 4}
	return n, o.Decode(n)
}

// cloudPorts are services often exposed by mistake on cloud hosts that are
// not in nmap's top 1000: Docker, etcd, Kibana, RabbitMQ, CouchDB, Redis,
// Kubernetes API and kubelet, ActiveMQ, Cassandra, Kafka, Alertmanager,
// Elasticsearch, Memcached, MongoDB.
const cloudPorts = "2375,2376,2379,2380,5601,5672,5984,6379,6443,8161,9042,9092,9093,9300,10250,11211,15672,27017,27018"

func (n *Naabu) Name() string { return "naabu" }

// Scan scans one IP per naabu run, ParallelHosts at a time, so progress
// counts finished IPs. naabu shuffles IP×port within a run, which would
// leave every IP half done until the very end.
func (n *Naabu) Scan(ctx context.Context, sc *model.ScanContext) error {
	if len(sc.Targets) == 0 {
		return nil
	}
	prog := sc.Progress()
	parallel := max(1, min(n.ParallelHosts, len(sc.Targets)))
	rate := max(1, n.Rate/parallel) // same packets/s in total as one run over all IPs
	var mu sync.Mutex
	seen := map[string]bool{} // a name with several IPs is reported once per port
	onResult := func(hr *result.HostResult) {
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
	}

	for _, ip := range sc.Targets {
		prog.Add(ip, 1)
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(parallel)
	for _, ip := range sc.Targets {
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return err
			}
			if err := n.scan(gctx, ip, rate, onResult); err != nil {
				return fmt.Errorf("%s: %w", ip, err)
			}
			prog.Finish(ip)
			return nil
		})
	}
	return g.Wait()
}

func (n *Naabu) scan(ctx context.Context, ip string, rate int, onResult result.ResultFn) error {
	r, err := runner.NewRunner(&runner.Options{
		Host:               goflags.StringSlice{ip},
		ScanType:           runner.ConnectScan,
		TopPorts:           n.TopPorts,
		Ports:              n.ExtraPorts,
		Rate:               rate,
		Retries:            n.Retries,
		Timeout:            time.Second,
		Threads:            25,
		WarmUpTime:         2,
		IPVersion:          goflags.StringSlice{"4", "6"},
		Silent:             true,
		DisableStdout:      true,
		DisableUpdateCheck: true,
		OnResult:           onResult,
	})
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	return r.RunEnumeration(ctx)
}
