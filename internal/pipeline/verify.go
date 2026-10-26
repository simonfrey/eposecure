package pipeline

import (
	"context"
	"net"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/simonfrey/eposecure/internal/model"
)

// stillOpen re-checks endpoints of the previous run that the current scan did
// not find, on hosts that are still scan targets. A dropped packet should not
// produce a "closed" alert followed by a "new" one the next day. Endpoints that
// still accept a TCP connection are returned (marked as scanner "verify"),
// together with their previous findings, which this run could not re-test.
func stillOpen(ctx context.Context, prev model.Snapshot, cur []model.Endpoint, names map[string][]string) ([]model.Endpoint, []model.Finding) {
	found := map[string]bool{}
	for _, e := range cur {
		found[e.Key()] = true
	}
	targets := map[string]bool{}
	for _, list := range names {
		for _, n := range list {
			targets[n] = true
		}
	}

	var mu sync.Mutex
	open := map[string]bool{}
	var restored []model.Endpoint
	var g errgroup.Group
	g.SetLimit(20)
	for _, e := range prev.Endpoints {
		if found[e.Key()] || !targets[e.Host] || e.Protocol == "udp" {
			continue // still found, no longer in the inventory, or UDP (no connection to test)
		}
		g.Go(func() error {
			if !accepts(ctx, e.Addr()) {
				return nil
			}
			mu.Lock()
			defer mu.Unlock()
			e.Scanner = "verify"
			restored = append(restored, e)
			open[e.Addr()] = true
			return nil
		})
	}
	_ = g.Wait()

	var findings []model.Finding
	for _, f := range prev.Findings {
		if open[addrOf(f.MatchedAt)] {
			findings = append(findings, f)
		}
	}
	return restored, findings
}

// accepts tries a TCP connection twice.
func accepts(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 3 * time.Second}
	for range 2 {
		if c, err := d.DialContext(ctx, "tcp", addr); err == nil {
			_ = c.Close()
			return true
		}
	}
	return false
}

// addrOf returns host:port for a finding location, which is a URL
// ("https://host/path") or a plain "host:port".
func addrOf(matched string) string {
	u, err := url.Parse(matched)
	if err != nil || u.Host == "" {
		return matched
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return net.JoinHostPort(u.Hostname(), port)
}
