package pipeline

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/simonfrey/eposecure/internal/model"
)

// resolve turns targets into the IPs to port-scan and, per IP, the targets
// behind it (see model.ScanContext.Names). Each IP is scanned once no matter
// how many names point at it. Resolved IPs in an excluded range are dropped.
func resolve(ctx context.Context, log *slog.Logger, targets, exclude []string, prog model.Progress) (ips []string, names map[string][]string) {
	names = map[string][]string{}
	var mu sync.Mutex
	add := func(ip netip.Addr, name string) {
		ip = ip.Unmap()
		if excluded(ip.String(), exclude) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		names[ip.String()] = append(names[ip.String()], name)
	}

	var g errgroup.Group
	g.SetLimit(20)
	for _, t := range targets {
		prog.Add(t, 1)
		if ip, err := netip.ParseAddr(t); err == nil {
			add(ip, t)
			prog.Done(t, 1)
			continue
		}
		g.Go(func() error {
			defer prog.Done(t, 1)
			lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			resolved, err := net.DefaultResolver.LookupNetIP(lctx, "ip", t)
			if err != nil {
				log.Warn("cannot resolve, skipping", "target", t, "err", err)
				return nil
			}
			for _, ip := range resolved {
				add(ip, t)
			}
			return nil
		})
	}
	_ = g.Wait()

	for ip, n := range names {
		slices.Sort(n)
		names[ip] = slices.Compact(n)
	}
	return slices.Sorted(maps.Keys(names)), names
}
