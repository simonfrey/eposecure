// Package progress tracks how far a run is, per phase (discovery, resolve,
// each scanner) and per target within a phase, and reports it to the log and
// the database while the run is going.
package progress

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/simonfrey/eposecure/internal/model"
)

// Sink persists progress. Only rows that changed since the last save are passed.
type Sink interface {
	SaveProgress(ctx context.Context, u Update) error
}

// Update is the run's state plus the phases and targets that changed.
type Update struct {
	RunID      int64
	Phase      string    // phase currently running, "" between phases
	OverallPct float64   // 0..100
	ETA        time.Time // zero if unknown, e.g. on the first run
	Phases     []PhaseRow
	Targets    []TargetRow
}

type PhaseRow struct {
	Name              string
	Ord               int
	Started, Finished time.Time
	Done, Total       int64
}

type TargetRow struct {
	Phase, Target     string
	Host, IP, Domain  string
	Done, Total       int
	Started, Finished time.Time
}

// Tracker is the progress of one run.
type Tracker struct {
	mu     sync.Mutex
	runID  int64
	log    *slog.Logger
	sink   Sink
	phases []*Phase
	// prev is how long each phase took in the previous successful run; it
	// weighs the phases for the overall percentage and the ETA.
	prev   map[string]time.Duration
	domain map[string]string   // asset target -> account (DNS root domain, project, ...)
	ipOf   map[string]string   // name -> one IP it resolved to
	names  map[string][]string // IP -> names
	now    func() time.Time

	stop chan struct{}
	done chan struct{}
}

// New creates the tracker with the phases in the order they will run, so
// the overall percentage counts phases that have not started yet.
func New(runID int64, log *slog.Logger, sink Sink, phases []string, prev map[string]time.Duration) *Tracker {
	t := &Tracker{runID: runID, log: log, sink: sink, prev: prev, now: time.Now,
		domain: map[string]string{}, ipOf: map[string]string{}, names: map[string][]string{}}
	for _, name := range phases {
		t.add(name)
	}
	return t
}

func (t *Tracker) add(name string) *Phase {
	p := &Phase{t: t, name: name, ord: len(t.phases), targets: map[string]*target{}, dirty: true}
	t.phases = append(t.phases, p)
	return p
}

// Phase starts the named phase and returns it for reporting.
func (t *Tracker) Phase(name string) *Phase {
	t.mu.Lock()
	defer t.mu.Unlock()
	var p *Phase
	for _, ph := range t.phases {
		if ph.name == name {
			p = ph
		}
	}
	if p == nil {
		p = t.add(name)
	}
	p.started, p.dirty = t.now(), true
	return p
}

// SetAssets lets targets be attributed to the account (domain, project) they belong to.
func (t *Tracker) SetAssets(assets []model.Asset) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, a := range assets {
		if a.Target != "" && t.domain[a.Target] == "" {
			t.domain[a.Target] = a.Account
		}
	}
}

// SetNames lets targets be attributed to IPs, see model.ScanContext.Names.
func (t *Tracker) SetNames(names map[string][]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.names = names
	for ip, ns := range names {
		for _, n := range ns {
			if cur, ok := t.ipOf[n]; !ok || ip < cur { // stable choice for names with several IPs
				t.ipOf[n] = ip
			}
		}
	}
}

// describe returns the host, IP and domain behind a target. Called with t.mu held.
func (t *Tracker) describe(key string) (host, ip, domain string) {
	if key == "" {
		return "", "", ""
	}
	host = key
	if strings.Contains(key, "://") {
		if u, err := url.Parse(key); err == nil {
			host = u.Hostname()
		}
	} else if h, _, err := net.SplitHostPort(key); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	if _, err := netip.ParseAddr(host); err == nil {
		ip = host
		domain = t.domain[host]
		for _, n := range t.names[ip] {
			if domain != "" {
				break
			}
			domain = t.domain[n]
		}
		return host, ip, domain
	}
	return host, t.ipOf[host], t.domain[host]
}

// Phase is one step of the run. It implements model.Progress.
type Phase struct {
	t                 *Tracker
	name              string
	ord               int
	started, finished time.Time
	targets           map[string]*target
	order             []string
	dirty             bool
}

type target struct {
	done, total       int
	started, finished time.Time
	dirty             bool
}

var _ model.Progress = (*Phase)(nil)

// get returns the target, creating it. Called with t.mu held.
func (p *Phase) get(key string) *target {
	tg, ok := p.targets[key]
	if !ok {
		tg = &target{started: p.t.now()}
		p.targets[key] = tg
		p.order = append(p.order, key)
	}
	tg.dirty, p.dirty = true, true
	return tg
}

func (p *Phase) Add(key string, total int) {
	p.t.mu.Lock()
	defer p.t.mu.Unlock()
	tg := p.get(key)
	tg.total += total
	tg.finished = time.Time{}
}

func (p *Phase) Done(key string, n int) {
	p.t.mu.Lock()
	defer p.t.mu.Unlock()
	tg := p.get(key)
	tg.done += n
	if tg.done >= tg.total && tg.finished.IsZero() {
		tg.done, tg.finished = tg.total, p.t.now()
	}
}

// Finish marks the target complete and logs it, so the log shows targets
// of slow phases (naabu per IP, nuclei) as they finish.
func (p *Phase) Finish(key string) {
	p.t.mu.Lock()
	defer p.t.mu.Unlock()
	tg := p.get(key)
	if !tg.finished.IsZero() {
		return
	}
	tg.total = max(tg.total, tg.done, 1)
	tg.done, tg.finished = tg.total, p.t.now()
	n := 0
	for _, k := range p.order {
		if k != "" && !p.targets[k].finished.IsZero() {
			n++
		}
	}
	_, ip, domain := p.t.describe(key)
	p.t.log.Info("target done", "phase", p.name, "target", key, "ip", ip, "domain", domain,
		"targets", fmt.Sprintf("%d/%d", n, p.count()))
}

// End finishes the phase and all its targets, also those whose work was
// not fully reported (e.g. nuclei templates that do not apply to a target).
func (p *Phase) End() {
	p.t.mu.Lock()
	defer p.t.mu.Unlock()
	now := p.t.now()
	for _, tg := range p.targets {
		if tg.finished.IsZero() {
			tg.total = max(tg.total, tg.done, 1)
			tg.done, tg.finished, tg.dirty = tg.total, now, true
		}
	}
	p.finished, p.dirty = now, true
}

// count is the number of real targets ("" is the phase itself).
func (p *Phase) count() int {
	if _, ok := p.targets[""]; ok {
		return len(p.targets) - 1
	}
	return len(p.targets)
}

// units returns done and total over all targets.
func (p *Phase) units() (done, total int64) {
	for _, tg := range p.targets {
		done += int64(tg.done)
		total += int64(tg.total)
	}
	return done, total
}

// fraction is how much of the phase is done, 0..1.
func (p *Phase) fraction() float64 {
	switch {
	case !p.finished.IsZero():
		return 1
	case p.started.IsZero():
		return 0
	}
	done, total := p.units()
	if total == 0 {
		return 0
	}
	return min(float64(done)/float64(total), 1)
}

// current returns the phase that is running, or nil. Called with t.mu held.
func (t *Tracker) current() *Phase {
	var cur *Phase
	for _, p := range t.phases {
		if !p.started.IsZero() && p.finished.IsZero() {
			cur = p
		}
	}
	return cur
}

// estimate returns the overall fraction done and the time left, for the
// run and for the current phase. Unknown times are -1. Called with t.mu held.
func (t *Tracker) estimate() (overall float64, left, phaseLeft time.Duration) {
	now := t.now()
	var known time.Duration
	var nKnown int
	for _, p := range t.phases {
		if d := t.prev[p.name]; d > 0 {
			known += d
			nKnown++
		}
	}
	weight := func(p *Phase) float64 {
		switch {
		case nKnown == 0:
			return 1
		case t.prev[p.name] > 0:
			return t.prev[p.name].Seconds()
		default:
			return known.Seconds() / float64(nKnown) // a new phase weighs like an average one
		}
	}

	var sum, total float64
	phaseLeft = -1
	for _, p := range t.phases {
		w, f := weight(p), p.fraction()
		sum += w * f
		total += w

		var rest time.Duration
		switch {
		case f == 1:
		case p.started.IsZero() && t.prev[p.name] > 0:
			rest = t.prev[p.name]
		case !p.started.IsZero() && f > 0:
			elapsed := now.Sub(p.started)
			rest = time.Duration(float64(elapsed) * (1 - f) / f)
			phaseLeft = rest
		case !p.started.IsZero() && t.prev[p.name] > 0:
			rest = max(t.prev[p.name]-now.Sub(p.started), 0)
		default:
			left = -1
		}
		if left >= 0 {
			left += rest
		}
	}
	if total == 0 {
		return 0, left, phaseLeft
	}
	return sum / total, left, phaseLeft
}

// Start flushes changed rows every flushEvery and logs a summary every
// logEvery until Close.
func (t *Tracker) Start(ctx context.Context, flushEvery, logEvery time.Duration) {
	t.stop, t.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(t.done)
		flush, logT := time.NewTicker(flushEvery), time.NewTicker(logEvery)
		defer flush.Stop()
		defer logT.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.stop:
				return
			case <-flush.C:
				t.Flush(ctx)
			case <-logT.C:
				t.Log()
			}
		}
	}()
}

// Close stops the loop and saves what changed since the last flush, also
// when the run failed or was cancelled.
func (t *Tracker) Close() {
	if t.stop != nil {
		close(t.stop)
		<-t.done
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Flush(ctx)
}

// Flush saves the rows that changed. A failed save is retried on the next
// flush; progress is informational and never fails the run.
func (t *Tracker) Flush(ctx context.Context) {
	if t.sink == nil {
		return
	}
	u := t.update()
	if err := t.sink.SaveProgress(ctx, u); err != nil {
		t.log.Warn("saving progress", "err", err)
		t.redirty(u)
	}
}

// update collects the changed rows and clears their dirty flags.
func (t *Tracker) update() Update {
	t.mu.Lock()
	defer t.mu.Unlock()
	overall, left, _ := t.estimate()
	u := Update{RunID: t.runID, OverallPct: 100 * overall}
	if left >= 0 {
		u.ETA = t.now().Add(left)
	}
	if cur := t.current(); cur != nil {
		u.Phase = cur.name
	}
	for _, p := range t.phases {
		if !p.dirty {
			continue
		}
		p.dirty = false
		done, total := p.units()
		u.Phases = append(u.Phases, PhaseRow{Name: p.name, Ord: p.ord, Started: p.started,
			Finished: p.finished, Done: done, Total: total})
		for _, key := range p.order {
			tg := p.targets[key]
			if !tg.dirty {
				continue
			}
			tg.dirty = false
			host, ip, domain := t.describe(key)
			u.Targets = append(u.Targets, TargetRow{Phase: p.name, Target: key, Host: host, IP: ip,
				Domain: domain, Done: tg.done, Total: tg.total, Started: tg.started, Finished: tg.finished})
		}
	}
	return u
}

func (t *Tracker) redirty(u Update) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.phases {
		for _, r := range u.Phases {
			if r.Name == p.name {
				p.dirty = true
			}
		}
		for _, r := range u.Targets {
			if r.Phase == p.name {
				p.targets[r.Target].dirty = true
			}
		}
	}
}

// Log writes one line with the overall and the current phase's progress.
func (t *Tracker) Log() {
	t.mu.Lock()
	defer t.mu.Unlock()
	overall, left, phaseLeft := t.estimate()
	args := []any{"overall", pct(overall), "eta", dur(left)}
	if p := t.current(); p != nil {
		done, total := p.units()
		args = append(args, "phase", p.name, "step", fmt.Sprintf("%d/%d", p.ord+1, len(t.phases)),
			"phase_done", pct(p.fraction()), "units", fmt.Sprintf("%d/%d", done, total), "phase_eta", dur(phaseLeft))
		if n := p.count(); n > 0 {
			finished, ips, ipsDone, active := 0, map[string]bool{}, 0, []string(nil)
			for _, key := range p.order {
				if key == "" {
					continue
				}
				tg := p.targets[key]
				_, ip, _ := t.describe(key)
				if ip != "" {
					ips[ip] = ips[ip] || false
				}
				if tg.finished.IsZero() {
					if ip != "" {
						ips[ip] = true // true = still has open work
					}
					if tg.done > 0 && len(active) < 3 {
						active = append(active, fmt.Sprintf("%s %d/%d", key, tg.done, tg.total))
					}
				} else {
					finished++
				}
			}
			for _, open := range ips {
				if !open {
					ipsDone++
				}
			}
			args = append(args, "targets", fmt.Sprintf("%d/%d", finished, n))
			if len(ips) > 0 {
				args = append(args, "ips", fmt.Sprintf("%d/%d", ipsDone, len(ips)))
			}
			if len(active) > 0 {
				args = append(args, "active", strings.Join(active, ", "))
			}
		}
	}
	t.log.Info("progress", args...)
}

func pct(f float64) string { return fmt.Sprintf("%.1f%%", 100*f) }

func dur(d time.Duration) string {
	if d < 0 {
		return "unknown"
	}
	return d.Round(time.Second).String()
}
