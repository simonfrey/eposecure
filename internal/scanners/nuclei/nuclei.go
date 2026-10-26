// Package nuclei runs nuclei templates against every endpoint. Templates are
// installed and updated automatically into $HOME.
package nuclei

import (
	"cmp"
	"context"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

type Nuclei struct {
	Severities  []string `yaml:"severities"`
	Tags        []string `yaml:"tags"`         // only templates with one of these tags; empty = all
	ExcludeTags []string `yaml:"exclude_tags"` // never run, e.g. dos
	ExcludeIDs  []string `yaml:"exclude_ids"`  // never run these template ids
	// TakeoverCandidates also scans hostnames with a dangling CNAME (from
	// dns discovery), for the dns and http takeover templates.
	TakeoverCandidates bool `yaml:"takeover_candidates"`
	RateLimit          int  `yaml:"rate_limit"` // requests per second across all hosts
	Concurrency        int  `yaml:"concurrency"`
	// ScanStrategy is host-spray (all templates on a few hosts at a time, so
	// hosts finish one after another) or template-spray (each template on
	// all hosts, so all hosts finish together at the end).
	ScanStrategy string `yaml:"scan_strategy"`
}

func New(o config.Options) (*Nuclei, error) {
	n := &Nuclei{
		Severities:   []string{"medium", "high", "critical"},
		ExcludeTags:  []string{"dos", "fuzz", "intrusive"},
		RateLimit:    50,
		Concurrency:  10,
		ScanStrategy: "host-spray",
	}
	return n, o.Decode(n)
}

func (n *Nuclei) Name() string { return "nuclei" }

// targets returns the URL of HTTP endpoints, host:port of other TCP
// endpoints and, if enabled, the takeover candidate hostnames.
func (n *Nuclei) targets(sc *model.ScanContext) []string {
	var out []string
	for _, e := range sc.Endpoints {
		switch {
		case e.Protocol == "udp":
			// nuclei's network templates speak TCP
		case e.URL != "":
			out = append(out, e.URL)
		default:
			out = append(out, e.Addr())
		}
	}
	if n.TakeoverCandidates {
		out = append(out, sc.TakeoverCandidates...)
	}
	return out
}

func (n *Nuclei) Scan(ctx context.Context, sc *model.ScanContext) error {
	targets := n.targets(sc)
	if len(targets) == 0 {
		return nil
	}

	c := n.Concurrency
	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity:    strings.Join(n.Severities, ","),
			Tags:        n.Tags,
			ExcludeTags: n.ExcludeTags,
			ExcludeIDs:  n.ExcludeIDs,
		}),
		nuclei.WithGlobalRateLimitCtx(ctx, n.RateLimit, time.Second),
		nuclei.WithScanStrategy(n.ScanStrategy),
		// One event per template and target also when nothing matched: that
		// is how progress is counted, and how unresponsive hosts show up.
		nuclei.EnableMatcherStatus(),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency: c, HostConcurrency: c,
			HeadlessHostConcurrency: 1, HeadlessTemplateConcurrency: 1,
			JavascriptTemplateConcurrency: c, TemplatePayloadConcurrency: c, ProbeConcurrency: c,
		}),
	)
	if err != nil {
		return err
	}
	defer ne.Close()
	if err := ne.LoadAllTemplates(); err != nil {
		return err
	}
	// No probing: httpx already resolved HTTP endpoints to URLs, and with
	// probing on, nuclei v3.11 silently skips HTTP templates for URL inputs.
	ne.LoadTargets(targets, false)

	prog := sc.Progress()
	perTarget := len(ne.GetTemplates()) + len(ne.GetWorkflows())
	for _, t := range targets {
		prog.Add(t, perTarget)
	}
	in := newInputs(targets)

	var mu sync.Mutex
	skipped := map[string]int{} // host -> templates not run because it stopped responding
	defer func() {
		if len(skipped) > 0 {
			slog.Warn("nuclei skipped templates on unresponsive hosts", "module", n.Name(), "hosts", skipped)
		}
	}()
	return ne.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		mu.Lock()
		if key, first := in.attribute(ev); first {
			prog.Done(key, 1)
		}
		mu.Unlock()
		if !ev.MatcherStatus {
			// Failure event, not a match. Count skips so they are visible.
			if strings.Contains(ev.Error, "unresponsive") {
				mu.Lock()
				skipped[ev.Host]++
				mu.Unlock()
			}
			return
		}
		matched := ev.Matched
		if matched == "" {
			matched = ev.URL
		}
		// One template can match several ways at one URL (e.g. each missing
		// header); like the nuclei CLI, tell them apart as template:matcher.
		id := ev.TemplateID
		if sub := cmp.Or(ev.MatcherName, ev.ExtractorName); sub != "" {
			id += ":" + sub
		}
		mu.Lock()
		defer mu.Unlock()
		sc.Findings = append(sc.Findings, model.Finding{
			TemplateID: id,
			Name:       ev.Info.Name,
			Severity:   ev.Info.SeverityHolder.Severity.String(),
			MatchedAt:  matched,
			Target:     ev.Host,
			Scanner:    n.Name(),
			Tags:       ev.Info.Tags.ToSlice(),
			Raw:        ev,
		})
	})
}

// inputs attributes nuclei's result events to the target they ran on.
// Events carry host and port, not the input, so a target is found by host
// and port, or by host alone for templates without a port (dns). Each
// target counts each template once.
type inputs struct {
	byHost map[string][]*input
}

type input struct {
	key, port string
	seen      map[string]bool // template ids
}

func newInputs(targets []string) *inputs {
	in := &inputs{byHost: map[string][]*input{}}
	for _, t := range targets {
		host, port := hostPort(t)
		in.byHost[host] = append(in.byHost[host], &input{key: t, port: port, seen: map[string]bool{}})
	}
	return in
}

// attribute returns the target the event belongs to, and whether it is the
// first event of this template on that target. Not safe for concurrent use.
func (in *inputs) attribute(ev *output.ResultEvent) (key string, first bool) {
	host, port := strings.ToLower(ev.Host), ev.Port
	if h, p, err := net.SplitHostPort(host); err == nil { // some protocols report host:port
		host, port = h, cmp.Or(port, p)
	}
	if host == "" {
		host, port = hostPort(cmp.Or(ev.URL, ev.Matched))
	}
	host = strings.Trim(host, "[]")
	cands := in.byHost[host]
	var samePort []*input
	for _, c := range cands {
		if port != "" && c.port == port {
			samePort = append(samePort, c)
		}
	}
	if len(samePort) > 0 {
		cands = samePort
	}
	for _, c := range cands {
		if !c.seen[ev.TemplateID] {
			c.seen[ev.TemplateID] = true
			return c.key, true
		}
	}
	return "", false
}

// hostPort splits a URL, host:port or bare hostname. URLs without a port
// get the scheme's default; a bare hostname has no port.
func hostPort(target string) (host, port string) {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", ""
		}
		port = u.Port()
		if port == "" {
			port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
		}
		return strings.ToLower(u.Hostname()), port
	}
	if h, p, err := net.SplitHostPort(target); err == nil {
		return strings.ToLower(h), p
	}
	return strings.ToLower(target), ""
}
