// Package nuclei runs nuclei templates against every endpoint. Templates are
// installed and updated automatically into $HOME.
package nuclei

import (
	"cmp"
	"context"
	"log/slog"
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
}

func New(o config.Options) (*Nuclei, error) {
	n := &Nuclei{
		Severities:  []string{"medium", "high", "critical"},
		ExcludeTags: []string{"dos", "fuzz", "intrusive"},
		RateLimit:   50,
		Concurrency: 10,
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

	var mu sync.Mutex
	skipped := map[string]int{} // host -> templates not run because it stopped responding
	defer func() {
		if len(skipped) > 0 {
			slog.Warn("nuclei skipped templates on unresponsive hosts", "module", n.Name(), "hosts", skipped)
		}
	}()
	return ne.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
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
