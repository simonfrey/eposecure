// Package nuclei runs nuclei templates against every endpoint. Templates are
// installed and updated automatically into $HOME.
package nuclei

import (
	"context"
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
	RateLimit   int      `yaml:"rate_limit"`   // requests per second across all hosts
	Concurrency int      `yaml:"concurrency"`
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

func (n *Nuclei) Scan(ctx context.Context, sc *model.ScanContext) error {
	if len(sc.Endpoints) == 0 {
		return nil
	}
	targets := make([]string, 0, len(sc.Endpoints))
	for _, e := range sc.Endpoints {
		if e.URL != "" {
			targets = append(targets, e.URL)
		} else {
			targets = append(targets, e.Addr())
		}
	}

	c := n.Concurrency
	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity:    strings.Join(n.Severities, ","),
			Tags:        n.Tags,
			ExcludeTags: n.ExcludeTags,
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
	return ne.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		matched := ev.Matched
		if matched == "" {
			matched = ev.URL
		}
		mu.Lock()
		defer mu.Unlock()
		sc.Findings = append(sc.Findings, model.Finding{
			TemplateID: ev.TemplateID,
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
