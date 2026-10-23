package diff

import (
	"testing"

	"github.com/simonfrey/exposure-scanner/internal/model"
)

func types(events []model.Event) map[string]int {
	m := map[string]int{}
	for _, e := range events {
		m[e.Type]++
	}
	return m
}

func TestFirstRunReportsEverythingAsNew(t *testing.T) {
	cur := model.Snapshot{
		Assets:    []model.Asset{{Provider: "gcp", Account: "p1", Target: "1.2.3.4"}},
		Endpoints: []model.Endpoint{{Host: "1.2.3.4", Port: 443}},
		Findings:  []model.Finding{{TemplateID: "CVE-1", MatchedAt: "https://1.2.3.4"}},
	}
	got := types(Compute(model.Snapshot{}, cur))
	if got[model.NewAsset] != 1 || got[model.NewEndpoint] != 1 || got[model.NewFinding] != 1 || len(got) != 3 {
		t.Fatalf("unexpected events: %v", got)
	}
}

func TestOpenAndClosePort(t *testing.T) {
	asset := model.Asset{Provider: "gcp", Account: "p1", Name: "vm-1", Target: "1.2.3.4"}
	prev := model.Snapshot{
		Assets:    []model.Asset{asset},
		Endpoints: []model.Endpoint{{Host: "1.2.3.4", Port: 443}},
	}
	cur := model.Snapshot{
		Assets:    []model.Asset{asset},
		Endpoints: []model.Endpoint{{Host: "1.2.3.4", Port: 443}, {Host: "1.2.3.4", Port: 8080}},
	}

	events := Compute(prev, cur)
	if len(events) != 1 || events[0].Type != model.NewEndpoint || events[0].Port != 8080 {
		t.Fatalf("want one new_endpoint on 8080, got %+v", events)
	}
	if events[0].Account != "p1" || events[0].Resource != "vm-1" {
		t.Fatalf("event not enriched with asset info: %+v", events[0])
	}

	events = Compute(cur, prev)
	if len(events) != 1 || events[0].Type != model.ClosedEndpoint || events[0].Port != 8080 {
		t.Fatalf("want one closed_endpoint on 8080, got %+v", events)
	}
}

func TestRemovedAssetKeepsItsProvider(t *testing.T) {
	prev := model.Snapshot{
		Assets:    []model.Asset{{Provider: "aws", Account: "123", Target: "5.6.7.8"}},
		Endpoints: []model.Endpoint{{Host: "5.6.7.8", Port: 22}},
	}
	events := Compute(prev, model.Snapshot{})
	got := types(events)
	if got[model.RemovedAsset] != 1 || got[model.ClosedEndpoint] != 1 {
		t.Fatalf("unexpected events: %v", got)
	}
	for _, e := range events {
		if e.Provider != "aws" || e.Account != "123" {
			t.Fatalf("lost asset info: %+v", e)
		}
	}
}

func TestDuplicatesCollapse(t *testing.T) {
	cur := model.Snapshot{Endpoints: []model.Endpoint{{Host: "a", Port: 80}, {Host: "a", Port: 80}}}
	if n := len(Compute(model.Snapshot{}, cur)); n != 1 {
		t.Fatalf("want 1 event, got %d", n)
	}
}

func TestRiskChanged(t *testing.T) {
	f := model.Finding{TemplateID: "CVE-1", MatchedAt: "https://a", Target: "a", Severity: "medium", EPSS: 0.10}
	with := func(mod func(*model.Finding)) model.Snapshot {
		g := f
		mod(&g)
		return model.Snapshot{Findings: []model.Finding{g}}
	}
	prev := model.Snapshot{Findings: []model.Finding{f}}
	for name, tc := range map[string]struct {
		cur  model.Snapshot
		want bool
	}{
		"unchanged":        {with(func(*model.Finding) {}), false},
		"small epss move":  {with(func(g *model.Finding) { g.EPSS = 0.15 }), false},
		"large epss move":  {with(func(g *model.Finding) { g.EPSS = 0.35 }), true},
		"now exploited":    {with(func(g *model.Finding) { g.Exploited = true }), true},
		"severity raised":  {with(func(g *model.Finding) { g.Severity = "critical" }), true},
		"severity lowered": {with(func(g *model.Finding) { g.Severity = "low" }), true},
	} {
		events := Compute(prev, tc.cur)
		got := types(events)[model.RiskChanged] == 1
		if got != tc.want || len(events) != map[bool]int{true: 1, false: 0}[tc.want] {
			t.Errorf("%s: events %+v", name, events)
		}
	}
	e := Compute(prev, with(func(g *model.Finding) { g.Exploited, g.Severity = true, "high" }))[0]
	if e.Severity != "high" || e.Detail["old_severity"] != "medium" || e.Detail["new_exploited"] != true {
		t.Errorf("detail: %+v", e)
	}
}

func TestUDPAndTCPOnSamePortAreDistinct(t *testing.T) {
	prev := model.Snapshot{Endpoints: []model.Endpoint{{Host: "a", Port: 53, Protocol: "tcp"}}}
	cur := model.Snapshot{Endpoints: []model.Endpoint{{Host: "a", Port: 53}, {Host: "a", Port: 53, Protocol: "udp"}}}
	events := Compute(prev, cur)
	if len(events) != 1 || events[0].Type != model.NewEndpoint || events[0].Detail["protocol"] != "udp" {
		t.Fatalf("want one new udp endpoint (tcp and empty protocol are the same), got %+v", events)
	}
}
