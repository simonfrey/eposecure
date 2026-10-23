// Package diff compares two run snapshots and produces events.
package diff

import (
	"cmp"
	"math"

	"github.com/simonfrey/exposure-scanner/internal/model"
)

// Compute returns the events between prev and cur. With an empty prev
// (first run) everything in cur is reported as new.
func Compute(prev, cur model.Snapshot) []model.Event {
	var events []model.Event

	owner := assetIndex(cur.Assets, prev.Assets)
	endpointEvent := func(typ string, e model.Endpoint) model.Event {
		a := owner[e.Host]
		return model.Event{Type: typ, Target: e.Host, Port: e.Port, Provider: a.Provider, Account: a.Account,
			Resource: a.Name, Detail: map[string]any{"ip": e.IP, "url": e.URL, "title": e.Title, "tech": e.Tech,
				"protocol": cmp.Or(e.Protocol, "tcp"), "service": e.Service}}
	}
	added, removed := delta(prev.Endpoints, cur.Endpoints, model.Endpoint.Key)
	for _, e := range added {
		events = append(events, endpointEvent(model.NewEndpoint, e))
	}
	for _, e := range removed {
		events = append(events, endpointEvent(model.ClosedEndpoint, e))
	}

	findingEvent := func(typ string, f model.Finding) model.Event {
		a := owner[f.Target]
		return model.Event{Type: typ, Target: f.Target, Severity: f.Severity, Provider: a.Provider, Account: a.Account,
			Resource: a.Name, Detail: map[string]any{"template_id": f.TemplateID, "name": f.Name, "matched_at": f.MatchedAt,
				"tags": f.Tags, "exploited": f.Exploited, "epss": f.EPSS}}
	}
	addedF, removedF := delta(prev.Findings, cur.Findings, func(f model.Finding) string {
		return f.TemplateID + "|" + f.MatchedAt
	})
	for _, f := range addedF {
		events = append(events, findingEvent(model.NewFinding, f))
	}
	for _, f := range removedF {
		events = append(events, findingEvent(model.ResolvedFinding, f))
	}
	for _, ch := range riskChanges(prev.Findings, cur.Findings) {
		e := findingEvent(model.RiskChanged, ch.cur)
		e.Detail["old_severity"], e.Detail["new_severity"] = ch.prev.Severity, ch.cur.Severity
		e.Detail["old_exploited"], e.Detail["new_exploited"] = ch.prev.Exploited, ch.cur.Exploited
		e.Detail["old_epss"], e.Detail["new_epss"] = ch.prev.EPSS, ch.cur.EPSS
		events = append(events, e)
	}

	assetEvent := func(typ string, a model.Asset) model.Event {
		return model.Event{Type: typ, Target: a.Target, Provider: a.Provider, Account: a.Account,
			Resource: a.Name, Detail: map[string]any{"kind": a.Kind, "source": a.Source}}
	}
	addedA, removedA := delta(prev.Assets, cur.Assets, func(a model.Asset) string {
		return a.Provider + "|" + a.Kind + "|" + a.Target
	})
	for _, a := range addedA {
		events = append(events, assetEvent(model.NewAsset, a))
	}
	for _, a := range removedA {
		events = append(events, assetEvent(model.RemovedAsset, a))
	}
	return events
}

// epssStep is the EPSS change (absolute probability) that counts as a risk
// change. Scores move a little every day; smaller steps would be noise.
const epssStep = 0.1

type change struct{ prev, cur model.Finding }

// riskChanges returns findings present in both runs whose risk changed:
// another severity, newly listed as exploited, or a large EPSS move.
func riskChanges(prev, cur []model.Finding) []change {
	key := func(f model.Finding) string { return f.TemplateID + "|" + f.MatchedAt }
	before := make(map[string]model.Finding, len(prev))
	for _, f := range prev {
		before[key(f)] = f
	}
	var out []change
	seen := map[string]bool{}
	for _, f := range cur {
		k := key(f)
		p, ok := before[k]
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		if p.Severity != f.Severity || !p.Exploited && f.Exploited || math.Abs(f.EPSS-p.EPSS) >= epssStep {
			out = append(out, change{p, f})
		}
	}
	return out
}

// delta returns the items only in cur (added) and only in prev (removed).
func delta[T any](prev, cur []T, key func(T) string) (added, removed []T) {
	in := func(items []T) map[string]bool {
		m := make(map[string]bool, len(items))
		for _, it := range items {
			m[key(it)] = true
		}
		return m
	}
	prevKeys, curKeys := in(prev), in(cur)
	seen := map[string]bool{}
	for _, it := range cur {
		if k := key(it); !prevKeys[k] && !seen[k] {
			seen[k] = true
			added = append(added, it)
		}
	}
	for _, it := range prev {
		if k := key(it); !curKeys[k] && !seen[k] {
			seen[k] = true
			removed = append(removed, it)
		}
	}
	return added, removed
}

// assetIndex maps scan targets to the asset that produced them, preferring
// the current run so closed endpoints still get their provider and account.
func assetIndex(cur, prev []model.Asset) map[string]model.Asset {
	m := map[string]model.Asset{}
	for _, list := range [][]model.Asset{prev, cur} {
		for _, a := range list {
			m[a.Target] = a
		}
	}
	return m
}
