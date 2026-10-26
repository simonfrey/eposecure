package progress

import (
	"context"
	"log/slog"
	"math"
	"testing"
	"time"

	"github.com/simonfrey/exposure-scanner/internal/model"
)

type fakeSink struct{ updates []Update }

func (f *fakeSink) SaveProgress(_ context.Context, u Update) error {
	f.updates = append(f.updates, u)
	return nil
}

// clock returns a tracker whose time only moves when advance is called.
func clock(t *Tracker) (advance func(time.Duration)) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t.now = func() time.Time { return now }
	return func(d time.Duration) { now = now.Add(d) }
}

func TestDescribe(t *testing.T) {
	tr := New(1, slog.Default(), nil, nil, nil)
	tr.SetAssets([]model.Asset{
		{Target: "a.example.com", Account: "example.com"},
		{Target: "1.2.3.4", Account: "project-a"},
		{Target: "c.example.com", Account: "example.com"},
	})
	tr.SetNames(map[string][]string{
		"1.2.3.4": {"1.2.3.4", "a.example.com"},
		"5.6.7.8": {"c.example.com"},
	})
	for key, want := range map[string][3]string{
		"https://A.example.com:8443/x": {"a.example.com", "1.2.3.4", "example.com"},
		"1.2.3.4:22":                   {"1.2.3.4", "1.2.3.4", "project-a"},
		"5.6.7.8":                      {"5.6.7.8", "5.6.7.8", "example.com"}, // via the name behind the IP
		"old.example.com":              {"old.example.com", "", ""},
		"":                             {"", "", ""},
	} {
		host, ip, domain := tr.describe(key)
		if got := [3]string{host, ip, domain}; got != want {
			t.Errorf("describe(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestEstimateWeighsPhasesByPreviousRun(t *testing.T) {
	prev := map[string]time.Duration{"naabu": 10 * time.Minute, "nuclei": 30 * time.Minute}
	tr := New(1, slog.Default(), nil, []string{"naabu", "nuclei"}, prev)
	advance := clock(tr)

	tr.Phase("naabu").End()
	p := tr.Phase("nuclei")
	p.Add("a", 100)
	advance(10 * time.Minute)
	p.Done("a", 25)

	overall, left, phaseLeft := tr.estimate()
	if want := (10 + 0.25*30) / 40.0; math.Abs(overall-want) > 1e-9 {
		t.Errorf("overall = %v, want %v", overall, want)
	}
	if phaseLeft != 30*time.Minute || left != 30*time.Minute { // 25% took 10m, 75% left
		t.Errorf("left = %v, phase left = %v, want 30m", left, phaseLeft)
	}
}

func TestEstimateUnknownOnFirstRun(t *testing.T) {
	tr := New(1, slog.Default(), nil, []string{"naabu", "nuclei"}, nil)
	clock(tr)
	p := tr.Phase("naabu")
	p.Add("1.2.3.4", 1)
	p.Add("5.6.7.8", 1)
	p.Finish("1.2.3.4")

	overall, left, _ := tr.estimate()
	if overall != 0.25 || left != -1 {
		t.Errorf("overall = %v, left = %v; want 0.25 (equal weights) and unknown", overall, left)
	}
}

func TestFlushSavesOnlyChanges(t *testing.T) {
	sink := &fakeSink{}
	tr := New(7, slog.Default(), sink, []string{"httpx"}, nil)
	clock(tr)
	p := tr.Phase("httpx")
	p.Add("a:80", 1)
	p.Add("b:80", 1)
	tr.Flush(t.Context())
	tr.Flush(t.Context())
	p.Done("b:80", 1)
	tr.Flush(t.Context())

	if n := len(sink.updates); n != 3 {
		t.Fatalf("%d updates", n)
	}
	first, idle, last := sink.updates[0], sink.updates[1], sink.updates[2]
	if first.RunID != 7 || first.Phase != "httpx" || len(first.Phases) != 1 || len(first.Targets) != 2 {
		t.Errorf("first = %+v", first)
	}
	if len(idle.Phases) != 0 || len(idle.Targets) != 0 {
		t.Errorf("unchanged rows saved again: %+v", idle)
	}
	if len(last.Targets) != 1 || last.Targets[0].Target != "b:80" || last.Targets[0].Finished.IsZero() {
		t.Errorf("last = %+v", last)
	}
	if last.OverallPct != 50 {
		t.Errorf("overall = %v", last.OverallPct)
	}
}

func TestEndFinishesUnreportedWork(t *testing.T) {
	tr := New(1, slog.Default(), nil, []string{"nuclei"}, nil)
	clock(tr)
	p := tr.Phase("nuclei")
	p.Add("https://a", 130)
	p.Done("https://a", 120) // some templates never report for this input
	p.End()
	if tg := p.targets["https://a"]; tg.done != 130 || tg.finished.IsZero() {
		t.Errorf("target = %+v", tg)
	}
	if overall, _, _ := tr.estimate(); overall != 1 {
		t.Errorf("overall = %v", overall)
	}
}
