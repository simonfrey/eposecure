package nuclei

import (
	"slices"
	"testing"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

func TestOptions(t *testing.T) {
	n, err := New(config.Options{"tags": []any{"panel", "exposure"}, "severities": []any{"info"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(n.Tags, []string{"panel", "exposure"}) || !slices.Equal(n.Severities, []string{"info"}) {
		t.Errorf("not decoded: %+v", n)
	}
	if !slices.Equal(n.ExcludeTags, []string{"dos", "fuzz", "intrusive"}) {
		t.Errorf("unsafe templates not excluded by default: %v", n.ExcludeTags)
	}
}

func TestTargets(t *testing.T) {
	sc := &model.ScanContext{
		Endpoints: []model.Endpoint{
			{Host: "a.example.com", Port: 443, URL: "https://a.example.com"},
			{Host: "a.example.com", Port: 22},
			{Host: "a.example.com", Port: 161, Protocol: "udp"},
		},
		TakeoverCandidates: []string{"old.example.com"},
	}
	n := &Nuclei{}
	if got, want := n.targets(sc), []string{"https://a.example.com", "a.example.com:22"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	n.TakeoverCandidates = true
	if got, want := n.targets(sc), []string{"https://a.example.com", "a.example.com:22", "old.example.com"}; !slices.Equal(got, want) {
		t.Errorf("with takeover candidates: got %v, want %v", got, want)
	}
}
