package nuclei

import (
	"slices"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/simonfrey/eposecure/internal/config"
	"github.com/simonfrey/eposecure/internal/model"
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

func TestInteractsh(t *testing.T) {
	n, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o := n.interactsh(); !o.NoInteractsh {
		t.Errorf("callbacks on without a server (would use public oast.* servers): %+v", o)
	} else if o.CacheSize <= 0 {
		t.Errorf("nuclei panics on a zero cache size even with callbacks off: %+v", o)
	}
	n, err = New(config.Options{"interactsh_server": "https://oob.example.com", "interactsh_token": "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if o := n.interactsh(); o.NoInteractsh || o.ServerURL != "https://oob.example.com" || o.Authorization != "s3cret" {
		t.Errorf("own server not used: %+v", o)
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

func TestAttribute(t *testing.T) {
	in := newInputs([]string{"https://a.example.com", "http://a.example.com:8080", "a.example.com:22", "old.example.com"})
	for i, c := range []struct {
		ev        output.ResultEvent
		key       string
		first     bool
		situation string
	}{
		{output.ResultEvent{TemplateID: "t1", Host: "a.example.com", Port: "443"}, "https://a.example.com", true, "by host and port"},
		{output.ResultEvent{TemplateID: "t1", Host: "a.example.com", Port: "443"}, "", false, "second match of the same template"},
		{output.ResultEvent{TemplateID: "t1", Host: "a.example.com:8080"}, "http://a.example.com:8080", true, "host:port in Host"},
		{output.ResultEvent{TemplateID: "dns", Host: "a.example.com"}, "https://a.example.com", true, "no port: first target on the host"},
		{output.ResultEvent{TemplateID: "dns", Host: "a.example.com"}, "http://a.example.com:8080", true, "no port: next target on the host"},
		{output.ResultEvent{TemplateID: "t2", URL: "a.example.com:22"}, "a.example.com:22", true, "from the URL"},
		{output.ResultEvent{TemplateID: "t2", Host: "OLD.example.com", Port: "80"}, "old.example.com", true, "bare hostname"},
		{output.ResultEvent{TemplateID: "t2", Host: "other.example.com"}, "", false, "unknown host"},
	} {
		key, first := in.attribute(&c.ev)
		if key != c.key || first != c.first {
			t.Errorf("%d %s: got %q %v, want %q %v", i, c.situation, key, first, c.key, c.first)
		}
	}
}
