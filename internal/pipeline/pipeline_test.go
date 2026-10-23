package pipeline

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/simonfrey/exposure-scanner/internal/model"
	"github.com/simonfrey/exposure-scanner/internal/registry"
)

func TestTargets(t *testing.T) {
	assets := []model.Asset{
		{Target: "1.2.3.4"}, {Target: "1.2.3.4"}, // duplicate
		{Target: "10.1.2.3"},         // excluded by CIDR
		{Target: "skip.example.com"}, // excluded by name
		{Target: "api.example.com"},
		{Target: ""},
	}
	got := targets(assets, []string{"10.0.0.0/8", "SKIP.example.com"})
	want := []string{"1.2.3.4", "api.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"https://svc-abc.a.run.app/": "svc-abc.a.run.app",
		"WWW.Example.com.":           "www.example.com",
		"1.2.3.4":                    "1.2.3.4",
	} {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveScansEachIPOnce(t *testing.T) {
	ips, names := resolve(context.Background(), slog.Default(), []string{"127.0.0.1", "localhost"}, []string{"::1/128"})
	if !slices.Equal(ips, []string{"127.0.0.1"}) {
		t.Fatalf("ips = %v (::1 is excluded)", ips)
	}
	if got := names["127.0.0.1"]; !slices.Equal(got, []string{"127.0.0.1", "localhost"}) {
		t.Fatalf("names = %v", got)
	}
}

func TestStillOpen(t *testing.T) {
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	openPort := l.Addr().(*net.TCPAddr).Port
	closed, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()

	prev := model.Snapshot{
		Endpoints: []model.Endpoint{
			{Host: "127.0.0.1", Port: openPort},   // missed by the scan, still open
			{Host: "127.0.0.1", Port: closedPort}, // really closed
			{Host: "localhost", Port: 1},          // found again
			{Host: "gone.example.com", Port: 443}, // left the inventory, not re-checked
		},
		Findings: []model.Finding{
			{TemplateID: "a", MatchedAt: "http://127.0.0.1:" + strconv.Itoa(openPort) + "/x"},
			{TemplateID: "b", MatchedAt: "127.0.0.1:" + strconv.Itoa(closedPort)},
		},
	}
	cur := []model.Endpoint{{Host: "localhost", Port: 1}}
	names := map[string][]string{"127.0.0.1": {"127.0.0.1", "localhost"}}
	eps, findings := stillOpen(context.Background(), prev, cur, names)
	if len(eps) != 1 || eps[0].Port != openPort || eps[0].Scanner != "verify" {
		t.Fatalf("endpoints = %+v", eps)
	}
	if len(findings) != 1 || findings[0].TemplateID != "a" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestAddrOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://a.example.com/x?y=1": "a.example.com:443",
		"http://1.2.3.4:8080":         "1.2.3.4:8080",
		"1.2.3.4:22":                  "1.2.3.4:22",
		"a.example.com:6379":          "a.example.com:6379",
	} {
		if got := addrOf(in); got != want {
			t.Errorf("addrOf(%q) = %q, want %q", in, got, want)
		}
	}
}

type named string

func (n named) Name() string                                    { return string(n) }
func (n named) Discover(context.Context) ([]model.Asset, error) { return nil, nil }

func TestCheckDrift(t *testing.T) {
	p := &Pipeline{discoverers: []registry.Discoverer{named("dns"), named("cloudlist")}, maxDropPct: 50}
	eps := func(n int) []model.Endpoint { return make([]model.Endpoint, n) }
	assets := func(sources ...string) (out []model.Asset) {
		for _, s := range sources {
			out = append(out, model.Asset{Source: s})
		}
		return out
	}
	prev := model.Snapshot{Assets: assets("dns", "cloudlist"), Endpoints: eps(10)}

	for name, tc := range map[string]struct {
		cur     model.Snapshot
		wantErr string
	}{
		"ok":               {model.Snapshot{Assets: assets("dns", "cloudlist"), Endpoints: eps(5)}, ""},
		"source empty":     {model.Snapshot{Assets: assets("cloudlist"), Endpoints: eps(10)}, "discovery dns returned 0 assets"},
		"endpoints halved": {model.Snapshot{Assets: assets("dns", "cloudlist"), Endpoints: eps(4)}, "endpoints dropped from 10 to 4"},
	} {
		err := p.checkDrift(prev, tc.cur)
		if (err == nil) != (tc.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.wantErr)
		}
	}
	if err := p.checkDrift(model.Snapshot{}, model.Snapshot{}); err != nil {
		t.Errorf("first run: %v", err)
	}
}

func TestUnique(t *testing.T) {
	got := unique([]model.Finding{
		{TemplateID: "git-config", MatchedAt: "http://a/.git/config", Scanner: "nuclei"},
		{TemplateID: "CVE-1", MatchedAt: "http://a"},
		{TemplateID: "git-config", MatchedAt: "http://a/.git/config", Scanner: "second pass"},
		{TemplateID: "git-config", MatchedAt: "http://b/.git/config"},
	})
	if len(got) != 3 || got[0].Scanner != "nuclei" {
		t.Fatalf("got %+v", got)
	}
}

func TestSplitTakeover(t *testing.T) {
	scan, takeover := splitTakeover([]model.Asset{
		{Kind: "hostname", Target: "www.example.com"},
		{Kind: "takeover", Target: "old.example.com"},
		{Kind: "compute", Target: "1.2.3.4"},
	})
	if len(scan) != 2 || len(takeover) != 1 || takeover[0].Target != "old.example.com" {
		t.Fatalf("scan=%+v takeover=%+v", scan, takeover)
	}
}

func TestStillOpenSkipsUDP(t *testing.T) {
	prev := model.Snapshot{Endpoints: []model.Endpoint{{Host: "127.0.0.1", Port: 161, Protocol: "udp"}}}
	names := map[string][]string{"127.0.0.1": {"127.0.0.1"}}
	if eps, _ := stillOpen(context.Background(), prev, nil, names); len(eps) != 0 {
		t.Fatalf("udp endpoint re-checked over tcp: %+v", eps)
	}
}
