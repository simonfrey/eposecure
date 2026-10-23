package pipeline

import (
	"context"
	"log/slog"
	"slices"
	"testing"

	"github.com/simonfrey/exposure-scanner/internal/model"
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
