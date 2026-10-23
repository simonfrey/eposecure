package registry

import (
	"testing"

	"github.com/simonfrey/exposure-scanner/internal/config"
)

func TestUnknownModuleFails(t *testing.T) {
	if _, err := Scanners([]config.Module{{Use: "tsunami"}}); err == nil {
		t.Fatal("expected error for unknown scanner")
	}
	if _, err := Discoverers([]config.Module{{Use: "nope"}}); err == nil {
		t.Fatal("expected error for unknown discoverer")
	}
}

func TestBuildsInConfigOrder(t *testing.T) {
	s, err := Scanners([]config.Module{{Use: "cve_lookup"}, {Use: "naabu"}, {Use: "httpx"}, {Use: "nuclei"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cve_lookup", "naabu", "httpx", "nuclei"}
	for i, sc := range s {
		if sc.Name() != want[i] {
			t.Fatalf("position %d: got %s, want %s", i, sc.Name(), want[i])
		}
	}
}

// Adding another cloud must be config only: an AWS provider block builds
// without any GCP settings present.
func TestCloudlistAcceptsOtherProviders(t *testing.T) {
	d, err := Discoverers([]config.Module{{Use: "cloudlist", Options: config.Options{
		"providers": []any{map[string]any{
			"provider":       "aws",
			"id":             "prod",
			"aws_access_key": "AKIAEXAMPLE",
			"aws_secret_key": "secret",
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if d[0].Name() != "cloudlist" {
		t.Fatalf("got %s", d[0].Name())
	}
}
