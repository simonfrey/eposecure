package gcpassetsearch

import (
	"maps"
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestCollectTargets(t *testing.T) {
	v, err := structpb.NewValue(map[string]any{
		"address":  "34.1.2.3",
		"internal": "10.0.0.5",
		"selfLink": "https://compute.googleapis.com/compute/v1/projects/p/regions/r/addresses/a",
		"status": map[string]any{
			"url":     "https://svc-abc-ew.a.run.app",
			"console": "https://console.cloud.google.com/run",
			"script":  "https://github.com/acme/setup.sh",
		},
		"ips": []any{"2600:1900::1", "not-an-ip"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	collectTargets(v, got)
	want := []string{"2600:1900::1", "34.1.2.3", "svc-abc-ew.a.run.app"}
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, want) {
		t.Fatalf("got %v, want %v", keys, want)
	}
}
