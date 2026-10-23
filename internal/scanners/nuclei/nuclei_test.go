package nuclei

import (
	"slices"
	"testing"

	"github.com/simonfrey/exposure-scanner/internal/config"
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
