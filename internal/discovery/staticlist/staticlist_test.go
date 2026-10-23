package staticlist

import (
	"slices"
	"strings"
	"testing"

	"github.com/simonfrey/exposure-scanner/internal/config"
)

func targets(t *testing.T, s *StaticList) []string {
	t.Helper()
	assets, err := s.Discover(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, a := range assets {
		out = append(out, a.Target)
	}
	return out
}

func TestExpand(t *testing.T) {
	s, err := New(config.Options{"targets": []any{"192.0.2.0/30", "198.51.100.8/31", "203.0.113.5/32",
		"2001:db8::/127", "1.2.3.4", "app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "192.0.2.2", "198.51.100.8", "198.51.100.9", "203.0.113.5",
		"2001:db8::", "2001:db8::1", "1.2.3.4", "app.example.com"}
	if got := targets(t, s); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExpandUnmaskedPrefix(t *testing.T) {
	s, err := New(config.Options{"targets": []any{"192.0.2.77/24"}})
	if err != nil {
		t.Fatal(err)
	}
	got := targets(t, s)
	if len(got) != 254 || got[0] != "192.0.2.1" || got[253] != "192.0.2.254" {
		t.Fatalf("got %d targets, first %s, last %s", len(got), got[0], got[len(got)-1])
	}
}

func TestMaxIPs(t *testing.T) {
	for _, cidr := range []string{"10.0.0.0/8", "2001:db8::/64", "::/0"} {
		_, err := New(config.Options{"targets": []any{cidr}})
		if err == nil || !strings.Contains(err.Error(), "max_ips") {
			t.Errorf("%s: err = %v", cidr, err)
		}
	}
	if _, err := New(config.Options{"targets": []any{"10.0.0.0/16"}, "max_ips": 70000}); err != nil {
		t.Errorf("raised max_ips: %v", err)
	}
}
