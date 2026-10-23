package httpx

import "testing"

func TestVersionedCPE(t *testing.T) {
	base := "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
	cases := map[[2]string]string{
		{base, "nginx:1.18.0"}: "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
		{base, "nginx"}:        "", // no version, nothing precise to look up
		{"", "nginx:1.18.0"}:   "", // no CPE known
	}
	for in, want := range cases {
		if got := versionedCPE(in[0], in[1]); got != want {
			t.Errorf("versionedCPE(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
