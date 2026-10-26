package httpx

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/simonfrey/exposure-scanner/internal/model"
)

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

type counter struct {
	mu   sync.Mutex
	done map[string]int
}

func (c *counter) Add(string, int) {}
func (c *counter) Done(target string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done[target] += n
}
func (c *counter) Finish(string) {}

// Ports that do not speak HTTP must count as progress too, or the phase
// would look stuck at the share of HTTP endpoints.
func TestScanReportsFailedInputs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	open := srv.Listener.Addr().(*net.TCPAddr).Port
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	h, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Timeout = 2
	c := &counter{done: map[string]int{}}
	sc := &model.ScanContext{
		Endpoints: []model.Endpoint{{Host: "127.0.0.1", Port: open}, {Host: "127.0.0.1", Port: closed}},
		Reporter:  c,
	}
	if err := h.Scan(t.Context(), sc); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{open, closed} {
		if addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port)); c.done[addr] != 1 {
			t.Errorf("%s reported %d times", addr, c.done[addr])
		}
	}
	if sc.Endpoints[0].URL == "" || sc.Endpoints[1].URL != "" {
		t.Errorf("endpoints = %+v", sc.Endpoints)
	}
}
