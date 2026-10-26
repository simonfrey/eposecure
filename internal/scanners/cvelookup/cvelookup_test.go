package cvelookup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/simonfrey/eposecure/internal/config"
	"github.com/simonfrey/eposecure/internal/model"
	"github.com/simonfrey/eposecure/internal/store"
)

const nvdBody = `{"totalResults": 3, "vulnerabilities": [
 {"cve": {"id": "CVE-2021-23017", "descriptions": [{"lang": "en", "value": "resolver bug"}],
   "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.7, "baseSeverity": "HIGH"}}]}}},
 {"cve": {"id": "CVE-2009-0001", "descriptions": [{"lang": "en", "value": "old"}],
   "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]}}},
 {"cve": {"id": "CVE-2020-0002", "descriptions": [{"lang": "en", "value": "minor"}],
   "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 2.0, "baseSeverity": "LOW"}}]}}}
]}`

func TestScan(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.URL.Query().Get("cpeName"); got != "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*" {
			t.Errorf("cpeName = %q", got)
		}
		if q := r.URL.Query(); !q.Has("isVulnerable") || !q.Has("noRejected") {
			t.Errorf("precision flags missing: %s", r.URL.RawQuery)
		}
		if r.Header.Get("apiKey") != "k" {
			t.Error("api key header missing")
		}
		_, _ = w.Write([]byte(nvdBody))
	}))
	defer srv.Close()

	c, err := New(config.Options{"base_url": srv.URL, "api_key": "k"})
	if err != nil {
		t.Fatal(err)
	}
	c.interval = 0
	cpe := "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
	sc := &model.ScanContext{Endpoints: []model.Endpoint{
		{Host: "a.example.com", Port: 443, URL: "https://a.example.com", CPE: []string{cpe}},
		{Host: "b.example.com", Port: 443, URL: "https://b.example.com", CPE: []string{cpe}},
	}}
	if err := c.Scan(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("same CPE should be looked up once, got %d calls", calls)
	}
	// 2 endpoints x 2 CVEs at or above medium (the low one is filtered).
	if len(sc.Findings) != 4 {
		t.Fatalf("want 4 findings, got %+v", sc.Findings)
	}
	f := sc.Findings[0]
	if f.TemplateID != "CVE-2021-23017" || f.Severity != "high" || f.MatchedAt != "https://a.example.com" {
		t.Errorf("unexpected finding %+v", f)
	}
	if sc.Findings[1].Severity != "medium" {
		t.Errorf("CVSS v2 severity not read: %+v", sc.Findings[1])
	}
}

func TestUnknownCPEIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c, _ := New(config.Options{"base_url": srv.URL})
	c.interval = 0
	sc := &model.ScanContext{Endpoints: []model.Endpoint{{CPE: []string{"cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"}}}}
	if err := c.Scan(context.Background(), sc); err != nil || len(sc.Findings) != 0 {
		t.Fatalf("err=%v findings=%v", err, sc.Findings)
	}
}

type fakeCache map[string]store.CVECacheEntry

func (f fakeCache) GetCVECache(_ context.Context, cpes []string) (map[string]store.CVECacheEntry, error) {
	out := map[string]store.CVECacheEntry{}
	for _, c := range cpes {
		if e, ok := f[c]; ok {
			out[c] = e
		}
	}
	return out, nil
}

func (f fakeCache) PutCVECache(_ context.Context, entries map[string][]byte) error {
	for c, d := range entries {
		f[c] = store.CVECacheEntry{Data: d, FetchedAt: time.Now()}
	}
	return nil
}

func TestCache(t *testing.T) {
	const cpe = "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"
	cached := []byte(`[{"id":"CVE-2024-6387","severity":"high","score":8.1,"summary":"regreSSHion"}]`)
	status := http.StatusOK
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(status)
		_, _ = w.Write([]byte(nvdBody))
	}))
	defer srv.Close()
	scan := func(fc fakeCache) ([]model.Finding, error) {
		c, _ := New(config.Options{"base_url": srv.URL})
		c.interval, c.cache = 0, fc
		sc := &model.ScanContext{Endpoints: []model.Endpoint{{Host: "a.example.com", Port: 22, CPE: []string{cpe}}}}
		err := c.Scan(context.Background(), sc)
		return sc.Findings, err
	}

	// Fresh entry: no NVD call. Findings of non-HTTP endpoints point at host:port.
	calls = 0
	got, err := scan(fakeCache{cpe: {Data: cached, FetchedAt: time.Now().Add(-time.Hour)}})
	if err != nil || calls != 0 || len(got) != 1 || got[0].TemplateID != "CVE-2024-6387" || got[0].MatchedAt != "a.example.com:22" {
		t.Fatalf("fresh: calls=%d err=%v findings=%+v", calls, err, got)
	}

	// Stale entry and NVD down: the stale entry is used.
	calls, status = 0, http.StatusServiceUnavailable
	got, err = scan(fakeCache{cpe: {Data: cached, FetchedAt: time.Now().Add(-48 * time.Hour)}})
	if err != nil || calls != 3 || len(got) != 1 {
		t.Fatalf("stale fallback: calls=%d err=%v findings=%+v", calls, err, got)
	}

	// No entry and NVD down: the run fails.
	if _, err := scan(fakeCache{}); err == nil {
		t.Fatal("miss with NVD down should fail")
	}

	// Stale entry and NVD up: refetched and written back.
	status = http.StatusOK
	fc := fakeCache{cpe: {Data: cached, FetchedAt: time.Now().Add(-48 * time.Hour)}}
	got, err = scan(fc)
	if err != nil || len(got) != 2 || time.Since(fc[cpe].FetchedAt) > time.Minute {
		t.Fatalf("refresh: err=%v findings=%+v entry=%+v", err, got, fc[cpe])
	}
}
