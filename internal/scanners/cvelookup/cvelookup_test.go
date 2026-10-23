package cvelookup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
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
