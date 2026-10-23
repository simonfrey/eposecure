// Package cvelookup reports known CVEs for software versions httpx detected,
// by asking the NVD CVE API for each versioned CPE. Passive: no traffic to targets.
package cvelookup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

const nvdURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type CVELookup struct {
	APIKey      string `yaml:"api_key"`      // optional, raises the NVD rate limit 10x
	MinSeverity string `yaml:"min_severity"` // default medium
	BaseURL     string `yaml:"base_url"`

	http     *http.Client
	interval time.Duration
}

func New(o config.Options) (*CVELookup, error) {
	c := &CVELookup{MinSeverity: "medium", BaseURL: nvdURL, http: &http.Client{Timeout: 60 * time.Second}}
	if err := o.Decode(c); err != nil {
		return nil, err
	}
	// NVD allows 5 requests per 30s without a key and 50 with one.
	c.interval = 6 * time.Second
	if c.APIKey != "" {
		c.interval = 600 * time.Millisecond
	}
	return c, nil
}

func (c *CVELookup) Name() string { return "cve_lookup" }

type cve struct {
	ID       string
	Severity string
	Score    float64
	Summary  string
}

func (c *CVELookup) Scan(ctx context.Context, sc *model.ScanContext) error {
	cache := map[string][]cve{}
	var last time.Time
	for _, e := range sc.Endpoints {
		for _, cpe := range e.CPE {
			cves, ok := cache[cpe]
			if !ok {
				var err error
				// NVD returns sporadic 503s; retry a few times, backing off.
				for attempt := 1; ; attempt++ {
					if err := sleep(ctx, time.Duration(attempt)*c.interval-time.Since(last)); err != nil {
						return err
					}
					cves, err = c.lookup(ctx, cpe)
					last = time.Now()
					if err == nil || attempt == 3 {
						break
					}
				}
				if err != nil {
					return fmt.Errorf("nvd %s: %w", cpe, err)
				}
				cache[cpe] = cves
			}
			for _, v := range cves {
				if !model.SeverityAtLeast(v.Severity, c.MinSeverity) {
					continue
				}
				sc.Findings = append(sc.Findings, model.Finding{
					TemplateID: v.ID,
					Name:       v.Summary,
					Severity:   v.Severity,
					MatchedAt:  e.URL,
					Target:     e.Host,
					Scanner:    c.Name(),
					Raw:        map[string]any{"cpe": cpe, "score": v.Score},
				})
			}
		}
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics map[string][]struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
				BaseSeverity string `json:"baseSeverity"` // CVSS v2 keeps it here
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (c *CVELookup) lookup(ctx context.Context, cpe string) ([]cve, error) {
	q := url.Values{"cpeName": {cpe}, "resultsPerPage": {"2000"}}
	// isVulnerable drops CVEs where the CPE is only part of the environment
	// ("running on"); noRejected drops rejected CVEs. Both are valueless flags.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"?"+q.Encode()+"&isVulnerable&noRejected", nil)
	if err != nil {
		return nil, err
	}
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // CPE unknown to NVD
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	var body nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	cves := make([]cve, 0, len(body.Vulnerabilities))
	for _, v := range body.Vulnerabilities {
		out := cve{ID: v.CVE.ID}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				out.Summary = d.Value
				break
			}
		}
		// Prefer the newest CVSS version available.
		for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if m := v.CVE.Metrics[k]; len(m) > 0 {
				out.Score = m[0].CVSSData.BaseScore
				out.Severity = strings.ToLower(m[0].CVSSData.BaseSeverity + m[0].BaseSeverity)
				break
			}
		}
		cves = append(cves, out)
	}
	return cves, nil
}
