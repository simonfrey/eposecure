// Package httpx probes every open port for HTTP(S) and records status, title,
// detected technologies and their versioned CPEs.
package httpx

import (
	"context"
	"strings"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

type HTTPX struct {
	Threads   int `yaml:"threads"`
	RateLimit int `yaml:"rate_limit"` // requests per second
	Timeout   int `yaml:"timeout"`    // seconds
	// FollowHostRedirects follows redirects that stay on the same host, so
	// "/" -> "/login" reports the real page. Redirects to other hosts (SSO,
	// a CDN) are never followed: their title and software are not ours.
	FollowHostRedirects bool `yaml:"follow_host_redirects"`
	MaxRedirects        int  `yaml:"max_redirects"`
}

func New(o config.Options) (*HTTPX, error) {
	h := &HTTPX{Threads: 25, RateLimit: 50, Timeout: 10, FollowHostRedirects: true, MaxRedirects: 3}
	return h, o.Decode(h)
}

func (h *HTTPX) Name() string { return "httpx" }

func (h *HTTPX) Scan(_ context.Context, sc *model.ScanContext) error {
	if len(sc.Endpoints) == 0 {
		return nil
	}
	byAddr := map[string]*model.Endpoint{}
	var inputs goflags.StringSlice
	for i := range sc.Endpoints {
		e := &sc.Endpoints[i]
		if e.Protocol == "udp" {
			continue
		}
		byAddr[e.Addr()] = e
		inputs = append(inputs, e.Addr())
	}
	if len(inputs) == 0 {
		return nil
	}

	var mu sync.Mutex
	opts := &runner.Options{
		Methods:             "GET",
		InputTargetHost:     inputs,
		Threads:             h.Threads,
		RateLimit:           h.RateLimit,
		Timeout:             h.Timeout,
		Retries:             1,
		TechDetect:          true,
		ExtractTitle:        true,
		StatusCode:          true,
		FollowRedirects:     false,
		FollowHostRedirects: h.FollowHostRedirects,
		MaxRedirects:        h.MaxRedirects,
		DisableStdin:        true,
		DisableUpdateCheck:  true,
		Silent:              true,
		DisableStdout:       true,
		OnResult: func(r runner.Result) {
			if r.Err != nil || r.Failed {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			e, ok := byAddr[r.Input]
			if !ok {
				return
			}
			e.URL, e.HTTPStatus, e.Title, e.Tech = r.URL, r.StatusCode, r.Title, r.Technologies
			e.CPE = nil
			for tech, info := range r.TechnologyDetails {
				if cpe := versionedCPE(info.CPE, tech); cpe != "" {
					e.CPE = append(e.CPE, cpe)
				}
			}
		},
	}
	if err := opts.ValidateOptions(); err != nil {
		return err
	}
	r, err := runner.New(opts)
	if err != nil {
		return err
	}
	defer r.Close()
	r.RunEnumeration()
	return nil
}

// versionedCPE puts the detected version ("nginx:1.18.0") into the product
// CPE from wappalyzer ("cpe:2.3:a:f5:nginx:*:*:..."). Without a version or
// CPE there is nothing precise to look up, so it returns "".
func versionedCPE(cpe, tech string) string {
	_, version, ok := strings.Cut(tech, ":")
	parts := strings.Split(cpe, ":")
	if !ok || version == "" || len(parts) != 13 {
		return ""
	}
	parts[5] = version
	return strings.Join(parts, ":")
}
