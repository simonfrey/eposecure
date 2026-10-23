// Package model holds the data that flows through a scan run.
package model

import (
	"net"
	"strconv"
)

// Asset is one public-facing thing a discoverer found.
type Asset struct {
	Provider string // gcp, aws, dns, static, ...
	Account  string // GCP project, AWS account, Azure subscription, DNS root domain
	Kind     string // service or resource type, e.g. compute, cloud-run, hostname
	Name     string // provider resource id or name
	Target   string // IP or hostname to scan
	Source   string // discovery module that produced it
}

// Endpoint is an open port on a target, optionally enriched with HTTP details.
type Endpoint struct {
	Host       string // hostname or IP as scanned
	IP         string
	Port       int
	URL        string
	HTTPStatus int
	Title      string
	Tech       []string // "app" or "app:version"
	CPE        []string // versioned CPE 2.3 strings
	Scanner    string
	// Service is the detected service on non-HTTP ports ("ssh", "redis",
	// "mysql", "dns", ...). Empty for plain TCP/HTTP endpoints.
	Service string
	// Protocol is "tcp" (default, also when empty) or "udp".
	Protocol string
}

// Addr returns host:port.
func (e Endpoint) Addr() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// Key identifies the endpoint across runs: host:port for TCP, host:port/udp for UDP.
func (e Endpoint) Key() string {
	if e.Protocol == "udp" {
		return e.Addr() + "/udp"
	}
	return e.Addr()
}

// Finding is a vulnerability or misconfiguration on an endpoint.
type Finding struct {
	TemplateID string // nuclei template id or CVE id
	Name       string
	Severity   string // info, low, medium, high, critical
	MatchedAt  string
	Target     string
	Scanner    string
	Tags       []string // nuclei template tags
	Exploited  bool     // listed in CISA KEV (actively exploited)
	EPSS       float64  // exploit probability within 30 days, 0..1
	Raw        any      // stored as jsonb
}

// ScanContext is passed through the scanners in order. Each scanner reads
// what earlier ones produced and adds its own results.
type ScanContext struct {
	Targets []string // IPs to port-scan
	// Names maps each IP to the inventory targets behind it: hostnames that
	// resolve to it, and the IP itself if it was discovered as such. Open
	// ports are reported per name, never for an IP that is not inventory
	// (e.g. a CDN or Cloud Run frontend shared with other customers).
	Names     map[string][]string
	Endpoints []Endpoint
	Findings  []Finding
	// TakeoverCandidates are hostnames from discovery that do not resolve
	// but still have a CNAME. nuclei's takeover templates check whether the
	// resource behind them can be claimed.
	TakeoverCandidates []string
}

// Snapshot is the complete result of one successful run.
type Snapshot struct {
	Assets    []Asset
	Endpoints []Endpoint
	Findings  []Finding
}

// Event types emitted by the diff between two runs.
const (
	NewEndpoint     = "new_endpoint"
	ClosedEndpoint  = "closed_endpoint"
	NewFinding      = "new_finding"
	ResolvedFinding = "resolved_finding"
	NewAsset        = "new_asset"
	RemovedAsset    = "removed_asset"
	RiskChanged     = "risk_changed"
)

// Event is a change between the previous and the current run.
// Flat fields so Grafana can use them as alert labels.
type Event struct {
	Type     string
	Target   string
	Port     int
	Severity string
	Provider string
	Account  string
	Resource string
	Detail   map[string]any
}

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// SeverityAtLeast reports whether sev is at or above min. Unknown severities rank lowest.
func SeverityAtLeast(sev, min string) bool {
	return severityRank[sev] >= severityRank[min]
}
