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
}

// Addr returns host:port.
func (e Endpoint) Addr() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// Finding is a vulnerability or misconfiguration on an endpoint.
type Finding struct {
	TemplateID string // nuclei template id or CVE id
	Name       string
	Severity   string // info, low, medium, high, critical
	MatchedAt  string
	Target     string
	Scanner    string
	Raw        any // stored as jsonb
}

// ScanContext is passed through the scanners in order. Each scanner reads
// what earlier ones produced and adds its own results.
type ScanContext struct {
	Targets   []string
	Endpoints []Endpoint
	Findings  []Finding
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
