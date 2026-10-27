package dns

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
	"golang.org/x/sync/errgroup"
)

// Related finds other domains of the same owner in certificate transparency
// logs (crt.sh). Real reverse WHOIS has no free source: RDAP has no public
// reverse search and registrant data is mostly redacted. Certificates are
// public, though: OV/EV certificates name the organization, and one
// certificate often covers several of the owner's domains.
type Related struct {
	// Organizations to search certificates for. Empty: derived from the
	// root domains' RDAP registrant and their certificates.
	Organizations []string `yaml:"organizations"`
	// AutoScan enumerates and scans found domains like root_domains.
	// Otherwise they are only reported.
	AutoScan bool `yaml:"auto_scan"`
	// MaxCerts caps certificate downloads per run, newest first.
	MaxCerts int `yaml:"max_certs"`

	crtURL  string // overridable in tests
	rdapURL string
	client  *http.Client
	backoff time.Duration
}

// relatedDomain is a registrable domain found via a root domain's certificates.
type relatedDomain struct {
	Domain string
	Seed   string // the root domain it was found through
}

type crtEntry struct {
	ID         int64  `json:"id"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	seed       string
}

func (r *Related) init() {
	if r.MaxCerts <= 0 {
		r.MaxCerts = 200
	}
	r.crtURL = cmp.Or(r.crtURL, "https://crt.sh/")
	r.rdapURL = cmp.Or(r.rdapURL, "https://rdap.org/domain/")
	r.backoff = cmp.Or(r.backoff, 5*time.Second)
	if r.client == nil {
		r.client = &http.Client{Timeout: 60 * time.Second}
	}
}

// find returns the related domains of roots. It is best effort: on errors it
// still returns what it found, plus the joined errors, so the caller can
// decide how to treat a partial answer.
func (r *Related) find(ctx context.Context, roots []string) ([]relatedDomain, error) {
	var errs []error
	var entries []crtEntry
	for _, root := range roots {
		for _, q := range []string{root, "%." + root} {
			e, err := r.search(ctx, "q", q)
			if err != nil {
				errs = append(errs, err)
			}
			entries = append(entries, withSeed(e, root)...)
		}
	}
	rootCerts, err := r.download(ctx, newest(entries, r.MaxCerts))
	errs = append(errs, err)

	orgs := r.Organizations
	if len(orgs) == 0 {
		orgs, err = r.deriveOrgs(ctx, roots, rootCerts)
		errs = append(errs, err)
		slog.Info("related domains: searching certificates by organization", "module", "dns", "orgs", orgs)
	}
	var orgEntries []crtEntry
	for _, org := range orgs {
		e, err := r.search(ctx, "O", org)
		if err != nil {
			errs = append(errs, err)
		}
		// Org certificates belong to no root; attribute them to the first.
		orgEntries = append(orgEntries, withSeed(e, roots[0])...)
	}
	orgCerts, err := r.download(ctx, newest(orgEntries, r.MaxCerts-len(rootCerts)))
	errs = append(errs, err)

	seen := map[string]bool{}
	var out []relatedDomain
	for _, c := range slices.Concat(rootCerts, orgCerts) {
		for _, name := range c.names {
			d, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimPrefix(strings.ToLower(name), "*."))
			if err != nil || seen[d] || underAny(d, roots) {
				continue
			}
			seen[d] = true
			out = append(out, relatedDomain{Domain: d, Seed: c.seed})
		}
	}
	slices.SortFunc(out, func(a, b relatedDomain) int { return strings.Compare(a.Domain, b.Domain) })
	return out, errors.Join(errs...)
}

func withSeed(entries []crtEntry, seed string) []crtEntry {
	for i := range entries {
		entries[i].seed = seed
	}
	return entries
}

// newest drops renewals (same names) and keeps the n most recent certificates.
func newest(entries []crtEntry, n int) []crtEntry {
	slices.SortFunc(entries, func(a, b crtEntry) int { return strings.Compare(b.NotBefore, a.NotBefore) })
	seen := map[string]bool{}
	entries = slices.DeleteFunc(entries, func(e crtEntry) bool {
		k := e.CommonName + "|" + e.NameValue
		dup := seen[k]
		seen[k] = true
		return dup
	})
	return entries[:min(len(entries), max(n, 0))]
}

func underAny(domain string, roots []string) bool {
	return slices.ContainsFunc(roots, func(r string) bool {
		return domain == r || strings.HasSuffix(domain, "."+r) || strings.HasSuffix(r, "."+domain)
	})
}

// search lists unexpired certificates matching one crt.sh query parameter.
func (r *Related) search(ctx context.Context, param, value string) ([]crtEntry, error) {
	q := url.Values{param: {value}, "exclude": {"expired"}, "output": {"json"}}
	body, err := r.get(ctx, r.crtURL+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("crt.sh %s=%s: %w", param, value, err)
	}
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh %s=%s: %w", param, value, err)
	}
	return entries, nil
}

type cert struct {
	seed  string
	names []string
	orgs  []string
}

// download fetches the certificates, since crt.sh search results only show
// the names that matched, not all names on the certificate.
func (r *Related) download(ctx context.Context, entries []crtEntry) ([]cert, error) {
	var mu sync.Mutex
	var certs []cert
	var errs []error
	var g errgroup.Group
	g.SetLimit(4)
	for _, e := range entries {
		g.Go(func() error {
			c, err := r.fetchCert(ctx, e.ID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("crt.sh certificate %d: %w", e.ID, err))
				return nil
			}
			certs = append(certs, cert{seed: e.seed, names: c.DNSNames, orgs: c.Subject.Organization})
			return nil
		})
	}
	_ = g.Wait()
	return certs, errors.Join(errs...)
}

func (r *Related) fetchCert(ctx context.Context, id int64) (*x509.Certificate, error) {
	body, err := r.get(ctx, r.crtURL+"?d="+strconv.FormatInt(id, 10))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// deriveOrgs collects the organization names of the root domains: the RDAP
// registrant where it is not redacted, and the subject of OV/EV certificates.
func (r *Related) deriveOrgs(ctx context.Context, roots []string, certs []cert) ([]string, error) {
	var orgs []string
	var errs []error
	for _, root := range roots {
		org, err := r.registrant(ctx, root)
		if err != nil {
			errs = append(errs, err)
		}
		orgs = append(orgs, org)
	}
	for _, c := range certs {
		orgs = append(orgs, c.orgs...)
	}
	orgs = slices.DeleteFunc(orgs, func(o string) bool { return o == "" || redacted(o) })
	slices.Sort(orgs)
	return slices.Compact(orgs), errors.Join(errs...)
}

func redacted(org string) bool {
	o := strings.ToLower(org)
	return strings.Contains(o, "redacted") || strings.Contains(o, "privacy") ||
		strings.Contains(o, "proxy") || strings.Contains(o, "withheld") || strings.Contains(o, "not disclosed")
}

// registrant returns the registrant organization from RDAP, or "".
func (r *Related) registrant(ctx context.Context, domain string) (string, error) {
	body, err := r.get(ctx, r.rdapURL+domain)
	if errors.Is(err, errNotFound) {
		return "", nil // TLD without RDAP
	}
	if err != nil {
		return "", fmt.Errorf("rdap %s: %w", domain, err)
	}
	var resp struct {
		Entities []struct {
			Roles      []string          `json:"roles"`
			VCardArray []json.RawMessage `json:"vcardArray"`
		} `json:"entities"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("rdap %s: %w", domain, err)
	}
	for _, e := range resp.Entities {
		if !slices.Contains(e.Roles, "registrant") || len(e.VCardArray) < 2 {
			continue
		}
		// jCard: ["vcard", [[name, params, type, value], ...]]
		var props [][]any
		if json.Unmarshal(e.VCardArray[1], &props) != nil {
			continue
		}
		for _, p := range props {
			if len(p) == 4 && p[0] == "org" {
				if s, ok := p[3].(string); ok {
					return s, nil
				}
			}
		}
	}
	return "", nil
}

var errNotFound = errors.New("not found")

// get retries throttling and server errors, which crt.sh returns often.
func (r *Related) get(ctx context.Context, u string) ([]byte, error) {
	var err error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * r.backoff):
			}
		}
		var body []byte
		var retry bool
		body, retry, err = r.getOnce(ctx, u)
		if err == nil || !retry {
			return body, err
		}
	}
	return nil, err
}

func (r *Related) getOnce(ctx context.Context, u string) (body []byte, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, ctx.Err() == nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		retry = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return body, err != nil, err
}
