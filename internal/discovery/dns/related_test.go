package dns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/simonfrey/eposecure/internal/model"
)

func pemCert(t *testing.T, org string, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if org != "" {
		tmpl.Subject.Organization = []string{org}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// fakeCT serves crt.sh searches, certificate downloads and RDAP.
type fakeCT struct {
	search map[string][]crtEntry // "q=..." or "O=..."
	certs  map[int64][]byte
	rdap   map[string]string // domain → raw RDAP JSON
	down   bool              // crt.sh answers 503
}

func (f *fakeCT) related(t *testing.T, r Related) *Related {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		switch {
		case req.URL.Path == "/crt/" && f.down:
			w.WriteHeader(http.StatusServiceUnavailable)
		case req.URL.Path == "/crt/" && q.Has("d"):
			id, _ := strconv.ParseInt(q.Get("d"), 10, 64)
			_, _ = w.Write(f.certs[id])
		case req.URL.Path == "/crt/":
			key := "q=" + q.Get("q")
			if q.Has("O") {
				key = "O=" + q.Get("O")
			}
			_ = json.NewEncoder(w).Encode(f.search[key])
		default:
			body, ok := f.rdap[req.URL.Path[len("/rdap/"):]]
			if !ok {
				http.NotFound(w, req)
				return
			}
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	r.crtURL, r.rdapURL = srv.URL+"/crt/", srv.URL+"/rdap/"
	r.client = srv.Client()
	r.backoff = time.Millisecond
	r.init()
	return &r
}

func domains(rs []relatedDomain) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Domain)
	}
	return out
}

func TestRelatedFromSharedCertsAndOrg(t *testing.T) {
	f := &fakeCT{
		search: map[string][]crtEntry{
			"q=example.com": {
				{ID: 1, CommonName: "example.com", NameValue: "example.com", NotBefore: "2026-10-01"},
				// renewal with the same names: not downloaded again
				{ID: 2, CommonName: "example.com", NameValue: "example.com", NotBefore: "2026-01-01"},
			},
			"q=%.example.com": {{ID: 3, CommonName: "shop.example.com", NameValue: "shop.example.com", NotBefore: "2026-09-01"}},
			"O=Example GmbH":  {{ID: 4, CommonName: "example-corp.de", NameValue: "Example GmbH", NotBefore: "2026-08-01"}},
		},
		certs: map[int64][]byte{
			1: pemCert(t, "", "example.com", "*.example.net", "www.example.com"),
			2: pemCert(t, "", "renewal-only.org"),
			3: pemCert(t, "", "shop.example.com", "a.b.example.co.uk"),
			4: pemCert(t, "Example GmbH", "example-corp.de", "www.example-corp.de"),
		},
		rdap: map[string]string{"example.com": `{"entities":[{"roles":["registrant"],
			"vcardArray":["vcard",[["version",{},"text","4.0"],["org",{},"text","Example GmbH"]]]}]}`},
	}
	r := f.related(t, Related{})
	got, err := r.find(context.Background(), []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example-corp.de", "example.co.uk", "example.net"}
	if !slices.Equal(domains(got), want) {
		t.Fatalf("got %v, want %v", domains(got), want)
	}
}

func TestRelatedSkipsRedactedRegistrant(t *testing.T) {
	f := &fakeCT{rdap: map[string]string{"example.com": `{"entities":[{"roles":["registrant"],
		"vcardArray":["vcard",[["org",{},"text","REDACTED FOR PRIVACY"]]]}]}`}}
	r := f.related(t, Related{})
	orgs, err := r.deriveOrgs(context.Background(), []string{"example.com", "no-rdap.example"}, nil)
	if err != nil || len(orgs) != 0 {
		t.Fatalf("orgs=%v err=%v", orgs, err)
	}
}

func TestRelatedConfiguredOrgsAndCap(t *testing.T) {
	f := &fakeCT{
		search: map[string][]crtEntry{"O=Acme": {
			{ID: 1, CommonName: "old.test", NameValue: "Acme", NotBefore: "2025-01-01"},
			{ID: 2, CommonName: "new.test", NameValue: "Acme", NotBefore: "2026-01-01"},
		}},
		certs: map[int64][]byte{1: pemCert(t, "Acme", "old.test"), 2: pemCert(t, "Acme", "new.test")},
	}
	r := f.related(t, Related{Organizations: []string{"Acme"}, MaxCerts: 1})
	got, err := r.find(context.Background(), []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(domains(got), []string{"new.test"}) {
		t.Fatalf("got %v", domains(got))
	}
}

type fakeStore model.Snapshot

func (f fakeStore) LastSnapshot(context.Context) (model.Snapshot, error) {
	return model.Snapshot(f), nil
}

func TestRelatedKeepsLastRunWhenCrtShIsDown(t *testing.T) {
	f := &fakeCT{down: true}
	d := &DNS{RootDomains: []string{"example.com"}, Related: f.related(t, Related{})}
	d.last = fakeStore{Assets: []model.Asset{
		{Provider: "dns", Kind: "related_domain", Target: "example.net", Source: "dns"},
		{Provider: "dns", Kind: "hostname", Target: "www.example.com", Source: "dns"},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got := d.related(ctx)
	if len(got) != 1 || got[0].Target != "example.net" {
		t.Fatalf("got %+v", got)
	}
}
