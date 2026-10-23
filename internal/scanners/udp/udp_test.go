package udp

import (
	"net"
	"strings"
	"testing"

	miekgdns "github.com/miekg/dns"

	"github.com/simonfrey/exposure-scanner/internal/config"
)

func TestNewRejectsUnknownPort(t *testing.T) {
	if _, err := New(config.Options{"ports": []any{53, 500}}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
}

func TestDNSCheck(t *testing.T) {
	q := new(miekgdns.Msg)
	if err := q.Unpack(dnsRequest()); err != nil || !q.RecursionDesired {
		t.Fatalf("request: %v %+v", err, q)
	}
	reply := func(ra bool, rcode int, answers int) []byte {
		m := new(miekgdns.Msg)
		m.SetRcode(q, rcode)
		m.RecursionAvailable = ra
		for range answers {
			rr, _ := miekgdns.NewRR("example.com. 60 IN A 192.0.2.1")
			m.Answer = append(m.Answer, rr)
		}
		b, _ := m.Pack()
		return b
	}
	if ok, f := dnsCheck(reply(true, miekgdns.RcodeSuccess, 1)); !ok || f == nil || f.id != "udp-dns-open-resolver" {
		t.Errorf("open resolver: ok=%v f=%+v", ok, f)
	}
	if ok, f := dnsCheck(reply(false, miekgdns.RcodeRefused, 0)); !ok || f != nil {
		t.Errorf("authoritative only: ok=%v f=%+v", ok, f)
	}
	if ok, _ := dnsCheck(dnsRequest()); ok {
		t.Error("a query is not a response")
	}
}

func TestChecks(t *testing.T) {
	ntp := make([]byte, 48)
	ntp[0] = 0x1c // version 3, mode 4
	for name, tc := range map[string]struct {
		check  func([]byte) (bool, *finding)
		reply  []byte
		ok     bool
		report bool
	}{
		"ntp server":     {ntpCheck, ntp, true, false},
		"ntp short":      {ntpCheck, ntp[:10], false, false},
		"ntp client":     {ntpCheck, ntpRequest(), false, false},
		"snmp response":  {snmpCheck, []byte{0x30, 0x10, 0x02, 0x01, 0x01, 0xa2, 0x00}, true, true},
		"snmp garbage":   {snmpCheck, []byte("hello"), false, false},
		"ssdp":           {ssdpCheck, []byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n"), true, true},
		"ssdp http":      {ssdpCheck, []byte("HTTP/1.1 400 Bad"), false, false},
		"tftp error":     {tftpCheck, []byte{0, 5, 0, 1, 'n', 'o', 0}, true, true},
		"tftp data":      {tftpCheck, []byte{0, 3, 0, 1, 'x'}, true, true},
		"tftp unrelated": {tftpCheck, []byte{1, 2, 3, 4}, false, false},
	} {
		ok, f := tc.check(tc.reply)
		if ok != tc.ok || (f != nil) != tc.report {
			t.Errorf("%s: ok=%v finding=%+v", name, ok, f)
		}
	}
}

// TestSendFromOtherPort checks that a reply from another source port (as
// TFTP servers do) is accepted, and that a silent port times out.
func TestSendFromOtherPort(t *testing.T) {
	var lc net.ListenConfig
	srv, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()
	other, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	go func() {
		buf := make([]byte, 512)
		_, from, err := srv.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = other.WriteTo([]byte{0, 5, 0, 1, 'n', 'o', 0}, from)
	}()

	u := &UDP{TimeoutMS: 500, Retries: 1}
	port := srv.LocalAddr().(*net.UDPAddr).Port
	if ok, f := u.send(t.Context(), "127.0.0.1", port, probes[69]); !ok || f == nil {
		t.Fatalf("ok=%v f=%+v", ok, f)
	}
	silent := other.LocalAddr().(*net.UDPAddr).Port
	if ok, _ := u.send(t.Context(), "127.0.0.1", silent, probes[123]); ok {
		t.Fatal("silent port reported open")
	}
}
