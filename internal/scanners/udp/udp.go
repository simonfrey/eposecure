// Package udp finds a few well-known UDP services (DNS, NTP, SNMP, SSDP,
// TFTP) by sending each a protocol request. Only a reply counts as open: a
// silent port is indistinguishable from a filtered one. Services that should
// never answer the internet (open resolver, SNMP "public", SSDP, TFTP) are
// also reported as findings.
package udp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	miekgdns "github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/simonfrey/exposure-scanner/internal/config"
	"github.com/simonfrey/exposure-scanner/internal/model"
)

type UDP struct {
	Ports       []int `yaml:"ports"`      // empty = scanner does nothing
	TimeoutMS   int   `yaml:"timeout_ms"` // wait for a reply, per attempt
	Retries     int   `yaml:"retries"`
	Concurrency int   `yaml:"concurrency"`
}

func New(o config.Options) (*UDP, error) {
	u := &UDP{TimeoutMS: 2000, Retries: 2, Concurrency: 50}
	if err := o.Decode(u); err != nil {
		return nil, err
	}
	for _, p := range u.Ports {
		if _, ok := probes[p]; !ok {
			return nil, fmt.Errorf("udp: no probe for port %d (supported: 53, 69, 123, 161, 1900)", p)
		}
	}
	return u, nil
}

func (u *UDP) Name() string { return "udp" }

// probe is a request for one service and a check of its reply. The check
// returns whether the reply is from that service, and an optional finding
// (template id, name, severity) when the reply itself shows an exposure.
type probe struct {
	service string
	request func() []byte
	check   func(reply []byte) (ok bool, f *finding)
}

type finding struct{ id, name, severity string }

var probes = map[int]probe{
	53:   {"dns", dnsRequest, dnsCheck},
	69:   {"tftp", tftpRequest, tftpCheck},
	123:  {"ntp", ntpRequest, ntpCheck},
	161:  {"snmp", snmpRequest, snmpCheck},
	1900: {"ssdp", ssdpRequest, ssdpCheck},
}

func (u *UDP) Scan(ctx context.Context, sc *model.ScanContext) error {
	if len(u.Ports) == 0 {
		return nil
	}
	prog := sc.Progress()
	var mu sync.Mutex
	var g errgroup.Group
	g.SetLimit(u.Concurrency)
	for _, ip := range sc.Targets {
		prog.Add(ip, len(u.Ports))
		for _, port := range u.Ports {
			g.Go(func() error {
				defer prog.Done(ip, 1)
				p := probes[port]
				ok, f := u.send(ctx, ip, port, p)
				if !ok {
					return nil
				}
				mu.Lock()
				defer mu.Unlock()
				for _, h := range sc.Names[ip] {
					sc.Endpoints = append(sc.Endpoints, model.Endpoint{Host: h, IP: ip, Port: port,
						Protocol: "udp", Service: p.service, Scanner: u.Name()})
					if f != nil {
						sc.Findings = append(sc.Findings, model.Finding{TemplateID: f.id, Name: f.name,
							Severity: f.severity, MatchedAt: "udp://" + net.JoinHostPort(h, strconv.Itoa(port)),
							Target: h, Scanner: u.Name(), Tags: []string{"exposure", "misconfig", "udp"}})
					}
				}
				return nil
			})
		}
	}
	return g.Wait()
}

// send probes ip:port and waits for a reply from that IP. The socket is not
// connected, because TFTP servers answer from a different port.
func (u *UDP) send(ctx context.Context, ip string, port int, p probe) (bool, *finding) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, nil
	}
	var lc net.ListenConfig
	network := "udp4"
	if addr.Is6() && !addr.Is4In6() {
		network = "udp6"
	}
	conn, err := lc.ListenPacket(ctx, network, ":0")
	if err != nil {
		return false, nil
	}
	defer func() { _ = conn.Close() }()
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr.Unmap(), uint16(port))) // #nosec G115 -- ports come from the probes table
	buf := make([]byte, 4096)
	for range u.Retries + 1 {
		if ctx.Err() != nil {
			return false, nil
		}
		if _, err := conn.WriteTo(p.request(), dst); err != nil {
			return false, nil
		}
		deadline := time.Now().Add(time.Duration(u.TimeoutMS) * time.Millisecond)
		_ = conn.SetReadDeadline(deadline)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				break // timeout: retry
			}
			src, ok := from.(*net.UDPAddr)
			if !ok || src.AddrPort().Addr().Unmap() != addr.Unmap() {
				continue // stray packet from someone else
			}
			if ok, f := p.check(buf[:n]); ok {
				return true, f
			}
		}
	}
	return false, nil
}

// dnsRequest asks for example.com with recursion desired: an authoritative
// server for other zones refuses, an open resolver answers.
func dnsRequest() []byte {
	m := new(miekgdns.Msg)
	m.SetQuestion("example.com.", miekgdns.TypeA)
	b, _ := m.Pack()
	return b
}

func dnsCheck(reply []byte) (bool, *finding) {
	m := new(miekgdns.Msg)
	if err := m.Unpack(reply); err != nil || !m.Response {
		return false, nil
	}
	if m.RecursionAvailable && m.Rcode == miekgdns.RcodeSuccess && len(m.Answer) > 0 {
		return true, &finding{"udp-dns-open-resolver", "Open DNS resolver (amplification, cache snooping)", "medium"}
	}
	return true, nil
}

func ntpRequest() []byte {
	b := make([]byte, 48)
	b[0] = 0x1b // leap 0, version 3, mode 3 (client)
	return b
}

func ntpCheck(reply []byte) (bool, *finding) {
	return len(reply) >= 48 && reply[0]&0x07 == 4, nil // mode 4: server
}

// snmpRequest is an SNMPv2c GetRequest for sysDescr.0 with community "public".
func snmpRequest() []byte {
	return []byte{
		0x30, 0x29, // sequence, 41 bytes
		0x02, 0x01, 0x01, // version: v2c
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community
		0xa0, 0x1c, // GetRequest PDU, 28 bytes
		0x02, 0x04, 0x45, 0x58, 0x50, 0x4f, // request id
		0x02, 0x01, 0x00, // error status
		0x02, 0x01, 0x00, // error index
		0x30, 0x0e, 0x30, 0x0c, // varbind list, varbind
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // 1.3.6.1.2.1.1.1.0
		0x05, 0x00, // null
	}
}

func snmpCheck(reply []byte) (bool, *finding) {
	// Agents drop requests with a wrong community, so any GetResponse PDU
	// (0xa2) means "public" is readable.
	if len(reply) < 2 || reply[0] != 0x30 || !slices.Contains(reply, 0xa2) {
		return false, nil
	}
	return true, &finding{"udp-snmp-public-community", "SNMP readable with community \"public\"", "medium"}
}

func ssdpRequest() []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
}

func ssdpCheck(reply []byte) (bool, *finding) {
	if len(reply) < 12 || string(reply[:12]) != "HTTP/1.1 200" {
		return false, nil
	}
	return true, &finding{"udp-ssdp-exposed", "SSDP answers the internet (amplification)", "medium"}
}

// tftpRequest asks to read a file that does not exist.
func tftpRequest() []byte {
	return append([]byte{0x00, 0x01}, "exposure-scanner-probe\x00octet\x00"...)
}

func tftpCheck(reply []byte) (bool, *finding) {
	// DATA (3) or ERROR (5): either way a TFTP server answered.
	if len(reply) < 4 || reply[0] != 0 || (reply[1] != 3 && reply[1] != 5) {
		return false, nil
	}
	return true, &finding{"udp-tftp-exposed", "TFTP server reachable from the internet", "medium"}
}
