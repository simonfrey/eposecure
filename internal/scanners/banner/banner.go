// Package banner identifies services on non-HTTP ports (SSH, Redis, MySQL,
// ...) from their protocol banners, stores the service on the endpoint and,
// where the banner carries a precise upstream version, a versioned CPE for
// cve_lookup. Only connects to ports an earlier scanner reported open.
package banner

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/simonfrey/eposecure/internal/config"
	"github.com/simonfrey/eposecure/internal/model"
)

type Banner struct {
	Timeout     int `yaml:"timeout"` // seconds per probe
	Concurrency int `yaml:"concurrency"`
}

func New(o config.Options) (*Banner, error) {
	b := &Banner{Timeout: 3, Concurrency: 20}
	return b, o.Decode(b)
}

func (b *Banner) Name() string { return "banner" }

// result is what a probe learned. An empty service means unknown.
type result struct {
	service string
	cpe     string // versioned CPE 2.3, or "" if the version is not precise
}

// probe identifies the service on an open connection. The connection has a
// deadline set, so probes may block on reads.
type probe func(conn net.Conn) result

// probeFor maps well-known ports to a probe. Other ports are read for a
// plain-text banner, so e.g. SSH on port 2222 is still recognized.
func probeFor(port int) probe {
	switch port {
	case 21:
		return greeting(ftp)
	case 22:
		return greeting(ssh)
	case 25, 465, 587:
		return greeting(smtp)
	case 110:
		return greeting(prefix("+OK", "pop3"))
	case 143, 993:
		return greeting(prefix("* OK", "imap"))
	case 3306:
		return mysqlProbe
	case 5432:
		return postgresProbe
	case 5672:
		return amqpProbe
	case 6379:
		return redisProbe
	case 11211:
		return memcachedProbe
	case 9092:
		return kafkaProbe
	case 27017, 27018, 27019:
		return mongoProbe
	}
	return greeting(sniff)
}

func (b *Banner) Scan(ctx context.Context, sc *model.ScanContext) error {
	prog := sc.Progress()
	var g errgroup.Group
	g.SetLimit(b.Concurrency)
	for i := range sc.Endpoints {
		e := &sc.Endpoints[i]
		if e.URL != "" || e.Protocol == "udp" {
			continue // HTTP endpoints are httpx's job, UDP the udp scanner's
		}
		prog.Add(e.Addr(), 1)
		// Each goroutine writes only its own endpoint, so no lock is needed.
		g.Go(func() error {
			defer prog.Done(e.Addr(), 1)
			r := b.probe(ctx, e.Addr(), e.Port)
			if r.service == "" {
				return nil
			}
			e.Service = r.service
			if r.cpe != "" {
				e.CPE = append(e.CPE, r.cpe)
			}
			return nil
		})
	}
	return g.Wait()
}

func (b *Banner) probe(ctx context.Context, addr string, port int) result {
	timeout := time.Duration(b.Timeout) * time.Second
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return result{}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return probeFor(port)(conn)
}

// greeting reads the first line the server sends and passes it to parse.
func greeting(parse func(line string) result) probe {
	return func(conn net.Conn) result {
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil && line == "" {
			return result{}
		}
		return parse(strings.TrimSpace(line))
	}
}

func prefix(p, service string) func(string) result {
	return func(line string) result {
		if strings.HasPrefix(line, p) {
			return result{service: service}
		}
		return result{}
	}
}

// sniff recognizes plain-text protocols on non-standard ports.
func sniff(line string) result {
	switch {
	case strings.HasPrefix(line, "SSH-"):
		return ssh(line)
	case strings.HasPrefix(line, "220"):
		if strings.Contains(strings.ToLower(line), "ftp") {
			return ftp(line)
		}
		return smtp(line)
	case strings.HasPrefix(line, "+OK"):
		return result{service: "pop3"}
	case strings.HasPrefix(line, "* OK"):
		return result{service: "imap"}
	}
	return result{}
}

var opensshVersion = regexp.MustCompile(`^(\d+\.\d+)(p\d+)?$`)

// ssh parses "SSH-2.0-OpenSSH_9.6p1" or "SSH-2.0-dropbear_2022.83". A
// comment after the version ("OpenSSH_9.2p1 Debian-2+deb12u3") means a
// distribution build with backported fixes: its upstream version would
// match CVEs that are already patched, so no CPE is emitted.
func ssh(line string) result {
	if !strings.HasPrefix(line, "SSH-") {
		return result{}
	}
	_, software, _ := strings.Cut(strings.TrimPrefix(line, "SSH-"), "-")
	software, comment, _ := strings.Cut(software, " ")
	r := result{service: "ssh"}
	if comment != "" {
		return r
	}
	if v, ok := strings.CutPrefix(software, "OpenSSH_"); ok {
		// NVD splits "9.6p1" into version 9.6 and update p1.
		if m := opensshVersion.FindStringSubmatch(v); m != nil {
			r.cpe = cpe("openbsd:openssh", m[1], cmp.Or(m[2], "*"))
		}
	} else if v, ok := strings.CutPrefix(software, "dropbear_"); ok && isVersion(v) {
		r.cpe = cpe("dropbear_ssh_project:dropbear_ssh", v, "*")
	}
	return r
}

// smtp parses "220 host ESMTP Exim 4.96 ..." (other MTAs hide their version).
func smtp(line string) result {
	if !strings.HasPrefix(line, "220") {
		return result{}
	}
	r := result{service: "smtp"}
	fields := strings.Fields(line)
	for i, f := range fields {
		if strings.EqualFold(f, "exim") && i+1 < len(fields) && isVersion(fields[i+1]) {
			r.cpe = cpe("exim:exim", fields[i+1], "*")
		}
	}
	return r
}

// ftp parses "220 (vsFTPd 3.0.3)". Other servers are reported without CPE.
func ftp(line string) result {
	if !strings.HasPrefix(line, "220") {
		return result{}
	}
	r := result{service: "ftp"}
	if i := strings.Index(strings.ToLower(line), "vsftpd "); i >= 0 {
		v := strings.TrimRight(strings.Fields(line[i+len("vsftpd "):] + " ")[0], ")")
		if isVersion(v) {
			r.cpe = cpe("vsftpd_project:vsftpd", v, "*")
		}
	}
	return r
}

func mysqlProbe(conn net.Conn) result {
	// Greeting: 3-byte payload length, 1-byte sequence, then protocol 10 and
	// the version string up to a NUL.
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return result{}
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n < 2 || n > 1<<16 {
		return result{}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil || payload[0] != 10 {
		return result{}
	}
	version, _, _ := strings.Cut(string(payload[1:]), "\x00")
	return mysqlVersion(version)
}

// mysqlVersion maps a greeting version to a CPE. MariaDB announces itself
// as "5.5.5-10.6.12-MariaDB-..." for client compatibility.
func mysqlVersion(version string) result {
	if rest, ok := strings.CutPrefix(version, "5.5.5-"); ok && strings.Contains(rest, "MariaDB") {
		r := result{service: "mariadb"}
		if v, _, _ := strings.Cut(rest, "-"); isVersion(v) {
			r.cpe = cpe("mariadb:mariadb", v, "*")
		}
		return r
	}
	r := result{service: "mysql"}
	v, suffix, _ := strings.Cut(version, "-")
	if strings.Contains(suffix, "MariaDB") {
		r.service = "mariadb"
		if isVersion(v) {
			r.cpe = cpe("mariadb:mariadb", v, "*")
		}
		return r
	}
	if isVersion(v) {
		r.cpe = cpe("oracle:mysql", v, "*")
	}
	return r
}

func postgresProbe(conn net.Conn) result {
	// SSLRequest: a PostgreSQL server answers a single 'S' or 'N'.
	if _, err := conn.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		return result{}
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return result{}
	}
	switch resp[0] {
	case 'S', 'N':
		return result{service: "postgresql"}
	}
	return result{}
}

func amqpProbe(conn net.Conn) result {
	// After the AMQP 0-9-1 protocol header a broker answers with a
	// Connection.Start method frame (type 1, channel 0), or with its own
	// protocol header if it speaks another version.
	if _, err := conn.Write([]byte("AMQP\x00\x00\x09\x01")); err != nil {
		return result{}
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return result{}
	}
	if string(hdr[:]) == "AMQP" || hdr[0] == 1 && hdr[1] == 0 && hdr[2] == 0 {
		return result{service: "amqp"}
	}
	return result{}
}

func redisProbe(conn net.Conn) result {
	rd := bufio.NewReader(conn)
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return result{}
	}
	line, err := rd.ReadString('\n')
	if err != nil {
		return result{}
	}
	switch {
	case strings.HasPrefix(line, "+PONG"):
	case strings.HasPrefix(line, "-NOAUTH"), strings.HasPrefix(line, "-DENIED"):
		return result{service: "redis"} // password or protected mode
	default:
		return result{}
	}
	r := result{service: "redis"}
	if _, err := conn.Write([]byte("INFO server\r\n")); err != nil {
		return r
	}
	// Bulk string reply: "$<length>\r\n<body>\r\n".
	head, err := rd.ReadString('\n')
	if err != nil || !strings.HasPrefix(head, "$") {
		return r
	}
	n, err := strconv.Atoi(strings.TrimSpace(head[1:]))
	if err != nil || n <= 0 || n > 64<<10 {
		return r
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(rd, body); err != nil {
		return r
	}
	for ln := range strings.SplitSeq(string(body), "\r\n") {
		if v, ok := strings.CutPrefix(ln, "redis_version:"); ok && isVersion(v) {
			r.cpe = cpe("redis:redis", v, "*")
		}
	}
	return r
}

func memcachedProbe(conn net.Conn) result {
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return result{}
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return result{}
	}
	v, ok := strings.CutPrefix(strings.TrimSpace(line), "VERSION ")
	if !ok {
		return result{}
	}
	r := result{service: "memcached"}
	if isVersion(v) {
		r.cpe = cpe("memcached:memcached", v, "*")
	}
	return r
}

func kafkaProbe(conn net.Conn) result {
	// Kafka sends no banner but answers an ApiVersions request (key 18)
	// with a response carrying the same correlation id.
	req := make([]byte, 14)
	binary.BigEndian.PutUint32(req[0:4], 10)          // length of what follows
	binary.BigEndian.PutUint16(req[4:6], 18)          // api key: ApiVersions
	binary.BigEndian.PutUint16(req[6:8], 0)           // api version
	binary.BigEndian.PutUint32(req[8:12], 0x4b61666b) // correlation id
	binary.BigEndian.PutUint16(req[12:14], 0xffff)    // client id: null
	if _, err := conn.Write(req); err != nil {
		return result{}
	}
	var resp [8]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return result{}
	}
	if size := binary.BigEndian.Uint32(resp[0:4]); size < 4 || size > 1<<20 ||
		binary.BigEndian.Uint32(resp[4:8]) != 0x4b61666b {
		return result{}
	}
	return result{service: "kafka"}
}

func mongoProbe(conn net.Conn) result {
	// OP_QUERY {isMaster: 1} on admin.$cmd: answered by every MongoDB version
	// (OP_REPLY, opcode 1); servers dropping OP_QUERY answer with OP_MSG.
	doc := []byte{0x13, 0, 0, 0, 0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0, 1, 0, 0, 0, 0}
	coll := []byte("admin.$cmd\x00")
	body := binary.LittleEndian.AppendUint32(nil, 0) // flags
	body = append(body, coll...)
	body = binary.LittleEndian.AppendUint32(body, 0) // skip
	body = binary.LittleEndian.AppendUint32(body, 1) // return
	body = append(body, doc...)
	msg := binary.LittleEndian.AppendUint32(nil, uint32(16+len(body))) // #nosec G115 -- constant size
	msg = binary.LittleEndian.AppendUint32(msg, 1)                     // request id
	msg = binary.LittleEndian.AppendUint32(msg, 0)                     // response to
	msg = binary.LittleEndian.AppendUint32(msg, 2004)                  // OP_QUERY
	msg = append(msg, body...)
	if _, err := conn.Write(msg); err != nil {
		return result{}
	}
	var hdr [16]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return result{}
	}
	if op := binary.LittleEndian.Uint32(hdr[12:16]); op == 1 || op == 2013 {
		return result{service: "mongodb"}
	}
	return result{}
}

var versionRe = regexp.MustCompile(`^\d+(\.\d+)+$`)

// isVersion accepts plain dotted versions only. Anything else (distro
// suffixes, build tags) does not map to an NVD CPE version reliably.
func isVersion(v string) bool { return versionRe.MatchString(v) }

// cpe builds "cpe:2.3:a:<vendor:product>:<version>:<update>:*:*:*:*:*:*".
func cpe(vendorProduct, version, update string) string {
	return "cpe:2.3:a:" + vendorProduct + ":" + version + ":" + update + ":*:*:*:*:*:*"
}
