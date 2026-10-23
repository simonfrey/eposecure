package banner

import (
	"bufio"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestSSH(t *testing.T) {
	for line, want := range map[string]result{
		"SSH-2.0-OpenSSH_9.6p1":                   {"ssh", "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"},
		"SSH-2.0-OpenSSH_8.0":                     {"ssh", "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*"},
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3":  {"ssh", ""}, // backported fixes
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6": {"ssh", ""},
		"SSH-2.0-dropbear_2022.83":                {"ssh", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2022.83:*:*:*:*:*:*:*"},
		"SSH-1.99-Cisco-1.25":                     {"ssh", ""},
		"220 mail ESMTP":                          {},
	} {
		if got := ssh(line); got != want {
			t.Errorf("ssh(%q) = %+v, want %+v", line, got, want)
		}
	}
}

func TestSniff(t *testing.T) {
	for line, want := range map[string]result{
		"SSH-2.0-OpenSSH_9.6p1":             {"ssh", "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"},
		"220 (vsFTPd 3.0.3)":                {"ftp", "cpe:2.3:a:vsftpd_project:vsftpd:3.0.3:*:*:*:*:*:*:*"},
		"220 ProFTPD Server ready.":         {"ftp", ""},
		"220 mx ESMTP Exim 4.96 Mon, 1 Jan": {"smtp", "cpe:2.3:a:exim:exim:4.96:*:*:*:*:*:*:*"},
		"220 mx ESMTP Postfix":              {"smtp", ""},
		"+OK Dovecot ready.":                {"pop3", ""},
		"* OK IMAP ready":                   {"imap", ""},
		"HTTP/1.1 400 Bad Request":          {},
	} {
		if got := sniff(line); got != want {
			t.Errorf("sniff(%q) = %+v, want %+v", line, got, want)
		}
	}
}

func TestMySQLVersion(t *testing.T) {
	for v, want := range map[string]result{
		"8.0.36":                            {"mysql", "cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*"},
		"8.0.32-0ubuntu0.22.04.2":           {"mysql", "cpe:2.3:a:oracle:mysql:8.0.32:*:*:*:*:*:*:*"},
		"5.5.5-10.6.12-MariaDB-0ubuntu0.22": {"mariadb", "cpe:2.3:a:mariadb:mariadb:10.6.12:*:*:*:*:*:*:*"},
		"11.4.2-MariaDB":                    {"mariadb", "cpe:2.3:a:mariadb:mariadb:11.4.2:*:*:*:*:*:*:*"},
		"weird":                             {"mysql", ""},
	} {
		if got := mysqlVersion(v); got != want {
			t.Errorf("mysqlVersion(%q) = %+v, want %+v", v, got, want)
		}
	}
}

// serve runs handler for one connection on a loopback listener and returns its address.
func serve(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		handler(c)
	}()
	return l.Addr().String()
}

func TestRedisProbe(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		rd := bufio.NewReader(c)
		_, _ = rd.ReadString('\n')
		_, _ = c.Write([]byte("+PONG\r\n"))
		_, _ = rd.ReadString('\n')
		body := "# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n"
		_, _ = c.Write([]byte("$" + strconv.Itoa(len(body)) + "\r\n" + body + "\r\n"))
	})
	b := &Banner{Timeout: 2}
	if got := b.probe(t.Context(), addr, 6379); got != (result{"redis", "cpe:2.3:a:redis:redis:7.2.4:*:*:*:*:*:*:*"}) {
		t.Fatalf("got %+v", got)
	}
}

func TestRedisProbeAuth(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		_, _ = bufio.NewReader(c).ReadString('\n')
		_, _ = c.Write([]byte("-NOAUTH Authentication required.\r\n"))
	})
	b := &Banner{Timeout: 2}
	if got := b.probe(t.Context(), addr, 6379); got != (result{service: "redis"}) {
		t.Fatalf("got %+v", got)
	}
}

func TestPostgresProbe(t *testing.T) {
	addr := serve(t, func(c net.Conn) {
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("S"))
	})
	b := &Banner{Timeout: 2}
	if got := b.probe(t.Context(), addr, 5432); got.service != "postgresql" {
		t.Fatalf("got %+v", got)
	}
}

func TestSilentPort(t *testing.T) {
	addr := serve(t, func(c net.Conn) { time.Sleep(1500 * time.Millisecond) })
	b := &Banner{Timeout: 1}
	if got := b.probe(t.Context(), addr, 4444); got != (result{}) {
		t.Fatalf("got %+v", got)
	}
}
