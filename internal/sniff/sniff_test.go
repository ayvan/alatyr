package sniff

import (
	"crypto/tls"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// clientHello captures the first flight of a real crypto/tls client.
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Handshake()
	}()
	buf := make([]byte, 16<<10)
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestTLS(t *testing.T) {
	ch := clientHello(t, "www.Example.com")
	r, err := Stream(ch)
	if err != nil || r.Host != "www.example.com" || r.Protocol != "tls" || r.ECH {
		t.Fatalf("got %+v, %v", r, err)
	}
	// Every strict prefix asks for more data.
	for _, n := range []int{0, 1, 4, 5, 40, len(ch) / 2, len(ch) - 1} {
		if _, err := Stream(ch[:n]); err != ErrNeedMore {
			t.Fatalf("prefix %d: %v", n, err)
		}
	}
	// ClientHello split over two TLS records.
	body := ch[5:]
	split := append([]byte{0x16, 3, 1, 0, 50}, body[:50]...)
	rest := body[50:]
	split = append(split, 0x16, 3, 1, byte(len(rest)>>8), byte(len(rest)))
	split = append(split, rest...)
	if r, err := TLS(split); err != nil || r.Host != "www.example.com" {
		t.Fatalf("split: %+v, %v", r, err)
	}
}

func TestTLSNoSNI(t *testing.T) {
	ch := clientHello(t, "")
	if _, err := Stream(ch); err != ErrNoName {
		t.Fatalf("got %v", err)
	}
}

func TestHTTP(t *testing.T) {
	r, err := Stream([]byte("GET /x HTTP/1.1\r\nUser-Agent: a\r\nHost: Example.org:8080\r\n\r\n"))
	if err != nil || r.Host != "example.org" || r.Protocol != "http" {
		t.Fatalf("got %+v, %v", r, err)
	}
	if _, err := Stream([]byte("GET /x HTTP/1.1\r\nUser-")); err != ErrNeedMore {
		t.Fatalf("partial: %v", err)
	}
	if _, err := Stream([]byte("PO")); err != ErrNeedMore {
		t.Fatalf("method prefix: %v", err)
	}
	if _, err := Stream([]byte("SSH-2.0-OpenSSH\r\n")); err != ErrUnknown {
		t.Fatalf("ssh: %v", err)
	}
}

func TestQUICRFC9001(t *testing.T) {
	raw, err := os.ReadFile("testdata/rfc9001-client-initial.hex")
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var q QUIC
	r, err := q.Add(pkt)
	if err != nil || r.Host != "example.com" || r.Protocol != "quic" {
		t.Fatalf("got %+v, %v", r, err)
	}
	pkt[100] ^= 1 // corrupted: AEAD fails
	var q2 QUIC
	if _, err := q2.Add(pkt); err != ErrUnknown {
		t.Fatalf("corrupted: %v", err)
	}
}

func TestQUICReassembly(t *testing.T) {
	ch := clientHello(t, "chrome.example")[5:] // handshake message
	half := len(ch) / 2
	var q QUIC
	q.chunks = map[uint64][]byte{}
	// Second half arrives first: nothing contiguous yet.
	q.chunks[uint64(half)] = ch[half:]
	if _, err := ClientHello(nil); err != ErrNeedMore {
		t.Fatal(err)
	}
	q.chunks[0] = ch[:half]
	var stream []byte
	for _, o := range []uint64{0, uint64(half)} {
		stream = append(stream, q.chunks[o]...)
	}
	if r, err := ClientHello(stream); err != nil || r.Host != "chrome.example" {
		t.Fatalf("got %+v, %v", r, err)
	}
	if IsQUICInitial([]byte("GET / HTTP/1.1")) {
		t.Fatal("http is not quic")
	}
}
