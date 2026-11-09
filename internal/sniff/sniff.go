// Package sniff extracts the target host name from the first bytes of a
// connection: SNI from a TLS ClientHello, Host from an HTTP/1 request and SNI
// from a QUIC Initial packet. Nothing is decrypted beyond what the protocols
// make public (QUIC Initial keys are derived from the connection ID).
package sniff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

var (
	// ErrNeedMore means the data is a prefix of a supported message.
	ErrNeedMore = errors.New("need more data")
	// ErrUnknown means the data is not a supported protocol.
	ErrUnknown = errors.New("unknown protocol")
	// ErrNoName means the message has no host name in it.
	ErrNoName = errors.New("no host name")
)

// Result of sniffing.
type Result struct {
	Host     string
	Protocol string // "tls", "http", "quic"
	// ECH is set when the ClientHello uses Encrypted Client Hello: Host is
	// then the public (outer) name, not the real site.
	ECH bool
}

// Stream sniffs a TCP stream prefix (TLS or HTTP).
func Stream(b []byte) (Result, error) {
	if len(b) == 0 {
		return Result{}, ErrNeedMore
	}
	if b[0] == 0x16 {
		return TLS(b)
	}
	return HTTP(b)
}

// TLS parses TLS records carrying a ClientHello.
func TLS(b []byte) (Result, error) {
	var hs []byte
	for len(b) > 0 {
		if b[0] != 0x16 {
			if hs == nil {
				return Result{}, ErrUnknown
			}
			break
		}
		if len(b) < 5 {
			break
		}
		if b[1] != 3 {
			return Result{}, ErrUnknown
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			hs = append(hs, b[5:]...)
			break
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
	}
	r, err := ClientHello(hs)
	r.Protocol = "tls"
	return r, err
}

// ClientHello parses a handshake message (4-byte header + body). A
// truncated message gives ErrNeedMore along with whatever was found so far.
func ClientHello(hs []byte) (Result, error) {
	if len(hs) < 4 {
		return Result{}, ErrNeedMore
	}
	if hs[0] != 1 {
		return Result{}, ErrUnknown
	}
	body := hs[4:]
	if n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]); len(body) > n {
		body = body[:n]
	}
	p := parser{b: body}
	p.skip(2 + 32)    // version, random
	p.skip(p.u8())    // session id
	p.skip(p.u16())   // cipher suites
	p.skip(p.u8())    // compression
	extLen := p.u16() // extensions
	if p.short {
		return Result{}, ErrNeedMore
	}
	if extLen == 0 {
		return Result{}, ErrNoName
	}
	var res Result
	for p.ok() {
		typ, n := p.u16(), p.u16()
		data := p.bytes(n)
		if p.short {
			break
		}
		switch typ {
		case 0: // server_name
			q := parser{b: data}
			q.skip(2)
			for q.ok() {
				kind, l := q.u8(), q.u16()
				name := q.bytes(l)
				if !q.short && kind == 0 {
					res.Host = strings.ToLower(string(name))
				}
			}
		case 0xfe0d: // encrypted_client_hello
			res.ECH = true
		}
	}
	switch {
	case p.short:
		// res.Host may already be set: callers use it on timeout.
		return res, ErrNeedMore
	case res.Host == "":
		return res, ErrNoName
	}
	return res, nil
}

var methods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

// HTTP parses an HTTP/1.x request head.
func HTTP(b []byte) (Result, error) {
	known := false
	for _, m := range methods {
		n := min(len(m), len(b))
		if string(b[:n]) == m[:n] {
			known = true
			break
		}
	}
	if !known {
		return Result{}, ErrUnknown
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	head := b
	if end >= 0 {
		head = b[:end]
	}
	for _, line := range bytes.Split(head, []byte("\r\n"))[1:] {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok || !strings.EqualFold(string(k), "host") {
			continue
		}
		h := strings.TrimSpace(string(v))
		if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.HasSuffix(h, "]") {
			h = h[:i]
		}
		return Result{Host: strings.ToLower(strings.Trim(h, "[]")), Protocol: "http"}, nil
	}
	if end < 0 {
		return Result{}, ErrNeedMore
	}
	return Result{}, ErrNoName
}

type parser struct {
	b     []byte
	short bool
}

func (p *parser) ok() bool { return !p.short && len(p.b) > 0 }

func (p *parser) bytes(n int) []byte {
	if p.short || len(p.b) < n {
		p.short = true
		p.b = nil
		return nil
	}
	v := p.b[:n]
	p.b = p.b[n:]
	return v
}

func (p *parser) skip(n int) { p.bytes(n) }

func (p *parser) u8() int {
	v := p.bytes(1)
	if v == nil {
		return 0
	}
	return int(v[0])
}

func (p *parser) u16() int {
	v := p.bytes(2)
	if v == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(v))
}
