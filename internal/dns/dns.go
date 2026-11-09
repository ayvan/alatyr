// Package dns is the resolver users talk to (the gateway address plus every
// intercepted port-53 query). Each name is resolved through the tunnel or
// directly, according to the routing rules, and the answers are remembered
// as "IP -> names" so that later connections to those IPs can be routed by
// name.
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"alatyr/internal/rules"
)

// Exchanger sends a raw DNS query to a server and returns the raw answer.
type Exchanger interface {
	Exchange(ctx context.Context, server netip.AddrPort, q []byte) ([]byte, error)
}

// Config is the resolver behaviour; it can be swapped at runtime.
type Config struct {
	// Route decides where a name goes.
	Route func(name string) rules.Action
	// TunnelServers resolve tunnel names through Tunnel.
	TunnelServers []netip.AddrPort
	// DirectServers resolve other names via Direct; empty means the
	// system resolver.
	DirectServers []netip.AddrPort
	// Blocked names get NXDOMAIN (DoH servers, Firefox canary).
	Blocked func(name string) bool
}

// Server answers DNS queries.
type Server struct {
	tunnel, direct Exchanger
	cfg            atomicConfig
	Cache          *Cache
}

type atomicConfig struct {
	mu sync.RWMutex
	c  Config
}

// New creates a server.
func New(tunnel, direct Exchanger, cfg Config) *Server {
	s := &Server{tunnel: tunnel, direct: direct, Cache: NewCache()}
	s.SetConfig(cfg)
	return s
}

// SetConfig replaces the behaviour.
func (s *Server) SetConfig(c Config) {
	s.cfg.mu.Lock()
	s.cfg.c = c
	s.cfg.mu.Unlock()
}

func (s *Server) config() Config {
	s.cfg.mu.RLock()
	defer s.cfg.mu.RUnlock()
	return s.cfg.c
}

const (
	typeHTTPS = dnsmessage.Type(65)
	typeSVCB  = dnsmessage.Type(64)
)

// Handle answers one query. It returns nil when the query is malformed.
func (s *Server) Handle(ctx context.Context, q []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return reply(h, qs, dnsmessage.RCodeFormatError, nil)
	}
	question := qs[0]
	name := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	cfg := s.config()

	if cfg.Blocked != nil && cfg.Blocked(name) {
		return reply(h, qs, dnsmessage.RCodeNameError, nil)
	}
	switch question.Type {
	case dnsmessage.TypeAAAA:
		// The tunnel and the users' network are IPv4 only: an empty
		// answer makes clients use A records at once.
		return reply(h, qs, dnsmessage.RCodeSuccess, nil)
	case typeHTTPS, typeSVCB:
		// No HTTPS records: they carry ECH keys (which hide the site name
		// from SNI) and IPv6 hints.
		return reply(h, qs, dnsmessage.RCodeSuccess, nil)
	}

	action := rules.Direct
	if isLocal(name, question.Type) {
		action = rules.Direct
	} else if cfg.Route != nil {
		action = cfg.Route(name)
	}
	var ans []byte
	if action == rules.Tunnel {
		ans, err = exchangeAny(ctx, s.tunnel, cfg.TunnelServers, q)
	} else if len(cfg.DirectServers) > 0 {
		ans, err = exchangeAny(ctx, s.direct, cfg.DirectServers, q)
	} else {
		ans, err = systemResolve(ctx, h, question)
	}
	if err != nil {
		return reply(h, qs, dnsmessage.RCodeServerFailure, nil)
	}
	s.learn(name, ans)
	return ans
}

// isLocal names never leave this machine's network.
func isLocal(name string, t dnsmessage.Type) bool {
	if !strings.Contains(name, ".") {
		return true
	}
	for _, sfx := range []string{".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain"} {
		if strings.HasSuffix(name, sfx) {
			return true
		}
	}
	if t == dnsmessage.TypePTR && strings.HasSuffix(name, ".in-addr.arpa") {
		parts := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(parts) == 4 {
			ip, err := netip.ParseAddr(parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0])
			return err == nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
		}
	}
	return false
}

// learn records the A answers of a name in the cache.
func (s *Server) learn(name string, ans []byte) {
	var p dnsmessage.Parser
	if _, err := p.Start(ans); err != nil {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return
		}
		if h.Type != dnsmessage.TypeA {
			p.SkipAnswer()
			continue
		}
		r, err := p.AResource()
		if err != nil {
			return
		}
		s.Cache.Add(netip.AddrFrom4(r.A), name, time.Duration(h.TTL)*time.Second)
	}
}

func exchangeAny(ctx context.Context, ex Exchanger, servers []netip.AddrPort, q []byte) ([]byte, error) {
	if len(servers) == 0 {
		return nil, errors.New("no DNS servers")
	}
	var last error
	for _, srv := range servers {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		ans, err := ex.Exchange(c, srv, q)
		cancel()
		if err == nil && len(ans) >= 12 && binary.BigEndian.Uint16(ans) == binary.BigEndian.Uint16(q) {
			return ans, nil
		}
		if err == nil {
			err = errors.New("bad answer")
		}
		last = err
	}
	return nil, last
}

// reply builds an answer with the given code and A records.
func reply(h dnsmessage.Header, qs []dnsmessage.Question, rcode dnsmessage.RCode, as []dnsmessage.Resource) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: h.ID, Response: true, OpCode: h.OpCode, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true, RCode: rcode,
	})
	b.EnableCompression()
	b.StartQuestions()
	for _, q := range qs {
		b.Question(q)
	}
	b.StartAnswers()
	for _, r := range as {
		switch body := r.Body.(type) {
		case *dnsmessage.AResource:
			b.AResource(r.Header, *body)
		case *dnsmessage.PTRResource:
			b.PTRResource(r.Header, *body)
		case *dnsmessage.TXTResource:
			b.TXTResource(r.Header, *body)
		case *dnsmessage.MXResource:
			b.MXResource(r.Header, *body)
		case *dnsmessage.SRVResource:
			b.SRVResource(r.Header, *body)
		case *dnsmessage.CNAMEResource:
			b.CNAMEResource(r.Header, *body)
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

const systemTTL = 60

// systemResolve answers with the OS resolver (it has no raw query API, so
// the answer is synthesised for the common record types).
func systemResolve(ctx context.Context, h dnsmessage.Header, q dnsmessage.Question) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	name := strings.TrimSuffix(q.Name.String(), ".")
	hdr := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: systemTTL}
	var as []dnsmessage.Resource
	var err error
	r := net.DefaultResolver
	switch q.Type {
	case dnsmessage.TypeA:
		var ips []netip.Addr
		ips, err = r.LookupNetIP(ctx, "ip4", name)
		for _, ip := range ips {
			if ip = ip.Unmap(); ip.Is4() {
				as = append(as, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: ip.As4()}})
			}
		}
	case dnsmessage.TypeCNAME:
		var c string
		c, err = r.LookupCNAME(ctx, name)
		if n, e := dnsmessage.NewName(dotted(c)); e == nil && err == nil && dotted(c) != dotted(name) {
			as = append(as, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.CNAMEResource{CNAME: n}})
		}
	case dnsmessage.TypePTR:
		var names []string
		if ip, ok := ptrAddr(name); ok {
			names, err = r.LookupAddr(ctx, ip)
		}
		for _, n := range names {
			if nn, e := dnsmessage.NewName(dotted(n)); e == nil {
				as = append(as, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.PTRResource{PTR: nn}})
			}
		}
	case dnsmessage.TypeTXT:
		var txts []string
		txts, err = r.LookupTXT(ctx, name)
		for _, t := range txts {
			as = append(as, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.TXTResource{TXT: chunk(t)}})
		}
	case dnsmessage.TypeMX:
		var mxs []*net.MX
		mxs, err = r.LookupMX(ctx, name)
		for _, mx := range mxs {
			if n, e := dnsmessage.NewName(dotted(mx.Host)); e == nil {
				as = append(as, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.MXResource{Pref: mx.Pref, MX: n}})
			}
		}
	case dnsmessage.TypeSRV:
		var srvs []*net.SRV
		_, srvs, err = r.LookupSRV(ctx, "", "", name)
		for _, sv := range srvs {
			if n, e := dnsmessage.NewName(dotted(sv.Target)); e == nil {
				as = append(as, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.SRVResource{
					Priority: sv.Priority, Weight: sv.Weight, Port: sv.Port, Target: n}})
			}
		}
	default:
		return reply(h, []dnsmessage.Question{q}, dnsmessage.RCodeSuccess, nil), nil
	}
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return reply(h, []dnsmessage.Question{q}, dnsmessage.RCodeNameError, nil), nil
		}
		return nil, err
	}
	return reply(h, []dnsmessage.Question{q}, dnsmessage.RCodeSuccess, as), nil
}

func dotted(n string) string {
	if strings.HasSuffix(n, ".") {
		return n
	}
	return n + "."
}

func ptrAddr(name string) (string, bool) {
	parts := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
	if len(parts) != 4 {
		return "", false
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0], true
}

func chunk(s string) []string {
	var out []string
	for len(s) > 255 {
		out = append(out, s[:255])
		s = s[255:]
	}
	return append(out, s)
}

// --- transport helpers ---

// DialFunc opens a connection ("udp" or "tcp") to a DNS server.
type DialFunc func(ctx context.Context, network string, addr netip.AddrPort) (net.Conn, error)

// NetExchanger exchanges queries over UDP with a TCP retry on truncation.
type NetExchanger struct{ Dial DialFunc }

// Exchange implements Exchanger.
func (e NetExchanger) Exchange(ctx context.Context, srv netip.AddrPort, q []byte) ([]byte, error) {
	c, err := e.Dial(ctx, "udp", srv)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 || binary.BigEndian.Uint16(buf) != binary.BigEndian.Uint16(q) {
			continue // stray or spoofed answer
		}
		if buf[2]&0x02 == 0 { // not truncated
			return append([]byte(nil), buf[:n]...), nil
		}
		break
	}
	tc, err := e.Dial(ctx, "tcp", srv)
	if err != nil {
		return nil, err
	}
	defer tc.Close()
	if dl, ok := ctx.Deadline(); ok {
		tc.SetDeadline(dl)
	}
	return ExchangeStream(tc, q)
}

// ExchangeStream sends a length-prefixed query over a stream connection.
func ExchangeStream(c io.ReadWriter, q []byte) ([]byte, error) {
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := c.Write(append(msg, q...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	ans := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(c, ans)
	return ans, err
}

// ServeStream answers length-prefixed queries on a TCP connection until it
// is closed or idle.
func (s *Server) ServeStream(c net.Conn) {
	defer c.Close()
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		ans := s.Handle(context.Background(), q)
		if ans == nil {
			return
		}
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(ans))), ans...)); err != nil {
			return
		}
	}
}

// ServePacket answers queries on a UDP flow until it is idle.
func (s *Server) ServePacket(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if ans := s.Handle(context.Background(), q); ans != nil {
				c.Write(ans)
			}
		}()
	}
}
