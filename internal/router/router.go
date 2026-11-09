// Package router decides for every TCP/UDP flow of a user whether it goes
// through the VPN tunnel or directly from this machine, and moves the data.
//
// Decision order for a flow:
//  1. DoH/DoT blocking (if on), LAN protection;
//  2. subnet rules for the destination IP;
//  3. the site name: SNI / HTTP Host / QUIC SNI read from the first bytes
//     (ports 80, 443, 8080, 8443), else names from the DNS cache;
//  4. domain rules for that name;
//  5. the default action of the mode.
package router

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"alatyr/internal/dns"
	"alatyr/internal/rules"
	"alatyr/internal/sniff"
	"alatyr/internal/stack"
	"alatyr/internal/store"
)

const (
	dialTimeout = 10 * time.Second
	udpIdle     = 2 * time.Minute
	maxSniff    = 16 << 10
)

var sniffPorts = map[uint16]bool{80: true, 443: true, 8080: true, 8443: true}

// Tunnel dials through the VPN.
type Tunnel interface {
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	DialUDP(dst netip.AddrPort) (net.Conn, error)
}

// Options configure a Router.
type Options struct {
	Tunnel   Tunnel
	Gateway  netip.Addr
	DNS      *dns.Server
	UserName func(ip netip.Addr) string
}

type config struct {
	mode         string
	matcher      *rules.Matcher
	def          rules.Action
	blockQUIC    string
	blockDoH     bool
	allowLAN     bool
	sniffTimeout time.Duration
}

// Router handles user flows.
type Router struct {
	opts    Options
	cfg     atomic.Pointer[config]
	journal journal
	stats   counters
}

// New creates a router; call Configure before use.
func New(o Options) *Router {
	r := &Router{opts: o}
	r.cfg.Store(&config{mode: store.ModeFull, matcher: rules.NewMatcher(nil, nil, nil), def: rules.Tunnel})
	return r
}

// Configure applies routing settings and loaded subscriptions. Running
// flows keep their route; new flows use the new rules.
func (r *Router) Configure(rt store.Routing, subs []rules.Source) {
	c := &config{
		mode:         rt.Mode,
		matcher:      rules.NewMatcher(rules.Parse(rt.Direct), rules.Parse(rt.Tunnel), subs),
		def:          rules.Direct,
		blockQUIC:    rt.BlockQUIC,
		blockDoH:     rt.BlockDoH,
		allowLAN:     rt.AllowLAN,
		sniffTimeout: time.Duration(rt.SniffTimeoutMS) * time.Millisecond,
	}
	if c.mode != store.ModeLists {
		c.def = rules.Tunnel
	}
	if c.sniffTimeout <= 0 {
		c.sniffTimeout = 300 * time.Millisecond
	}
	r.cfg.Store(c)
	r.journal.resize(rt.JournalSize)

	r.opts.DNS.SetConfig(dns.Config{
		Route:         func(name string) rules.Action { return r.decideHost(r.cfg.Load(), name).Action },
		TunnelServers: servers(rt.DNSTunnel),
		DirectServers: servers(rt.DNSDirect),
		Blocked: func(name string) bool {
			return r.cfg.Load().blockDoH && dohHost(name)
		},
	})
}

func servers(list []string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, s := range list {
		s = strings.TrimSpace(s)
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap)
		} else if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.AddrPortFrom(a, 53))
		}
	}
	return out
}

// Decision is a routing result with an explanation.
type Decision struct {
	Action rules.Action `json:"action"`
	Rule   string       `json:"rule,omitempty"`
	Source string       `json:"source,omitempty"`
	Host   string       `json:"host,omitempty"`
	// HostFrom: sni, http, quic, dns (cache) or empty.
	HostFrom string `json:"host_from,omitempty"`
}

const (
	srcDefault = "по умолчанию"
	srcFull    = "режим «всё в туннель»"
	srcDoH     = "блокировка DoH/DoT"
	srcLAN     = "защита локальной сети"
	srcQUIC    = "блокировка QUIC"
)

func (r *Router) decideHost(c *config, host string) Decision {
	if c.mode == store.ModeFull {
		return Decision{Action: rules.Tunnel, Source: srcFull, Host: host}
	}
	if h, ok := rules.NormHost(host); ok {
		host = h
	}
	if c.blockDoH && dohHost(host) {
		return Decision{Action: rules.Block, Source: srcDoH, Host: host}
	}
	m := c.matcher.Domain(host)
	if m.Action == rules.None {
		return Decision{Action: c.def, Source: srcDefault, Host: host}
	}
	return Decision{Action: m.Action, Rule: m.Rule, Source: m.Source, Host: host}
}

// decideIP applies the rules that need only the destination address.
func (r *Router) decideIP(c *config, dst netip.AddrPort, udp bool) (Decision, bool) {
	ip := dst.Addr()
	if c.mode == store.ModeFull {
		return Decision{Action: rules.Tunnel, Source: srcFull}, true
	}
	if c.blockDoH && (dst.Port() == 853 || dst.Port() == 443 && dohIPs[ip]) {
		return Decision{Action: rules.Block, Source: srcDoH}, true
	}
	if m := c.matcher.IP(ip); m.Action != rules.None {
		return lanGuard(c, ip, Decision{Action: m.Action, Rule: m.Rule, Source: m.Source}), true
	}
	if !c.allowLAN && isLAN(ip) {
		// Decided before the handshake: a LAN address never needs a name,
		// and refusing early gives the client a clean "connection refused".
		return lanGuard(c, ip, Decision{Action: c.def, Source: srcDefault}), true
	}
	return Decision{}, false
}

// decideCached routes by names the DNS cache knows for the address.
func (r *Router) decideCached(c *config, ip netip.Addr) Decision {
	names := r.opts.DNS.Cache.Names(ip)
	for _, n := range names {
		if d := r.decideHost(c, n); d.Source != srcDefault {
			d.HostFrom = "dns"
			return d
		}
	}
	d := Decision{Action: c.def, Source: srcDefault}
	if len(names) > 0 {
		d.Host, d.HostFrom = names[0], "dns"
	}
	return d
}

// lanGuard refuses direct access to this machine's networks.
func lanGuard(c *config, ip netip.Addr, d Decision) Decision {
	if d.Action == rules.Direct && !c.allowLAN && isLAN(ip) {
		return Decision{Action: rules.Block, Source: srcLAN, Host: d.Host, HostFrom: d.HostFrom}
	}
	return d
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isLAN(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() ||
		ip.IsMulticast() || cgnat.Contains(ip) || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// --- TCP ---

// HandleTCP routes a new TCP connection.
func (r *Router) HandleTCP(q *stack.TCPRequest) {
	c := r.cfg.Load()
	dst := q.Dst
	if dst.Port() == 53 && (dst.Addr() == r.opts.Gateway || c.mode != store.ModeFull) {
		conn, err := q.Accept()
		if err == nil {
			r.opts.DNS.ServeStream(conn)
		}
		return
	}
	if dst.Addr() == r.opts.Gateway {
		q.Reject()
		return
	}
	e := r.newEntry("tcp", q.Src, dst)

	var conn net.Conn
	var first []byte
	d, decided := r.decideIP(c, dst, false)
	if !decided && sniffPorts[dst.Port()] {
		var err error
		if conn, err = q.Accept(); err != nil {
			return
		}
		var res sniff.Result
		first, res = sniffStream(conn, c.sniffTimeout)
		if res.Host != "" && !res.ECH {
			d = r.decideHost(c, res.Host)
			d.HostFrom = res.Protocol
			decided = true
		}
	}
	if !decided {
		d = r.decideCached(c, dst.Addr())
	}
	d = lanGuard(c, dst.Addr(), d)
	e.set(d)

	if d.Action == rules.Block {
		if conn != nil {
			conn.Close()
		} else {
			q.Reject()
		}
		r.finish(e, nil)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	out, err := r.dialTCP(ctx, d.Action, dst)
	cancel()
	if err != nil {
		if conn != nil {
			conn.Close()
		} else {
			q.Reject()
		}
		r.finish(e, err)
		return
	}
	if conn == nil {
		if conn, err = q.Accept(); err != nil {
			out.Close()
			r.finish(e, err)
			return
		}
	}
	r.finish(e, nil)
	r.stats.open(d.Action)
	defer r.stats.close(d.Action)
	if len(first) > 0 {
		if _, err := out.Write(first); err != nil {
			conn.Close()
			out.Close()
			return
		}
		r.stats.add(d.Action, true, len(first))
	}
	r.pipeTCP(conn, out, d.Action)
}

func (r *Router) dialTCP(ctx context.Context, a rules.Action, dst netip.AddrPort) (net.Conn, error) {
	if a == rules.Tunnel {
		return r.opts.Tunnel.DialTCP(ctx, dst)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp4", dst.String())
}

// sniffStream reads the first bytes until a name is found, the protocol is
// not recognised, or the timeout passes.
func sniffStream(c net.Conn, timeout time.Duration) ([]byte, sniff.Result) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, maxSniff)
	var res sniff.Result
	for len(buf) < maxSniff {
		c.SetReadDeadline(deadline)
		n, err := c.Read(tmp[:maxSniff-len(buf)])
		buf = append(buf, tmp[:n]...)
		var serr error
		res, serr = sniff.Stream(buf)
		if serr != sniff.ErrNeedMore || err != nil {
			break
		}
	}
	c.SetReadDeadline(time.Time{})
	return buf, res
}

type closeWriter interface{ CloseWrite() error }

var bufPool = sync.Pool{New: func() any { b := make([]byte, 64<<10); return &b }}

func (r *Router) pipeTCP(user, out net.Conn, a rules.Action) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn, up bool) {
		defer wg.Done()
		bp := bufPool.Get().(*[]byte)
		io.CopyBuffer(&countWriter{w: dst, r: r, a: a, up: up}, src, *bp)
		bufPool.Put(bp)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go cp(out, user, true)
	go cp(user, out, false)
	wg.Wait()
	user.Close()
	out.Close()
}

type countWriter struct {
	w  io.Writer
	r  *Router
	a  rules.Action
	up bool
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.r.stats.add(c.a, c.up, n)
	return n, err
}

// --- UDP ---

// HandleUDP routes a new UDP flow.
func (r *Router) HandleUDP(q *stack.UDPRequest) {
	c := r.cfg.Load()
	dst := q.Dst
	if dst.Port() == 53 && (dst.Addr() == r.opts.Gateway || c.mode != store.ModeFull) {
		r.opts.DNS.ServePacket(q.Conn)
		return
	}
	if dst.Addr() == r.opts.Gateway || dst.Addr().IsMulticast() || dst.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		q.Conn.Close()
		return
	}
	e := r.newEntry("udp", q.Src, dst)

	var first [][]byte
	d, decided := r.decideIP(c, dst, true)
	if !decided && dst.Port() == 443 {
		if c.blockQUIC == store.QUICBlock {
			d, decided = Decision{Action: rules.Block, Source: srcQUIC}, true
		} else {
			var res sniff.Result
			var isQUIC bool
			first, res, isQUIC = sniffQUIC(q.Conn, c.sniffTimeout)
			switch {
			case res.Host != "" && !res.ECH:
				d = r.decideHost(c, res.Host)
				d.HostFrom = "quic"
				decided = true
			case isQUIC && c.blockQUIC == store.QUICUnknown:
				d, decided = Decision{Action: rules.Block, Source: srcQUIC, Host: res.Host}, true
			}
		}
	}
	if !decided {
		d = r.decideCached(c, dst.Addr())
	}
	d = lanGuard(c, dst.Addr(), d)
	e.set(d)

	if d.Action == rules.Block {
		r.finish(e, nil)
		// Swallow the flow for a while so that retransmits don't create
		// a new flow (and log entry) per packet.
		drain(q.Conn, 30*time.Second)
		return
	}
	out, err := r.dialUDP(d.Action, dst)
	if err != nil {
		q.Conn.Close()
		r.finish(e, err)
		return
	}
	r.finish(e, nil)
	r.stats.open(d.Action)
	defer r.stats.close(d.Action)
	for _, p := range first {
		out.Write(p)
		r.stats.add(d.Action, true, len(p))
	}
	r.pipeUDP(q.Conn, out, d.Action)
}

func (r *Router) dialUDP(a rules.Action, dst netip.AddrPort) (net.Conn, error) {
	if a == rules.Tunnel {
		return r.opts.Tunnel.DialUDP(dst)
	}
	return net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dst))
}

// sniffQUIC reads Initial datagrams until the ClientHello name is known.
func sniffQUIC(c net.Conn, timeout time.Duration) ([][]byte, sniff.Result, bool) {
	deadline := time.Now().Add(timeout)
	var q sniff.QUIC
	var pkts [][]byte
	var res sniff.Result
	isQUIC := false
	buf := make([]byte, 65535)
	for len(pkts) < 8 {
		c.SetReadDeadline(deadline)
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		p := append([]byte(nil), buf[:n]...)
		pkts = append(pkts, p)
		r, serr := q.Add(p)
		res = r
		if serr == sniff.ErrUnknown {
			if len(pkts) == 1 {
				break // not QUIC at all
			}
			continue // e.g. a 0-RTT packet after the Initials
		}
		isQUIC = true
		if serr != sniff.ErrNeedMore {
			break
		}
	}
	c.SetReadDeadline(time.Time{})
	return pkts, res, isQUIC
}

func drain(c net.Conn, idle time.Duration) {
	defer c.Close()
	buf := make([]byte, 2048)
	for {
		c.SetReadDeadline(time.Now().Add(idle))
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}

func (r *Router) pipeUDP(user, out net.Conn, a rules.Action) {
	var once sync.Once
	stop := func() {
		once.Do(func() {
			user.Close()
			out.Close()
		})
	}
	// The flow ends when neither direction saw a packet for udpIdle.
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	cp := func(dst, src net.Conn, up bool) {
		defer stop()
		buf := make([]byte, 65535)
		for {
			src.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := src.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(0, last.Load())) < udpIdle {
					continue
				}
				return
			}
			last.Store(time.Now().UnixNano())
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
			r.stats.add(a, up, n)
		}
	}
	go cp(out, user, true)
	cp(user, out, false)
}

// --- check ---

// Check explains how a domain or IP would be routed (web UI "Проверить").
func (r *Router) Check(input string) (Decision, []string) {
	c := r.cfg.Load()
	input = strings.TrimSpace(input)
	if ip, err := netip.ParseAddr(input); err == nil {
		ip = ip.Unmap()
		if d, ok := r.decideIP(c, netip.AddrPortFrom(ip, 0), false); ok {
			return lanGuard(c, ip, d), r.opts.DNS.Cache.Names(ip)
		}
		return lanGuard(c, ip, r.decideCached(c, ip)), r.opts.DNS.Cache.Names(ip)
	}
	host := input
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	host = strings.SplitN(strings.SplitN(host, "/", 2)[0], ":", 2)[0]
	return r.decideHost(c, host), nil
}
