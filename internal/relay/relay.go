// Package relay wires together the upstream AmneziaWG client, the inbound
// AmneziaWG listeners and what is between them. Everything runs in-process:
// no OS network interfaces or routes are created.
//
// Between users and the upstream there are two paths:
//   - packet NAT: "everything to the tunnel" mode, and ICMP (ping) always;
//   - netstack: users' TCP/UDP flows are terminated in an in-memory stack and
//     handed to Flows (the router), which dials either directly or through
//     the upstream netstack.
//
// Both share the upstream tunnel address; the upstream netstack owns local
// ports stackPortLo..stackPortHi, NAT uses the rest.
package relay

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"alatyr/internal/awgconf"
	"alatyr/internal/nat"
	"alatyr/internal/stack"
	"alatyr/internal/store"
)

const stackPortLo, stackPortHi = 10000, 19999

// Flows handles users' TCP/UDP flows (the router).
type Flows interface {
	HandleTCP(*stack.TCPRequest)
	HandleUDP(*stack.UDPRequest)
}

// Options configure a Relay.
type Options struct {
	Upstream *awgconf.Config
	Subnet   netip.Prefix
	Gateway  netip.Addr
	MTU      int
	Store    *store.Store
	Debug    bool
}

// Relay is a running relay instance.
type Relay struct {
	opts     Options
	upDev    *device.Device
	upTun    *memTun
	upPeer   awgconf.Peer
	upAddr   netip.Addr
	nat      *nat.NAT
	upStack  *stack.Stack
	inStack  *stack.Stack
	full     atomic.Bool
	flows    atomic.Value // Flows
	sinks    sync.Map     // [4]byte user address -> *memTun
	live     sync.Map     // flowKey -> struct{}: flows handled by inStack
	liveN    atomic.Int64
	mu       sync.Mutex
	applyMu  sync.Mutex
	inbound  map[string]*inbound
	stop     chan struct{}
	stopOnce sync.Once
}

// flowKey identifies a user's TCP/UDP flow terminated in inStack.
type flowKey struct {
	proto    uint8
	src, dst netip.AddrPort
}

// track registers a stack flow for its lifetime, so that a switch to "full
// tunnel" does not steal its packets.
func (r *Relay) track(proto uint8, src, dst netip.AddrPort) func() {
	k := flowKey{proto, src, dst}
	r.live.Store(k, struct{}{})
	r.liveN.Add(1)
	return func() {
		r.live.Delete(k)
		r.liveN.Add(-1)
	}
}

type inbound struct {
	proto string
	port  int
	dev   *device.Device
	tun   *memTun
}

// PeerStats are runtime counters of one AWG peer.
type PeerStats struct {
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       uint64    `json:"rx_bytes"`
	TxBytes       uint64    `json:"tx_bytes"`
}

func newLogger(debug bool, prefix string) *device.Logger {
	l := &device.Logger{Verbosef: device.DiscardLogf}
	l.Errorf = func(f string, a ...any) { log.Printf("["+prefix+"] "+f, a...) }
	if debug {
		l.Verbosef = func(f string, a ...any) { log.Printf("["+prefix+"] "+f, a...) }
	}
	return l
}

// New starts the upstream connection and all enabled inbound listeners.
func New(opts Options) (*Relay, error) {
	up := opts.Upstream
	if len(up.Peers) != 1 {
		return nil, fmt.Errorf("upstream config must have exactly one [Peer], got %d", len(up.Peers))
	}
	var upAddr netip.Addr
	for _, a := range up.Interface.Addresses {
		if a.Addr().Is4() {
			upAddr = a.Addr()
			break
		}
	}
	if !upAddr.IsValid() {
		return nil, errors.New("upstream config has no IPv4 Address")
	}
	if opts.Subnet.Contains(upAddr) {
		return nil, fmt.Errorf("users subnet %s overlaps upstream address %s", opts.Subnet, upAddr)
	}
	upMTU := up.Interface.MTU
	if upMTU == 0 {
		upMTU = 1280
	}

	r := &Relay{
		opts:    opts,
		upPeer:  up.Peers[0],
		upAddr:  upAddr,
		inbound: map[string]*inbound{},
		stop:    make(chan struct{}),
	}
	r.full.Store(true)
	r.upTun = newMemTun("upstream", upMTU, r.fromUpstream)
	r.nat = nat.New(upAddr, opts.Subnet, opts.Gateway, r.upTun.Deliver)
	r.nat.Reserve(stackPortLo, stackPortHi)
	var err error
	r.upStack, err = stack.New(stack.Options{MTU: upMTU, Addr: upAddr, Output: r.upTun.Deliver,
		PortLo: stackPortLo, PortHi: stackPortHi})
	if err != nil {
		r.nat.Close()
		return nil, fmt.Errorf("upstream netstack: %w", err)
	}
	r.inStack, err = stack.New(stack.Options{MTU: opts.MTU, Output: r.toUser,
		TCP: func(q *stack.TCPRequest) {
			if f, ok := r.flows.Load().(Flows); ok {
				defer r.track(protoTCP, q.Src, q.Dst)()
				f.HandleTCP(q)
			} else {
				q.Reject()
			}
		},
		UDP: func(q *stack.UDPRequest) {
			if f, ok := r.flows.Load().(Flows); ok {
				defer r.track(protoUDP, q.Src, q.Dst)()
				f.HandleUDP(q)
			} else {
				q.Conn.Close()
			}
		}})
	if err != nil {
		r.nat.Close()
		r.upStack.Close()
		return nil, fmt.Errorf("inbound netstack: %w", err)
	}

	uapi, err := up.ClientUAPI()
	if err != nil {
		r.nat.Close()
		return nil, fmt.Errorf("upstream config: %w", err)
	}
	r.upDev = device.NewDevice(r.upTun, conn.NewDefaultBind(), newLogger(opts.Debug, "upstream"))
	if err := r.upDev.IpcSet(uapi); err != nil {
		r.Close()
		return nil, fmt.Errorf("upstream device: %w", err)
	}
	r.upTun.Wake()
	if err := r.upDev.Up(); err != nil {
		r.Close()
		return nil, fmt.Errorf("upstream up: %w", err)
	}
	log.Printf("upstream: %s via %s (tunnel address %s, MTU %d)", r.upPeer.Endpoint, r.upPeer.PublicKey, upAddr, upMTU)

	// A listener that cannot start (e.g. port busy) is not fatal: the
	// admin can pick another port in the web UI.
	if err := r.ApplyListeners(opts.Store.Settings().Listeners); err != nil {
		log.Printf("listeners: %v", err)
	}
	go r.reresolveLoop()
	return r, nil
}

func (r *Relay) startInbound(proto string, port int) error {
	srv, err := r.opts.Store.EnsureServer(proto)
	if err != nil {
		return err
	}
	ib := &inbound{proto: proto, port: port}
	ib.tun = newMemTun(proto, r.opts.MTU, func(pkt []byte) { r.fromUser(pkt, ib.tun) })
	ib.dev = device.NewDevice(ib.tun, conn.NewDefaultBind(), newLogger(r.opts.Debug, proto))

	pk, err := awgconf.KeyToHex(srv.PrivateKey)
	if err != nil {
		return err
	}
	params, err := awgconf.ParamsUAPI(awgconf.ServerParams(srv.Params))
	if err != nil {
		return fmt.Errorf("%s params: %w", proto, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\n%sreplace_peers=true\n", pk, port, params)
	for _, u := range r.opts.Store.Users() {
		if u.Protocol == proto && !u.Disabled {
			s, err := peerUAPI(u)
			if err != nil {
				log.Printf("%s: skip user %s: %v", proto, u.Name, err)
				continue
			}
			b.WriteString(s)
		}
	}
	if err := ib.dev.IpcSet(b.String()); err != nil {
		ib.dev.Close()
		log.Printf("%s listener on UDP %d: %v", proto, port, err)
		return fmt.Errorf("%s: не удалось занять UDP-порт %d (занят?)", awgconf.ProtocolTitle(proto), port)
	}
	ib.tun.Wake()
	if err := ib.dev.Up(); err != nil {
		ib.dev.Close()
		return fmt.Errorf("%s up: %w", proto, err)
	}
	r.mu.Lock()
	r.inbound[proto] = ib
	r.mu.Unlock()
	log.Printf("listening %s on UDP 0.0.0.0:%d", awgconf.ProtocolTitle(proto), port)
	return nil
}

// CheckListeners validates a listener set without applying it: ports must be
// in range, unique, and free (unless already ours).
func (r *Relay) CheckListeners(ls map[string]store.Listener) error {
	used := map[int]string{}
	for _, proto := range awgconf.Protocols {
		l := ls[proto]
		if l.Port < 0 || l.Port > 65535 || l.ExternalPort < 0 || l.ExternalPort > 65535 {
			return fmt.Errorf("%s: порт должен быть 1..65535", awgconf.ProtocolTitle(proto))
		}
		port := l.Active()
		if port == 0 {
			continue
		}
		if other, dup := used[port]; dup {
			return fmt.Errorf("UDP-порт %d указан и для %s, и для %s", port, awgconf.ProtocolTitle(other), awgconf.ProtocolTitle(proto))
		}
		used[port] = proto
	}
	r.mu.Lock()
	ours := map[int]bool{}
	for _, ib := range r.inbound {
		ours[ib.port] = true
	}
	r.mu.Unlock()
	for port, proto := range used {
		if ours[port] {
			continue
		}
		// The AWG bind listens on udp4 and udp6 separately; probe IPv4,
		// a dual-stack probe may succeed while 0.0.0.0:port is taken.
		c, err := net.ListenPacket("udp4", ":"+strconv.Itoa(port))
		if err != nil {
			return fmt.Errorf("%s: UDP-порт %d уже занят другой программой", awgconf.ProtocolTitle(proto), port)
		}
		c.Close()
	}
	return nil
}

// ApplyListeners starts, stops or re-binds inbound listeners to match ls.
// Port changes are applied live; connected users reconnect on their own.
func (r *Relay) ApplyListeners(ls map[string]store.Listener) error {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	var errs []error
	// Stop and re-bind first so freed ports can be reused by other protocols.
	for _, proto := range awgconf.Protocols {
		want := ls[proto].Active()
		r.mu.Lock()
		ib := r.inbound[proto]
		r.mu.Unlock()
		switch {
		case ib == nil:
		case want == 0:
			ib.dev.Close()
			r.mu.Lock()
			delete(r.inbound, proto)
			r.mu.Unlock()
			log.Printf("stopped %s", awgconf.ProtocolTitle(proto))
		case want != ib.port:
			if err := ib.dev.IpcSet(fmt.Sprintf("listen_port=%d\n", want)); err != nil {
				log.Printf("%s: rebind to UDP %d: %v", proto, want, err)
				errs = append(errs, fmt.Errorf("%s: не удалось занять UDP-порт %d (занят?)", awgconf.ProtocolTitle(proto), want))
				continue
			}
			r.mu.Lock()
			ib.port = want
			r.mu.Unlock()
			log.Printf("%s now listens on UDP 0.0.0.0:%d", awgconf.ProtocolTitle(proto), want)
		}
	}
	for _, proto := range awgconf.Protocols {
		want := ls[proto].Active()
		r.mu.Lock()
		ib := r.inbound[proto]
		r.mu.Unlock()
		if ib == nil && want > 0 {
			if err := r.startInbound(proto, want); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func peerUAPI(u store.User) (string, error) {
	pub, err := awgconf.KeyToHex(u.PublicKey)
	if err != nil {
		return "", err
	}
	psk, err := awgconf.KeyToHex(u.PresharedKey)
	if err != nil {
		return "", err
	}
	a, err := netip.ParseAddr(u.Address)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("public_key=%s\npreshared_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n",
		pub, psk, netip.PrefixFrom(a, 32)), nil
}

// AddUser makes a user able to connect.
func (r *Relay) AddUser(u store.User) error {
	if u.Disabled {
		return nil
	}
	r.mu.Lock()
	ib := r.inbound[u.Protocol]
	r.mu.Unlock()
	if ib == nil {
		return nil // loaded when the protocol gets enabled
	}
	s, err := peerUAPI(u)
	if err != nil {
		return err
	}
	return ib.dev.IpcSet(s)
}

// RemoveUser disconnects a user and forgets its NAT mappings.
func (r *Relay) RemoveUser(u store.User) error {
	r.mu.Lock()
	ib := r.inbound[u.Protocol]
	r.mu.Unlock()
	if a, err := netip.ParseAddr(u.Address); err == nil {
		r.nat.RemoveIP(a)
		if a.Is4() {
			r.sinks.Delete(a.As4())
		}
	}
	if ib == nil {
		return nil
	}
	pub, err := awgconf.KeyToHex(u.PublicKey)
	if err != nil {
		return err
	}
	return ib.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pub))
}

// Port returns the UDP port of a protocol listener (0 if disabled).
func (r *Relay) Port(proto string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ib := r.inbound[proto]; ib != nil {
		return ib.port
	}
	return 0
}

// UpstreamAddr is the tunnel address assigned by the upstream server.
func (r *Relay) UpstreamAddr() netip.Addr { return r.upAddr }

// UpstreamEndpoint returns the configured upstream endpoint.
func (r *Relay) UpstreamEndpoint() string { return r.upPeer.Endpoint }

// UpstreamStats returns counters of the upstream peer.
func (r *Relay) UpstreamStats() PeerStats {
	for _, s := range parseStats(r.upDev) {
		return s
	}
	return PeerStats{}
}

// UserStats returns per public key (base64) counters for a protocol.
func (r *Relay) UserStats() map[string]PeerStats {
	r.mu.Lock()
	ibs := make([]*inbound, 0, len(r.inbound))
	for _, ib := range r.inbound {
		ibs = append(ibs, ib)
	}
	r.mu.Unlock()
	out := map[string]PeerStats{}
	for _, ib := range ibs {
		for k, v := range parseStats(ib.dev) {
			out[k] = v
		}
	}
	return out
}

// NATMappings returns the number of active NAT entries.
func (r *Relay) NATMappings() int { return r.nat.Stats() }

func parseStats(d *device.Device) map[string]PeerStats {
	raw, err := d.IpcGet()
	if err != nil {
		return nil
	}
	out := map[string]PeerStats{}
	var key string
	var cur PeerStats
	var sec, nsec int64
	flush := func() {
		if key != "" {
			if sec > 0 {
				cur.LastHandshake = time.Unix(sec, nsec)
			}
			out[key] = cur
		}
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			key, cur, sec, nsec = hexToB64(v), PeerStats{}, 0, 0
		case "endpoint":
			cur.Endpoint = v
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	flush()
	return out
}

// reresolveLoop re-resolves the upstream endpoint host when the handshake
// goes stale (dynamic DNS, server IP changes).
func (r *Relay) reresolveLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	last := ""
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
		}
		st := r.UpstreamStats()
		if !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < 3*time.Minute {
			continue
		}
		ep, err := awgconf.ResolveEndpoint(r.upPeer.Endpoint)
		if err != nil {
			log.Printf("upstream: resolve %s: %v", r.upPeer.Endpoint, err)
			continue
		}
		if ep == st.Endpoint || ep == last {
			continue
		}
		last = ep
		pub, _ := awgconf.KeyToHex(r.upPeer.PublicKey)
		if err := r.upDev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", pub, ep)); err != nil {
			log.Printf("upstream: update endpoint: %v", err)
		} else {
			log.Printf("upstream: endpoint re-resolved to %s", ep)
		}
	}
}

// SetFlows installs the flow handler (router).
func (r *Relay) SetFlows(f Flows) { r.flows.Store(f) }

// SetFullTunnel switches between packet NAT for everything (true) and
// per-flow routing (false). Running flows stay on the path they started on.
func (r *Relay) SetFullTunnel(full bool) { r.full.Store(full) }

// DialTCP connects through the tunnel.
func (r *Relay) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return r.upStack.DialTCP(ctx, dst)
}

// DialUDP opens a UDP socket through the tunnel.
func (r *Relay) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	return r.upStack.DialUDP(dst)
}

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// fromUser dispatches a packet decrypted by an inbound device.
func (r *Relay) fromUser(pkt []byte, sink *memTun) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if !r.opts.Subnet.Contains(src) {
		return
	}
	proto := pkt[9]
	toStack := (proto == protoTCP || proto == protoUDP) && r.stackPath(pkt, proto, src, dst)
	if !toStack {
		r.nat.FromInside(pkt, sink)
		return
	}
	if dst != r.opts.Gateway && r.opts.Subnet.Contains(dst) {
		return // no user-to-user traffic
	}
	if v, ok := r.sinks.Load(src.As4()); !ok || v.(*memTun) != sink {
		r.sinks.Store(src.As4(), sink)
	}
	r.inStack.Inject(pkt)
}

// stackPath decides whether a user's TCP/UDP packet goes to inStack (per-flow
// routing) or to NAT. Flows already running on one path stay there when the
// mode changes, so settings can be applied without breaking connections.
func (r *Relay) stackPath(pkt []byte, proto uint8, src, dst netip.Addr) bool {
	full := r.full.Load()
	if dst == r.opts.Gateway {
		return true // our resolver
	}
	h := int(pkt[0]&0x0f) * 4
	first := binary.BigEndian.Uint16(pkt[6:8])&0x1fff == 0
	if !first || len(pkt) < h+4 || (proto == protoTCP && len(pkt) < h+14) {
		return !full
	}
	l4 := pkt[h:]
	sp := netip.AddrPortFrom(src, binary.BigEndian.Uint16(l4[0:2]))
	if full {
		if r.liveN.Load() == 0 {
			return false
		}
		_, ok := r.live.Load(flowKey{proto, sp, netip.AddrPortFrom(dst, binary.BigEndian.Uint16(l4[2:4]))})
		return ok
	}
	if proto == protoTCP && l4[13]&0x12 == 0x02 {
		return true // a new connection (SYN) is always routed
	}
	return !r.nat.Owns(proto, sp)
}

// toUser delivers a packet from the inbound stack to the user's device.
func (r *Relay) toUser(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	if v, ok := r.sinks.Load([4]byte(pkt[16:20])); ok {
		v.(*memTun).Deliver(pkt)
	}
}

// fromUpstream dispatches a packet received from the tunnel: the upstream
// netstack owns its port range, NAT the rest.
func (r *Relay) fromUpstream(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	proto := pkt[9]
	if proto != protoTCP && proto != protoUDP {
		r.nat.FromOutside(pkt)
		return
	}
	if off := binary.BigEndian.Uint16(pkt[6:8]) & 0x1fff; off != 0 {
		// Non-first fragment: no ports. Whoever has the first fragment
		// will use it, the other drops it.
		cp := append([]byte(nil), pkt...)
		r.upStack.Inject(cp)
		r.nat.FromOutside(pkt)
		return
	}
	h := int(pkt[0]&0x0f) * 4
	if len(pkt) < h+4 {
		return
	}
	if port := binary.BigEndian.Uint16(pkt[h+2 : h+4]); port >= stackPortLo && port <= stackPortHi {
		r.upStack.Inject(pkt)
		return
	}
	r.nat.FromOutside(pkt)
}

// Close shuts everything down.
func (r *Relay) Close() {
	r.stopOnce.Do(func() {
		close(r.stop)
		r.mu.Lock()
		for _, ib := range r.inbound {
			ib.dev.Close()
		}
		r.mu.Unlock()
		if r.upDev != nil {
			r.upDev.Close()
		}
		r.inStack.Close()
		r.upStack.Close()
		r.nat.Close()
	})
}

func hexToB64(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	return base64.StdEncoding.EncodeToString(b)
}
