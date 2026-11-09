// Package nat implements a small userspace IPv4 source NAT.
//
// Packets coming from relay users ("inside") get their source address
// rewritten to the single address the upstream tunnel gave us, with the
// TCP/UDP port or ICMP echo identifier remapped so that many users can share
// it. Replies coming from the upstream ("outside") are translated back and
// delivered to the inside sink the flow originated from.
package nat

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// Timeouts for idle mappings.
var (
	TimeoutUDP        = 3 * time.Minute
	TimeoutTCP        = 4 * time.Hour
	TimeoutTCPClosing = time.Minute
	TimeoutTCPPending = 90 * time.Second
	TimeoutICMP       = 30 * time.Second
	TimeoutFragment   = 30 * time.Second
)

// Sink receives translated packets. The packet slice is owned by the callee.
type Sink interface {
	Deliver(pkt []byte)
}

type insideKey struct {
	proto uint8
	ip    [4]byte
	port  uint16
}

type outsideKey struct {
	proto uint8
	port  uint16
}

type fragKey struct {
	src   [4]byte
	id    uint16
	proto uint8
}

type entry struct {
	proto       uint8
	ip          [4]byte
	port        uint16
	mapped      uint16
	sink        Sink
	last        time.Time
	established bool // seen a packet from outside
	closing     bool // TCP FIN/RST seen
}

type fragEntry struct {
	ip   [4]byte
	sink Sink
	last time.Time
}

// NAT is the translator. It is safe for concurrent use.
type NAT struct {
	mu      sync.Mutex
	public  [4]byte
	gateway [4]byte
	inside  netip.Prefix
	byIn    map[insideKey]*entry
	byOut   map[outsideKey]*entry
	frags   map[fragKey]*fragEntry
	up      func(pkt []byte)
	resLo   uint16 // outside ports resLo..resHi belong to someone else
	resHi   uint16
	flows   atomic.Int64 // TCP/UDP mappings, see Owns
	now     func() time.Time
	stop    chan struct{}
}

// New creates a NAT. public is the upstream tunnel address, inside is the
// users' subnet and gateway is the relay's own address inside it. up is called
// with packets that must be sent to the upstream tunnel.
func New(public netip.Addr, inside netip.Prefix, gateway netip.Addr, up func(pkt []byte)) *NAT {
	n := &NAT{
		public:  public.As4(),
		gateway: gateway.As4(),
		inside:  inside.Masked(),
		byIn:    map[insideKey]*entry{},
		byOut:   map[outsideKey]*entry{},
		frags:   map[fragKey]*fragEntry{},
		up:      up,
		now:     time.Now,
		stop:    make(chan struct{}),
	}
	go n.gcLoop()
	return n
}

// Reserve keeps the outside TCP/UDP ports lo..hi out of NAT use (they
// belong to the upstream netstack sharing the tunnel address).
func (n *NAT) Reserve(lo, hi uint16) {
	n.mu.Lock()
	n.resLo, n.resHi = lo, hi
	n.mu.Unlock()
}

// Close stops background work.
func (n *NAT) Close() { close(n.stop) }

// Stats returns the number of active mappings.
func (n *NAT) Stats() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.byIn)
}

func (n *NAT) gcLoop() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.stop:
			return
		case <-t.C:
			n.gc()
		}
	}
}

func (n *NAT) gc() {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	for k, e := range n.byIn {
		if now.Sub(e.last) > e.timeout() {
			delete(n.byIn, k)
			delete(n.byOut, outsideKey{e.proto, e.mapped})
			n.counted(e, -1)
		}
	}
	for k, f := range n.frags {
		if now.Sub(f.last) > TimeoutFragment {
			delete(n.frags, k)
		}
	}
}

func (n *NAT) counted(e *entry, d int64) {
	if e.proto != protoICMP {
		n.flows.Add(d)
	}
}

// Owns reports whether a user's TCP/UDP source port has a live mapping, so
// that its packets keep going through NAT after a mode switch.
func (n *NAT) Owns(proto uint8, src netip.AddrPort) bool {
	if n.flows.Load() == 0 {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.byIn[insideKey{proto, src.Addr().As4(), src.Port()}] != nil
}

// RemoveIP drops all mappings of a user address (e.g. a removed user).
func (n *NAT) RemoveIP(ip netip.Addr) {
	a := ip.As4()
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, e := range n.byIn {
		if e.ip == a {
			delete(n.byIn, k)
			delete(n.byOut, outsideKey{e.proto, e.mapped})
			n.counted(e, -1)
		}
	}
}

func (e *entry) timeout() time.Duration {
	switch e.proto {
	case protoTCP:
		switch {
		case e.closing:
			return TimeoutTCPClosing
		case !e.established:
			return TimeoutTCPPending
		}
		return TimeoutTCP
	case protoUDP:
		return TimeoutUDP
	}
	return TimeoutICMP
}

// ipv4 header helpers

func ihl(p []byte) int { return int(p[0]&0x0f) * 4 }

func fragInfo(p []byte) (offset uint16, more bool) {
	v := binary.BigEndian.Uint16(p[6:8])
	return v & 0x1fff, v&0x2000 != 0
}

// validate trims pkt to the IPv4 total length and returns header length.
func validate(pkt []byte) ([]byte, int, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, 0, false
	}
	h := ihl(pkt)
	tot := int(binary.BigEndian.Uint16(pkt[2:4]))
	if h < 20 || tot < h || tot > len(pkt) {
		return nil, 0, false
	}
	return pkt[:tot], h, true
}

// FromInside handles a packet sent by a relay user. sink is where replies go.
func (n *NAT) FromInside(pkt []byte, sink Sink) {
	pkt, h, ok := validate(pkt)
	if !ok {
		return
	}
	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	dstAddr := netip.AddrFrom4(dst)
	if !n.inside.Contains(netip.AddrFrom4(src)) {
		return
	}
	if dst == n.gateway {
		n.answerGateway(pkt, h, sink)
		return
	}
	if n.inside.Contains(dstAddr) || dst == n.public || dstAddr.IsMulticast() || dst == [4]byte{255, 255, 255, 255} || dstAddr.IsUnspecified() {
		return
	}
	proto := pkt[9]
	off, _ := fragInfo(pkt)

	if off != 0 {
		// Non-first fragment: no L4 header, only the address changes.
		rewriteAddr(pkt, 12, n.public)
		n.up(pkt)
		return
	}

	l4 := pkt[h:]
	var port uint16
	switch proto {
	case protoTCP:
		if len(l4) < 20 {
			return
		}
		port = binary.BigEndian.Uint16(l4[0:2])
	case protoUDP:
		if len(l4) < 8 {
			return
		}
		port = binary.BigEndian.Uint16(l4[0:2])
	case protoICMP:
		if len(l4) < 8 || l4[0] != 8 { // only echo requests leave the relay
			return
		}
		port = binary.BigEndian.Uint16(l4[4:6])
	default:
		return
	}

	n.mu.Lock()
	k := insideKey{proto, src, port}
	e := n.byIn[k]
	if e == nil {
		mapped, ok := n.allocLocked(proto, port)
		if !ok {
			n.mu.Unlock()
			return
		}
		e = &entry{proto: proto, ip: src, port: port, mapped: mapped}
		n.byIn[k] = e
		n.byOut[outsideKey{proto, mapped}] = e
		n.counted(e, 1)
	}
	e.sink = sink
	e.last = n.now()
	if proto == protoTCP {
		flags := l4[13]
		if flags&0x05 != 0 { // FIN or RST
			e.closing = true
		} else if flags&0x02 != 0 { // new SYN on a reused tuple
			e.closing = false
		}
	}
	mapped := e.mapped
	n.mu.Unlock()

	// Rewrite source address and port, fixing checksums incrementally.
	oldSrc := src
	rewriteAddr(pkt, 12, n.public)
	switch proto {
	case protoTCP:
		fixL4(l4, 16, oldSrc, n.public, port, mapped)
		binary.BigEndian.PutUint16(l4[0:2], mapped)
	case protoUDP:
		if binary.BigEndian.Uint16(l4[6:8]) != 0 {
			fixL4(l4, 6, oldSrc, n.public, port, mapped)
			if binary.BigEndian.Uint16(l4[6:8]) == 0 {
				binary.BigEndian.PutUint16(l4[6:8], 0xffff)
			}
		}
		binary.BigEndian.PutUint16(l4[0:2], mapped)
	case protoICMP:
		c := binary.BigEndian.Uint16(l4[2:4])
		c = csumUpdate16(c, port, mapped)
		binary.BigEndian.PutUint16(l4[2:4], c)
		binary.BigEndian.PutUint16(l4[4:6], mapped)
	}
	n.up(pkt)
}

// FromOutside handles a packet received from the upstream tunnel.
func (n *NAT) FromOutside(pkt []byte) {
	pkt, h, ok := validate(pkt)
	if !ok {
		return
	}
	if [4]byte(pkt[16:20]) != n.public {
		return
	}
	proto := pkt[9]
	off, more := fragInfo(pkt)
	var remote [4]byte
	copy(remote[:], pkt[12:16])
	id := binary.BigEndian.Uint16(pkt[4:6])

	if off != 0 {
		n.mu.Lock()
		f := n.frags[fragKey{remote, id, proto}]
		if f != nil {
			f.last = n.now()
		}
		n.mu.Unlock()
		if f == nil {
			return
		}
		rewriteAddr(pkt, 16, f.ip)
		f.sink.Deliver(pkt)
		return
	}

	l4 := pkt[h:]
	var port uint16
	icmpError := false
	switch proto {
	case protoTCP:
		if len(l4) < 20 {
			return
		}
		port = binary.BigEndian.Uint16(l4[2:4])
	case protoUDP:
		if len(l4) < 8 {
			return
		}
		port = binary.BigEndian.Uint16(l4[2:4])
	case protoICMP:
		if len(l4) < 8 {
			return
		}
		switch l4[0] {
		case 0: // echo reply
			port = binary.BigEndian.Uint16(l4[4:6])
		case 3, 4, 5, 11, 12:
			icmpError = true
		default:
			return
		}
	default:
		return
	}

	if icmpError {
		n.fromOutsideICMPError(pkt, l4)
		return
	}

	n.mu.Lock()
	e := n.byOut[outsideKey{proto, port}]
	if e == nil {
		n.mu.Unlock()
		return
	}
	e.last = n.now()
	e.established = true
	if proto == protoTCP && l4[13]&0x05 != 0 {
		e.closing = true
	}
	if more {
		n.frags[fragKey{remote, id, proto}] = &fragEntry{ip: e.ip, sink: e.sink, last: e.last}
	}
	ip, orig, sink := e.ip, e.port, e.sink
	n.mu.Unlock()

	rewriteAddr(pkt, 16, ip)
	switch proto {
	case protoTCP:
		fixL4(l4, 16, n.public, ip, port, orig)
		binary.BigEndian.PutUint16(l4[2:4], orig)
	case protoUDP:
		if binary.BigEndian.Uint16(l4[6:8]) != 0 {
			fixL4(l4, 6, n.public, ip, port, orig)
			if binary.BigEndian.Uint16(l4[6:8]) == 0 {
				binary.BigEndian.PutUint16(l4[6:8], 0xffff)
			}
		}
		binary.BigEndian.PutUint16(l4[2:4], orig)
	case protoICMP:
		c := binary.BigEndian.Uint16(l4[2:4])
		c = csumUpdate16(c, port, orig)
		binary.BigEndian.PutUint16(l4[2:4], c)
		binary.BigEndian.PutUint16(l4[4:6], orig)
	}
	sink.Deliver(pkt)
}

// fromOutsideICMPError translates ICMP errors (unreachable, TTL exceeded,
// fragmentation needed...) that quote one of our outgoing packets.
func (n *NAT) fromOutsideICMPError(pkt, l4 []byte) {
	inner := l4[8:]
	if len(inner) < 20 || inner[0]>>4 != 4 {
		return
	}
	ih := ihl(inner)
	if ih < 20 || len(inner) < ih+8 {
		return
	}
	if [4]byte(inner[12:16]) != n.public {
		return
	}
	iproto := inner[9]
	il4 := inner[ih:]
	var port uint16
	switch iproto {
	case protoTCP, protoUDP:
		port = binary.BigEndian.Uint16(il4[0:2])
	case protoICMP:
		if il4[0] != 8 {
			return
		}
		port = binary.BigEndian.Uint16(il4[4:6])
	default:
		return
	}
	n.mu.Lock()
	e := n.byOut[outsideKey{iproto, port}]
	if e == nil {
		n.mu.Unlock()
		return
	}
	ip, orig, sink := e.ip, e.port, e.sink
	n.mu.Unlock()

	// Quoted header: source becomes the user again.
	rewriteAddr(inner, 12, ip)
	switch iproto {
	case protoTCP:
		if len(il4) >= 18 {
			fixL4(il4, 16, n.public, ip, port, orig)
		}
		binary.BigEndian.PutUint16(il4[0:2], orig)
	case protoUDP:
		if binary.BigEndian.Uint16(il4[6:8]) != 0 {
			fixL4(il4, 6, n.public, ip, port, orig)
		}
		binary.BigEndian.PutUint16(il4[0:2], orig)
	case protoICMP:
		c := binary.BigEndian.Uint16(il4[2:4])
		binary.BigEndian.PutUint16(il4[2:4], csumUpdate16(c, port, orig))
		binary.BigEndian.PutUint16(il4[4:6], orig)
	}
	// ICMP checksum covers the whole message: recompute it.
	binary.BigEndian.PutUint16(l4[2:4], 0)
	binary.BigEndian.PutUint16(l4[2:4], checksum(l4))
	rewriteAddr(pkt, 16, ip)
	sink.Deliver(pkt)
}

// answerGateway replies to ICMP echo requests addressed to the relay itself.
func (n *NAT) answerGateway(pkt []byte, h int, sink Sink) {
	l4 := pkt[h:]
	if pkt[9] != protoICMP || len(l4) < 8 || l4[0] != 8 {
		return
	}
	if off, more := fragInfo(pkt); off != 0 || more {
		return
	}
	out := make([]byte, len(pkt))
	copy(out, pkt)
	copy(out[12:16], pkt[16:20])
	copy(out[16:20], pkt[12:16])
	out[8] = 64
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:h]))
	ol4 := out[h:]
	ol4[0] = 0
	binary.BigEndian.PutUint16(ol4[2:4], 0)
	binary.BigEndian.PutUint16(ol4[2:4], checksum(ol4))
	sink.Deliver(out)
}

// allocLocked picks an outside port/identifier for a new mapping, preferring
// to keep the original one.
func (n *NAT) allocLocked(proto uint8, want uint16) (uint16, bool) {
	free := func(p uint16) bool {
		_, used := n.byOut[outsideKey{proto, p}]
		return !used
	}
	if proto == protoICMP {
		if free(want) {
			return want, true
		}
		start := uint16(rand.IntN(65536))
		for i := 0; i < 65536; i++ {
			if p := start + uint16(i); free(p) {
				return p, true
			}
		}
		return 0, false
	}
	reserved := func(p uint16) bool { return n.resHi != 0 && p >= n.resLo && p <= n.resHi }
	if want >= 1024 && free(want) && !reserved(want) {
		return want, true
	}
	const lo, span = 1024, 65536 - 1024
	start := rand.IntN(span)
	for i := 0; i < span; i++ {
		p := uint16(lo + (start+i)%span)
		if free(p) && !reserved(p) {
			return p, true
		}
	}
	return 0, false
}

// checksum helpers

func checksum(b []byte) uint16 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

// csumUpdate16 applies RFC 1624 incremental update for one 16-bit word.
func csumUpdate16(sum, old, new uint16) uint16 {
	s := uint32(^sum) + uint32(^old) + uint32(new)
	s = (s & 0xffff) + (s >> 16)
	s = (s & 0xffff) + (s >> 16)
	return ^uint16(s)
}

func csumUpdateAddr(sum uint16, old, new [4]byte) uint16 {
	sum = csumUpdate16(sum, binary.BigEndian.Uint16(old[0:2]), binary.BigEndian.Uint16(new[0:2]))
	return csumUpdate16(sum, binary.BigEndian.Uint16(old[2:4]), binary.BigEndian.Uint16(new[2:4]))
}

// rewriteAddr replaces the IPv4 address at offset (12 = src, 16 = dst) and
// fixes the IP header checksum.
func rewriteAddr(pkt []byte, offset int, addr [4]byte) {
	var old [4]byte
	copy(old[:], pkt[offset:offset+4])
	copy(pkt[offset:offset+4], addr[:])
	c := binary.BigEndian.Uint16(pkt[10:12])
	binary.BigEndian.PutUint16(pkt[10:12], csumUpdateAddr(c, old, addr))
}

// fixL4 updates a TCP/UDP checksum located at l4[at:] for an address change
// (pseudo header) and a port change.
func fixL4(l4 []byte, at int, oldIP, newIP [4]byte, oldPort, newPort uint16) {
	c := binary.BigEndian.Uint16(l4[at : at+2])
	c = csumUpdateAddr(c, oldIP, newIP)
	c = csumUpdate16(c, oldPort, newPort)
	binary.BigEndian.PutUint16(l4[at:at+2], c)
}
