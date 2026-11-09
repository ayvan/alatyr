package nat

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

type capture struct{ pkts [][]byte }

func (c *capture) Deliver(p []byte) { c.pkts = append(c.pkts, append([]byte(nil), p...)) }

func buildIPv4(src, dst [4]byte, proto uint8, l4 []byte) []byte {
	p := make([]byte, 20+len(l4))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], 0x1234)
	p[8] = 64
	p[9] = proto
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	copy(p[20:], l4)
	return p
}

func pseudoSum(p []byte) uint16 {
	l4 := p[20:]
	ph := make([]byte, 12+len(l4))
	copy(ph[0:4], p[12:16])
	copy(ph[4:8], p[16:20])
	ph[9] = p[9]
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(l4)))
	copy(ph[12:], l4)
	return checksum(ph)
}

func withL4Checksum(p []byte, at int) []byte {
	binary.BigEndian.PutUint16(p[20+at:22+at], 0)
	binary.BigEndian.PutUint16(p[20+at:22+at], pseudoSum(p))
	return p
}

func checkValid(t *testing.T, p []byte) {
	t.Helper()
	if checksum(p[:20]) != 0 {
		t.Fatalf("bad IP checksum")
	}
	switch p[9] {
	case protoTCP, protoUDP:
		if pseudoSum(p) != 0 {
			t.Fatalf("bad L4 checksum")
		}
	case protoICMP:
		if checksum(p[20:]) != 0 {
			t.Fatalf("bad ICMP checksum")
		}
	}
}

func TestUDPRoundTrip(t *testing.T) {
	pub := netip.MustParseAddr("10.126.57.123")
	var up [][]byte
	n := New(pub, netip.MustParsePrefix("10.66.66.0/24"), netip.MustParseAddr("10.66.66.1"), func(p []byte) { up = append(up, append([]byte(nil), p...)) })
	defer n.Close()

	c1, c2 := &capture{}, &capture{}
	remote := [4]byte{1, 1, 1, 1}
	udp := func(sport uint16) []byte {
		l4 := make([]byte, 8+5)
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], 53)
		binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
		copy(l4[8:], "hello")
		return l4
	}
	p1 := withL4Checksum(buildIPv4([4]byte{10, 66, 66, 2}, remote, protoUDP, udp(5000)), 6)
	p2 := withL4Checksum(buildIPv4([4]byte{10, 66, 66, 3}, remote, protoUDP, udp(5000)), 6)
	n.FromInside(p1, c1)
	n.FromInside(p2, c2)
	if len(up) != 2 {
		t.Fatalf("expected 2 upstream packets, got %d", len(up))
	}
	ports := map[uint16]bool{}
	for _, p := range up {
		checkValid(t, p)
		if [4]byte(p[12:16]) != pub.As4() {
			t.Fatalf("source not translated")
		}
		ports[binary.BigEndian.Uint16(p[20:22])] = true
	}
	if len(ports) != 2 {
		t.Fatalf("ports collide")
	}
	// Replies.
	for i, p := range up {
		r := make([]byte, 8+3)
		binary.BigEndian.PutUint16(r[0:2], 53)
		copy(r[2:4], p[20:22])
		binary.BigEndian.PutUint16(r[4:6], uint16(len(r)))
		copy(r[8:], "ok!")
		rp := withL4Checksum(buildIPv4(remote, pub.As4(), protoUDP, r), 6)
		n.FromOutside(rp)
		c := []*capture{c1, c2}[i]
		if len(c.pkts) != 1 {
			t.Fatalf("client %d got %d packets", i, len(c.pkts))
		}
		got := c.pkts[0]
		checkValid(t, got)
		if binary.BigEndian.Uint16(got[22:24]) != 5000 {
			t.Fatalf("dst port not restored")
		}
		if got[19] != byte(2+i) {
			t.Fatalf("wrong client ip %v", got[16:20])
		}
	}
}

func TestTCPAndICMPError(t *testing.T) {
	pub := netip.MustParseAddr("10.126.57.123")
	var up [][]byte
	n := New(pub, netip.MustParsePrefix("10.66.66.0/24"), netip.MustParseAddr("10.66.66.1"), func(p []byte) { up = append(up, append([]byte(nil), p...)) })
	defer n.Close()
	c := &capture{}
	remote := [4]byte{93, 184, 216, 34}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	p := withL4Checksum(buildIPv4([4]byte{10, 66, 66, 7}, remote, protoTCP, tcp), 16)
	// Occupy port 40000 first so remapping is exercised.
	other := withL4Checksum(buildIPv4([4]byte{10, 66, 66, 8}, remote, protoTCP, append([]byte(nil), tcp...)), 16)
	n.FromInside(other, &capture{})
	n.FromInside(p, c)
	out := up[1]
	checkValid(t, out)
	mapped := binary.BigEndian.Uint16(out[20:22])
	if mapped == 40000 {
		t.Fatalf("expected remap")
	}
	// ICMP frag-needed quoting our packet.
	icmp := make([]byte, 8+28)
	icmp[0], icmp[1] = 3, 4
	copy(icmp[8:], out[:28])
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	ip := buildIPv4([4]byte{192, 0, 2, 1}, pub.As4(), protoICMP, icmp)
	n.FromOutside(ip)
	if len(c.pkts) != 1 {
		t.Fatalf("icmp error not delivered")
	}
	got := c.pkts[0]
	checkValid(t, got)
	inner := got[28:]
	if inner[15] != 7 || binary.BigEndian.Uint16(inner[20:22]) != 40000 {
		t.Fatalf("quoted header not restored")
	}
	if checksum(inner[:20]) != 0 {
		t.Fatalf("quoted ip checksum broken")
	}
}

func TestGatewayPing(t *testing.T) {
	n := New(netip.MustParseAddr("10.0.0.2"), netip.MustParsePrefix("10.66.66.0/24"), netip.MustParseAddr("10.66.66.1"), func([]byte) {})
	defer n.Close()
	c := &capture{}
	icmp := make([]byte, 16)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 77)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	n.FromInside(buildIPv4([4]byte{10, 66, 66, 5}, [4]byte{10, 66, 66, 1}, protoICMP, icmp), c)
	if len(c.pkts) != 1 || c.pkts[0][20] != 0 {
		t.Fatalf("no echo reply")
	}
	checkValid(t, c.pkts[0])
}
