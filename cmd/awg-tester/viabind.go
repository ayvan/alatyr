package main

import (
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// tunnelBind is a conn.Bind that sends the tested tunnel's UDP packets
// through another, already established tunnel (-via). The tested server then
// sees the connection coming from the internet, which checks port forwarding
// and NAT from the outside.
type tunnelBind struct {
	tnet  *netstack.Net
	laddr netip.Addr
	mu    sync.Mutex
	conn  net.PacketConn
}

type tunnelEndpoint struct{ dst netip.AddrPort }

func (e *tunnelEndpoint) ClearSrc()           {}
func (e *tunnelEndpoint) SrcToString() string { return "" }
func (e *tunnelEndpoint) DstToString() string { return e.dst.String() }
func (e *tunnelEndpoint) DstToBytes() []byte  { b, _ := e.dst.MarshalBinary(); return b }
func (e *tunnelEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *tunnelEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (b *tunnelBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c, err := b.tnet.ListenUDPAddrPort(netip.AddrPortFrom(b.laddr, port))
	if err != nil {
		return nil, 0, err
	}
	b.mu.Lock()
	b.conn = c
	b.mu.Unlock()
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := c.ReadFrom(packets[0])
		if err != nil {
			return 0, net.ErrClosed
		}
		ua := addr.(*net.UDPAddr)
		ip, _ := netip.AddrFromSlice(ua.IP)
		sizes[0] = n
		eps[0] = &tunnelEndpoint{dst: netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port))}
		return 1, nil
	}
	actual := port
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
		actual = uint16(la.Port)
	}
	return []conn.ReceiveFunc{recv}, actual, nil
}

func (b *tunnelBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		err := b.conn.Close()
		b.conn = nil
		return err
	}
	return nil
}

func (b *tunnelBind) SetMark(uint32) error { return nil }
func (b *tunnelBind) BatchSize() int       { return 1 }

func (b *tunnelBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	dst := ep.(*tunnelEndpoint).dst
	ua := &net.UDPAddr{IP: dst.Addr().AsSlice(), Port: int(dst.Port())}
	for _, buf := range bufs {
		if _, err := c.WriteTo(buf, ua); err != nil {
			return err
		}
	}
	return nil
}

func (b *tunnelBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &tunnelEndpoint{dst: ap}, nil
}
