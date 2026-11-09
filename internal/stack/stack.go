// Package stack wraps an in-memory gVisor TCP/IP stack fed with raw IPv4
// packets. It is used twice:
//
//   - inbound: terminates the TCP/UDP flows of relay users (any destination
//     address) so that each flow can be routed on its own;
//   - upstream: the client side of the AmneziaWG tunnel, used to dial
//     destinations through the VPN.
package stack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = 1

// Options configure a Stack.
type Options struct {
	MTU int
	// Addr is the stack's own address. When invalid the stack accepts
	// packets to any address (inbound mode, requires TCP/UDP handlers).
	Addr netip.Addr
	// Output receives packets the stack sends. The slice is owned by the
	// callee and must not block.
	Output func(pkt []byte)
	// PortLo..PortHi is the range of local ports for dialed connections
	// (0 = gVisor default).
	PortLo, PortHi uint16
	// TCP and UDP handle new inbound flows (inbound mode). The handlers run
	// in their own goroutines.
	TCP func(*TCPRequest)
	UDP func(*UDPRequest)
}

// Stack is a running gVisor stack.
type Stack struct {
	s      *stack.Stack
	ep     *channel.Endpoint
	output func([]byte)
}

// New creates a stack.
func New(o Options) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	st := &Stack{s: s, ep: channel.New(4096, uint32(o.MTU), ""), output: o.Output}

	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	// Larger windows: the default 1 MB caps throughput on high-RTT paths.
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)
	mod := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mod)

	st.ep.AddNotify(st)
	if err := s.CreateNIC(nicID, st.ep); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}
	if o.Addr.IsValid() {
		pa := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(o.Addr.AsSlice()).WithPrefix(),
		}
		if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("add address: %v", err)
		}
	} else {
		// Accept and answer for any destination address.
		s.SetPromiscuousMode(nicID, true)
		s.SetSpoofing(nicID, true)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	if o.PortLo != 0 {
		if err := s.SetPortRange(o.PortLo, o.PortHi); err != nil {
			return nil, fmt.Errorf("port range: %v", err)
		}
	}

	if o.TCP != nil {
		fwd := tcp.NewForwarder(s, 0, 4096, func(r *tcp.ForwarderRequest) {
			id := r.ID()
			o.TCP(&TCPRequest{r: r, Src: addrPort(id.RemoteAddress, id.RemotePort), Dst: addrPort(id.LocalAddress, id.LocalPort)})
		})
		s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	}
	if o.UDP != nil {
		fwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
			id := r.ID()
			req := &UDPRequest{Src: addrPort(id.RemoteAddress, id.RemotePort), Dst: addrPort(id.LocalAddress, id.LocalPort)}
			// The endpoint must be created synchronously: it takes over
			// the first packet of the flow.
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				return
			}
			req.Conn = gonet.NewUDPConn(s, &wq, ep)
			go o.UDP(req)
		})
		s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
	}
	return st, nil
}

// WriteNotify is called by the link endpoint when the stack sends a packet.
func (st *Stack) WriteNotify() {
	pkt := st.ep.Read()
	if pkt.IsNil() {
		return
	}
	v := pkt.ToView()
	pkt.DecRef()
	b := make([]byte, v.Size())
	copy(b, v.AsSlice())
	v.Release()
	st.output(b)
}

// Inject feeds a packet received from the network into the stack.
func (st *Stack) Inject(pkt []byte) {
	if len(pkt) == 0 || pkt[0]>>4 != 4 {
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	st.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
}

// DialTCP opens a TCP connection from the stack's address.
func (st *Stack) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !dst.Addr().Is4() {
		return nil, errors.New("only IPv4 is supported")
	}
	c, err := gonet.DialContextTCP(ctx, st.s, fullAddr(dst), ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// DialUDP opens a connected UDP socket from the stack's address.
func (st *Stack) DialUDP(dst netip.AddrPort) (net.Conn, error) {
	if !dst.Addr().Is4() {
		return nil, errors.New("only IPv4 is supported")
	}
	fa := fullAddr(dst)
	c, err := gonet.DialUDP(st.s, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Close stops the stack.
func (st *Stack) Close() {
	st.s.Close()
	st.ep.Close()
}

// TCPRequest is a new TCP connection from a user, before it is accepted.
type TCPRequest struct {
	Src, Dst netip.AddrPort
	r        *tcp.ForwarderRequest
	done     bool
}

// Accept completes the handshake with the user.
func (q *TCPRequest) Accept() (net.Conn, error) {
	var wq waiter.Queue
	ep, err := q.r.CreateEndpoint(&wq)
	q.r.Complete(false)
	q.done = true
	if err != nil {
		return nil, fmt.Errorf("accept: %v", err)
	}
	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(60 * time.Second)
	ep.SetSockOpt(&idle)
	return gonet.NewTCPConn(&wq, ep), nil
}

// Reject answers the SYN with a reset (destination unreachable).
func (q *TCPRequest) Reject() {
	if !q.done {
		q.r.Complete(true)
		q.done = true
	}
}

// UDPRequest is a new UDP flow from a user. Conn reads datagrams sent by the
// user and writes replies back to it.
type UDPRequest struct {
	Src, Dst netip.AddrPort
	Conn     net.Conn
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip, port)
}

func fullAddr(ap netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}
}
