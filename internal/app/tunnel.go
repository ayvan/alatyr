package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"alatyr/internal/relay"
	"alatyr/internal/store"
)

// tunnelHTTPClient makes HTTP requests through the VPN tunnel, resolving
// names with the tunnel DNS servers from the routing settings.
func tunnelHTTPClient(rl *relay.Relay, st *store.Store) *http.Client {
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		srv := netip.MustParseAddrPort("1.1.1.1:53")
		for _, s := range st.Routing().DNSTunnel {
			if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
				srv = netip.AddrPortFrom(a, 53)
				break
			}
		}
		if network == "tcp" || network == "tcp4" {
			return rl.DialTCP(ctx, srv)
		}
		return rl.DialUDP(srv)
	}}
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		host, ps, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(ps)
		if err != nil {
			return nil, err
		}
		ips := []netip.Addr{}
		if a, err := netip.ParseAddr(host); err == nil {
			ips = append(ips, a)
		} else if ips, err = res.LookupNetIP(ctx, "ip4", host); err != nil {
			return nil, err
		}
		var last error = errors.New("no IPv4 address for " + host)
		for _, ip := range ips {
			c, err := rl.DialTCP(ctx, netip.AddrPortFrom(ip.Unmap(), uint16(port)))
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}
	return &http.Client{
		Timeout: 3 * time.Minute,
		Transport: &http.Transport{
			DialContext:         dial,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 20 * time.Second,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// userNames maps user addresses to names for the routing journal.
type userNames struct {
	st *store.Store
	mu sync.Mutex
	m  map[netip.Addr]string
	at time.Time
}

func newUserNames(st *store.Store) *userNames { return &userNames{st: st} }

func (u *userNames) name(ip netip.Addr) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if time.Since(u.at) > 10*time.Second {
		u.m = map[netip.Addr]string{}
		for _, usr := range u.st.Users() {
			if a, err := netip.ParseAddr(usr.Address); err == nil {
				u.m[a] = usr.Name
			}
		}
		u.at = time.Now()
	}
	return u.m[ip]
}
