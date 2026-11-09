// Package app assembles the running service: AmneziaWG relay, DNS resolver,
// flow router and rule subscriptions.
package app

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"alatyr/internal/awgconf"
	dnssrv "alatyr/internal/dns"
	"alatyr/internal/lists"
	"alatyr/internal/relay"
	"alatyr/internal/router"
	"alatyr/internal/store"
)

// Options configure the service.
type Options struct {
	Upstream *awgconf.Config
	Subnet   netip.Prefix
	Gateway  netip.Addr
	MTU      int
	Store    *store.Store
	ListsDir string
	Debug    bool
}

// App is the running service.
type App struct {
	Relay  *relay.Relay
	Router *router.Router
	DNS    *dnssrv.Server
	Lists  *lists.Manager
	store  *store.Store

	applyMu sync.Mutex
}

// New starts everything. Subscriptions without a cache are downloaded in
// the background.
func New(o Options) (*App, error) {
	rl, err := relay.New(relay.Options{
		Upstream: o.Upstream, Subnet: o.Subnet, Gateway: o.Gateway, MTU: o.MTU, Store: o.Store, Debug: o.Debug,
	})
	if err != nil {
		return nil, err
	}
	dialTunnel := func(ctx context.Context, network string, a netip.AddrPort) (net.Conn, error) {
		if network == "tcp" {
			return rl.DialTCP(ctx, a)
		}
		return rl.DialUDP(a)
	}
	dialDirect := func(ctx context.Context, network string, a netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network+"4", a.String())
	}
	a := &App{Relay: rl, store: o.Store}
	a.DNS = dnssrv.New(dnssrv.NetExchanger{Dial: dialTunnel}, dnssrv.NetExchanger{Dial: dialDirect}, dnssrv.Config{})
	a.Router = router.New(router.Options{Tunnel: rl, Gateway: o.Gateway, DNS: a.DNS, UserName: newUserNames(o.Store).name})
	a.Lists = lists.New(o.ListsDir, tunnelHTTPClient(rl, o.Store), &http.Client{Timeout: 3 * time.Minute},
		o.Store.Routing, a.Apply)
	rl.SetFlows(a.Router)
	a.Lists.Start()
	return a, nil
}

// Apply pushes the stored routing settings and loaded lists to the
// running service.
func (a *App) Apply() {
	// Serialised: a list update and a save from the web UI must not race
	// and leave the older configuration in place.
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	r := a.store.Routing()
	a.Relay.SetFullTunnel(r.Mode == store.ModeFull)
	a.Router.Configure(r, a.Lists.Sources(r.Subscriptions))
}

// Close stops everything.
func (a *App) Close() {
	a.Lists.Close()
	a.Relay.Close()
}
