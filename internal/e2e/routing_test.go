//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"alatyr/internal/app"
	"alatyr/internal/awgconf"
	"alatyr/internal/router"
	"alatyr/internal/rules"
	"alatyr/internal/store"
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func get(t *testing.T, dial dialFunc, url string) string {
	t.Helper()
	c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: dial, DisableKeepAlives: true}}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

// lastEntry finds the newest journal entry for a host or destination.
func lastEntry(t *testing.T, rt *router.Router, needle string) router.Entry {
	t.Helper()
	for i := 0; i < 20; i++ {
		if es := rt.Journal(needle, 1); len(es) > 0 {
			return es[0]
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no journal entry for %s", needle)
	return router.Entry{}
}

func TestRouting(t *testing.T) {
	path := os.Getenv("ALATYR_VPN_CONF")
	if path == "" {
		t.Skip("ALATYR_VPN_CONF not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	up, err := awgconf.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	subnet := netip.MustParsePrefix("10.66.66.0/24")
	gw := netip.MustParseAddr("10.66.66.1")
	const port = 41832
	defaults := store.Settings{Listeners: map[string]store.Listener{awgconf.ProtoAWG2: {Port: port}}}
	routing := store.DefaultRouting([]string{"1.1.1.1"})
	routing.Mode = store.ModeLists
	routing.Subscriptions = nil
	routing.Tunnel = "api.ipify.org\nicanhazip.com\n149.154.160.0/20\n"
	routing.Direct = ""
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data.json"), subnet, defaults, routing)
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(app.Options{Upstream: up, Subnet: subnet, Gateway: gw, MTU: 1280, Store: st,
		ListsDir: filepath.Join(dir, "lists"), Debug: os.Getenv("ALATYR_DEBUG") != ""})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	setRouting := func(f func(r *store.Routing)) {
		r := st.Routing()
		f(&r)
		if err := st.SetRouting(r); err != nil {
			t.Fatal(err)
		}
		a.Apply()
	}

	u, err := st.AddUser("router-test", awgconf.ProtoAWG2)
	if err != nil {
		t.Fatal(err)
	}
	a.Relay.AddUser(u)
	text, err := u.ClientConfig(st.Server(u.Protocol), "127.0.0.1:41832", []string{gw.String()}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	cc, _ := awgconf.Parse(text)
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cc.Interface.Addresses[0].Addr()}, []netip.Addr{gw}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "client: "))
	defer dev.Close()
	uapi, _ := cc.ClientUAPI()
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	dev.Up()
	if c, err := tnet.Dial("udp", "10.66.66.1:9"); err == nil {
		c.Write([]byte{0})
		c.Close()
		time.Sleep(300 * time.Millisecond)
	}

	// "Direct" is whatever this machine's own routing gives (it may have
	// another VPN with split routes), so compare per URL.
	hostDial := (&net.Dialer{}).DialContext
	direct := get(t, hostDial, "http://checkip.amazonaws.com/")
	directIpify := get(t, hostDial, "http://api.ipify.org/")
	t.Logf("direct IP: %s (api.ipify.org sees %s)", direct, directIpify)

	// 1. Our DNS works and a domain from "my additions" goes through the
	// tunnel (decided by HTTP Host).
	tunnelIP := get(t, tnet.DialContext, "http://api.ipify.org/")
	t.Logf("api.ipify.org via relay: %s", tunnelIP)
	if net.ParseIP(tunnelIP) == nil || tunnelIP == direct || tunnelIP == directIpify {
		t.Fatalf("api.ipify.org must go through the tunnel: got %q, direct %s", tunnelIP, direct)
	}
	if e := lastEntry(t, a.Router, "api.ipify.org"); e.Action != rules.Tunnel || e.HostFrom != "http" {
		t.Errorf("journal: %+v", e)
	}

	// 2. A domain outside the rules goes directly.
	if got := get(t, tnet.DialContext, "http://checkip.amazonaws.com/"); got != direct {
		t.Fatalf("checkip.amazonaws.com must go directly: got %s, direct %s", got, direct)
	}

	// 3. HTTPS: decided by SNI, even without our DNS (the IP is resolved
	// on the host, as with DoH in a browser).
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip4", "icanhazip.com")
	if err != nil || len(ips) == 0 {
		t.Fatalf("resolve icanhazip.com: %v", err)
	}
	byIP := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ips[0], 443))
	}
	if got := get(t, byIP, "https://icanhazip.com/"); got != tunnelIP {
		t.Errorf("icanhazip.com over TLS by IP: got %s want tunnel %s", got, tunnelIP)
	}
	if e := lastEntry(t, a.Router, "icanhazip.com"); e.Action != rules.Tunnel || e.HostFrom != "tls" {
		t.Errorf("journal: %+v", e)
	}

	// 4. My exclusions win over my additions.
	setRouting(func(r *store.Routing) { r.Direct = "ipify.org\n" })
	if got := get(t, tnet.DialContext, "http://api.ipify.org/"); got != directIpify {
		t.Errorf("excluded api.ipify.org: got %s want direct %s", got, directIpify)
	}
	setRouting(func(r *store.Routing) { r.Direct = "" })

	// 5. Telegram subnet by IP: TCP to 149.154.167.50:443 via the tunnel.
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := tnet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("149.154.167.50:443"))
		cancel()
		if err != nil {
			t.Errorf("telegram: %v", err)
		} else {
			c.Close()
		}
		if e := lastEntry(t, a.Router, "149.154.167.50"); e.Action != rules.Tunnel || e.Rule != "149.154.160.0/20" {
			t.Errorf("telegram journal: %+v", e)
		}
	}

	// 6. LAN protection: direct access to private addresses is refused.
	{
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := tnet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("192.168.255.254:80"))
		cancel()
		if err == nil {
			c.Close()
			t.Errorf("LAN address must be refused")
		}
		if e := lastEntry(t, a.Router, "192.168.255.254"); e.Action != rules.Block {
			t.Errorf("LAN journal: %+v", e)
		}
	}

	// 7. TLS works end-to-end through both paths (certificates checked).
	{
		c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: tnet.DialContext, TLSClientConfig: &tls.Config{}}}
		for _, url := range []string{"https://api.ipify.org/", "https://checkip.amazonaws.com/"} {
			resp, err := c.Get(url)
			if err != nil {
				t.Errorf("%s: %v", url, err)
				continue
			}
			resp.Body.Close()
		}
	}

	// 8. Bulk transfer in both directions, directly and through the tunnel.
	bulk := func(label string) {
		c := &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{DialContext: tnet.DialContext}}
		start := time.Now()
		resp, err := c.Get("http://speed.cloudflare.com/__down?bytes=20000000")
		if err != nil {
			t.Fatalf("%s download: %v", label, err)
		}
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil || n != 20000000 {
			t.Fatalf("%s download: %d bytes, %v", label, n, err)
		}
		d := time.Since(start)
		t.Logf("%s: download 20 MB in %v (%.1f Mbit/s)", label, d.Round(time.Millisecond), 160/d.Seconds())
		start = time.Now()
		resp, err = c.Post("http://speed.cloudflare.com/__up", "application/octet-stream", bytes.NewReader(make([]byte, 20000000)))
		if err != nil {
			t.Fatalf("%s upload: %v", label, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		d = time.Since(start)
		t.Logf("%s: upload 20 MB in %v (%.1f Mbit/s)", label, d.Round(time.Millisecond), 160/d.Seconds())
	}
	bulk("direct")
	if e := lastEntry(t, a.Router, "speed.cloudflare.com"); e.Action != rules.Direct {
		t.Errorf("speed test should be direct: %+v", e)
	}
	setRouting(func(r *store.Routing) { r.Tunnel += "speed.cloudflare.com\n" })
	bulk("tunnel")
	if e := lastEntry(t, a.Router, "speed.cloudflare.com"); e.Action != rules.Tunnel {
		t.Errorf("speed test should be tunnel: %+v", e)
	}

	// 9. Inverted mode: everything through the tunnel except exclusions.
	setRouting(func(r *store.Routing) { r.Mode = store.ModeExcept; r.Direct = "amazonaws.com\n" })
	if got := get(t, tnet.DialContext, "http://api.ipify.org/"); got != tunnelIP {
		t.Errorf("except mode api.ipify.org: got %s", got)
	}
	if got := get(t, tnet.DialContext, "http://checkip.amazonaws.com/"); got != direct {
		t.Errorf("except mode excluded checkip: got %s", got)
	}

	// 10. Switch to "everything to the tunnel" at runtime.
	setRouting(func(r *store.Routing) { r.Mode = store.ModeFull })
	if got := get(t, tnet.DialContext, "http://checkip.amazonaws.com/"); got != tunnelIP {
		t.Errorf("full mode checkip: got %s want %s", got, tunnelIP)
	}

	// 11. Settings are applied without breaking running connections: a
	// keep-alive connection survives an edit of my additions, a
	// subscription update and mode switches, keeping the path it started
	// on; new connections follow the new settings.
	setRouting(func(r *store.Routing) {
		r.Mode, r.Direct, r.Tunnel = store.ModeLists, "", "api.ipify.org\n"
	})
	const trace = "http://speed.cloudflare.com/cdn-cgi/trace"
	traceIP := func(body string) string {
		for _, l := range strings.Split(body, "\n") {
			if v, ok := strings.CutPrefix(l, "ip="); ok {
				return v
			}
		}
		return ""
	}
	directCF := traceIP(get(t, hostDial, trace))
	keepAlive := func() *http.Client {
		return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: tnet.DialContext}}
	}
	reused := func(c *http.Client, label, want string, first ...bool) {
		t.Helper()
		var again bool
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			GotConn: func(i httptrace.GotConnInfo) { again = i.Reused },
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, trace, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := traceIP(string(b)); (!again && len(first) == 0) || got != want {
			t.Errorf("%s: reused=%v ip=%s, want reused connection with ip %s", label, again, got, want)
		}
	}
	old := keepAlive()
	reused(old, "before", directCF, true) // opens the connection
	setRouting(func(r *store.Routing) { r.Tunnel += "speed.cloudflare.com\n" })
	reused(old, "after editing my additions", directCF)
	if got := traceIP(get(t, tnet.DialContext, trace)); got != tunnelIP {
		t.Errorf("new connection after edit: %s want tunnel %s", got, tunnelIP)
	}

	lst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "||example.org\n")
	}))
	defer lst.Close()
	sub := store.Subscription{ID: "e2e", Name: "e2e", URL: lst.URL, Enabled: true, Action: "tunnel", Via: "direct"}
	setRouting(func(r *store.Routing) { r.Subscriptions = []store.Subscription{sub} })
	if err := a.Lists.Update(sub); err != nil {
		t.Fatalf("subscription update: %v", err)
	}
	if d, _ := a.Router.Check("example.org"); d.Action != rules.Tunnel {
		t.Errorf("subscription not applied: %+v", d)
	}
	reused(old, "after subscription update", directCF)

	setRouting(func(r *store.Routing) { r.Mode = store.ModeFull })
	reused(old, "after switching to full", directCF)
	fullConn := keepAlive()
	reused(fullConn, "full mode", tunnelIP, true)
	setRouting(func(r *store.Routing) { r.Mode = store.ModeLists; r.Tunnel = "api.ipify.org\n" })
	reused(fullConn, "full-mode connection after switching back", tunnelIP)
	reused(old, "first connection after switching back", directCF)
	t.Logf("stats: %+v", a.Router.Stats())
}
