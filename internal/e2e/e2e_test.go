//go:build e2e

// End-to-end test against a real upstream server:
//
//	ALATYR_VPN_CONF=../../vpn.conf go test -tags e2e -v ./internal/e2e
//
// For every inbound protocol it creates a user, connects to the relay with an
// in-process AmneziaWG client and fetches the public IP through the chain.
package e2e

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"alatyr/internal/app"
	"alatyr/internal/awgconf"
	"alatyr/internal/store"
)

func fetchIP(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error)) string {
	t.Helper()
	c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: dial}}
	resp, err := c.Get("http://api.ipify.org/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

func TestRelay(t *testing.T) {
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
	ports := map[string]int{awgconf.ProtoAWG1: 41821, awgconf.ProtoAWG2: 41822, awgconf.ProtoAWG3: 41823, awgconf.ProtoWG: 41824}
	defaults := store.Settings{Listeners: map[string]store.Listener{}}
	for p, port := range ports {
		defaults.Listeners[p] = store.Listener{Port: port}
	}
	routing := store.DefaultRouting([]string{"1.1.1.1"})
	routing.Mode = store.ModeFull
	routing.Subscriptions = nil
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data.json"), subnet, defaults, routing)
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(app.Options{Upstream: up, Subnet: subnet, Gateway: netip.MustParseAddr("10.66.66.1"),
		MTU: 1280, Store: st, ListsDir: filepath.Join(dir, "lists"), Debug: os.Getenv("ALATYR_DEBUG") != ""})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	rl := a.Relay

	direct := fetchIP(t, (&net.Dialer{}).DialContext)
	t.Logf("direct IP: %s", direct)

	for _, proto := range awgconf.Protocols {
		t.Run(proto, func(t *testing.T) {
			u, err := st.AddUser("test-"+proto, proto)
			if err != nil {
				t.Fatal(err)
			}
			if err := rl.AddUser(u); err != nil {
				t.Fatal(err)
			}
			text, err := u.ClientConfig(st.Server(proto), "127.0.0.1:"+strconv.Itoa(ports[proto]), []string{"1.1.1.1"}, 1280)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("client config:\n%s", text)
			cc, err := awgconf.Parse(text)
			if err != nil {
				t.Fatal(err)
			}
			tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cc.Interface.Addresses[0].Addr()}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 1280)
			if err != nil {
				t.Fatal(err)
			}
			dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(map[bool]int{true: device.LogLevelVerbose, false: device.LogLevelError}[os.Getenv("ALATYR_DEBUG") != ""], proto+"-client: "))
			defer dev.Close()
			uapi, err := cc.ClientUAPI()
			if err != nil {
				t.Fatal(err)
			}
			if err := dev.IpcSet(uapi); err != nil {
				t.Fatal(err)
			}
			if err := dev.Up(); err != nil {
				t.Fatal(err)
			}
			// The first packet a stock amneziawg-go client sends after
			// configuration goes out without S4 padding (see memTun.Wake);
			// real client apps hit this too, so prime the tunnel first.
			if c, err := tnet.Dial("udp", "10.66.66.1:9"); err == nil {
				c.Write([]byte{0})
				c.Close()
				time.Sleep(300 * time.Millisecond)
			}
			// DNS through the tunnel.
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			addrs, err := tnet.LookupContextHost(ctx, "api.ipify.org")
			if err != nil {
				t.Fatalf("DNS via relay: %v", err)
			}
			t.Logf("resolved via tunnel: %v", addrs)
			got := fetchIP(t, tnet.DialContext)
			t.Logf("IP via relay (%s): %s", awgconf.ProtocolTitle(proto), got)
			if net.ParseIP(got) == nil {
				t.Fatalf("bad response %q", got)
			}
			if got == direct {
				t.Fatalf("traffic did not go through the upstream tunnel")
			}
			// Bulk TCP download: full-size packets through both tunnels.
			{
				c := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{DialContext: tnet.DialContext}}
				start := time.Now()
				resp, err := c.Get("http://speed.cloudflare.com/__down?bytes=20000000")
				if err != nil {
					t.Fatalf("download: %v", err)
				}
				n, err := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if err != nil || n != 20000000 {
					t.Fatalf("download: got %d bytes, err %v", n, err)
				}
				d := time.Since(start)
				t.Logf("downloaded %d MB in %v (%.1f Mbit/s)", n/1000000, d.Round(time.Millisecond), float64(n*8)/d.Seconds()/1e6)
			}
			// Ping the relay gateway and an internet host many times: catches
			// packet misclassification by the obfuscation layer.
			for _, target := range []string{"10.66.66.1", "1.1.1.1"} {
				pc, err := tnet.DialPingAddr(netip.Addr{}, netip.MustParseAddr(target))
				if err != nil {
					t.Fatal(err)
				}
				lost := 0
				for i := 0; i < 50; i++ {
					pkt := make([]byte, 8+i*20)
					pkt[0], pkt[7] = 8, byte(i)
					pc.SetDeadline(time.Now().Add(2 * time.Second))
					if _, err := pc.Write(pkt); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 2000)
					if _, err := pc.Read(buf); err != nil {
						lost++
					}
				}
				pc.Close()
				t.Logf("ping %s: %d/50 lost", target, lost)
				if lost > 2 {
					t.Errorf("ping %s: too many lost (%d/50)", target, lost)
				}
			}
		})
	}
	t.Logf("upstream stats: %+v, NAT mappings: %d", rl.UpstreamStats(), rl.NATMappings())
}

// TestClientConf connects with a user config downloaded from a running relay:
//
//	ALATYR_CLIENT_CONF=user.conf go test -tags e2e -v -run TestClientConf ./internal/e2e
func TestClientConf(t *testing.T) {
	path := os.Getenv("ALATYR_CLIENT_CONF")
	if path == "" {
		t.Skip("ALATYR_CLIENT_CONF not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := awgconf.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cc.Interface.Addresses[0].Addr()}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "client: "))
	defer dev.Close()
	uapi, err := cc.ClientUAPI()
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	dev.Up()
	if c, err := tnet.Dial("udp", "10.66.66.1:9"); err == nil {
		c.Write([]byte{0})
		c.Close()
		time.Sleep(300 * time.Millisecond)
	}
	t.Logf("IP via relay: %s", fetchIP(t, tnet.DialContext))
}
