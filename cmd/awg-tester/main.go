// awg-tester connects to an AmneziaWG server (1.0 / 1.5 / 2.0 / 3.x) fully
// in userspace using a .conf file or a vpn:// key and checks that the tunnel
// really works: handshake, DNS, HTTP, exit IP, ping and download speed.
// Nothing is changed in the OS network settings.
//
//	awg-tester user.conf
//	awg-tester "vpn://AAAD..."
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"alatyr/internal/awgconf"
)

var (
	timeout   = flag.Duration("timeout", 15*time.Second, "handshake / request timeout")
	downloadM = flag.Int("download", 10, "download test size in MB (0 = skip)")
	pings     = flag.Int("ping", 20, "number of ICMP echo requests (0 = skip)")
	pingHost  = flag.String("ping-host", "1.1.1.1", "host to ping through the tunnel")
	ipURL     = flag.String("ip-url", "http://api.ipify.org/", "URL that returns the caller's public IP")
	verbose   = flag.Bool("v", false, "verbose AmneziaWG logs")
	expTunnel urlList
	expDirect urlList
	via       = flag.String("via", "", "send the tested tunnel's UDP through this other AWG config (checks reachability from the internet: port forwarding, NAT)")
)

type result struct {
	failed int
}

// urlList is a repeatable flag of IP-echo URLs (a bare domain means
// http://domain/).
type urlList []string

func (l *urlList) String() string { return strings.Join(*l, ",") }
func (l *urlList) Set(v string) error {
	if !strings.Contains(v, "://") {
		v = "http://" + v + "/"
	}
	*l = append(*l, v)
	return nil
}

func init() {
	flag.Var(&expTunnel, "expect-tunnel", "IP-echo URL or domain that must go through the VPN (Alatyr routing check); repeatable")
	flag.Var(&expDirect, "expect-direct", "IP-echo URL or domain that must go directly from the relay machine; repeatable")
}

func (r *result) ok(name, format string, a ...any) {
	fmt.Printf("  [ OK ] %-11s %s\n", name, fmt.Sprintf(format, a...))
}

func (r *result) fail(name, format string, a ...any) {
	r.failed++
	fmt.Printf("  [FAIL] %-11s %s\n", name, fmt.Sprintf(format, a...))
}

func (r *result) warn(name, format string, a ...any) {
	fmt.Printf("  [WARN] %-11s %s\n", name, fmt.Sprintf(format, a...))
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: awg-tester [flags] <config.conf | vpn://key>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	os.Exit(run(flag.Arg(0)))
}

func loadConfig(arg string) (*awgconf.Config, error) {
	text := arg
	if !strings.HasPrefix(strings.TrimSpace(arg), "vpn://") {
		raw, err := os.ReadFile(arg)
		if err != nil {
			return nil, err
		}
		text = string(raw)
	}
	if strings.HasPrefix(strings.TrimSpace(text), "vpn://") {
		var err error
		if text, err = awgconf.DecodeAmneziaURL(text); err != nil {
			return nil, err
		}
	}
	return awgconf.Parse(text)
}

func run(arg string) int {
	r := &result{}
	cfg, err := loadConfig(arg)
	if err != nil {
		fmt.Println("config:", err)
		return 2
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].Endpoint == "" {
		fmt.Println("config: need exactly one [Peer] with an Endpoint")
		return 2
	}
	var addrs []netip.Addr
	for _, a := range cfg.Interface.Addresses {
		addrs = append(addrs, a.Addr())
	}
	var dns []netip.Addr
	for _, d := range cfg.Interface.DNS {
		if a, err := netip.ParseAddr(d); err == nil {
			dns = append(dns, a)
		}
	}
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	mtu := cfg.Interface.MTU
	if mtu == 0 {
		mtu = 1280
	}

	fmt.Printf("awg-tester: %s, endpoint %s, address %v, MTU %d\n", cfg.Version(), cfg.Peers[0].Endpoint, addrs, mtu)

	ep, err := awgconf.ResolveEndpoint(cfg.Peers[0].Endpoint)
	if err != nil {
		r.fail("endpoint", "resolve %s: %v", cfg.Peers[0].Endpoint, err)
		return 1
	}
	r.ok("endpoint", "%s -> %s", cfg.Peers[0].Endpoint, ep)

	level := device.LogLevelError
	if *verbose {
		level = device.LogLevelVerbose
	}
	var bind conn.Bind = conn.NewDefaultBind()
	if *via != "" {
		vb, closeVia, err := startVia(*via, level)
		if err != nil {
			r.fail("via", "%v", err)
			return 1
		}
		defer closeVia()
		r.ok("via", "%s", vb.info)
		bind = vb.bind
	}

	tunDev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		fmt.Println("netstack:", err)
		return 1
	}
	dev := device.NewDevice(tunDev, bind, device.NewLogger(level, "awg: "))
	defer dev.Close()
	uapi, err := cfg.ClientUAPI()
	if err != nil {
		r.fail("config", "%v", err)
		return 1
	}
	if err := dev.IpcSet(uapi); err != nil {
		r.fail("config", "rejected by AmneziaWG: %v", err)
		return 1
	}
	if err := dev.Up(); err != nil {
		r.fail("device", "%v", err)
		return 1
	}

	// Handshake.
	start := time.Now()
	// The first packet after configuration is sent with stale S4 padding by
	// amneziawg-go; send a throwaway one so it is not a real request.
	if c, err := tnet.Dial("udp", net.JoinHostPort(dns[0].String(), "9")); err == nil {
		c.Write([]byte{0})
		c.Close()
	}
	hs := waitHandshake(dev, *timeout)
	if hs.IsZero() {
		r.fail("handshake", "no handshake within %v (wrong keys/params, server down or UDP blocked)", *timeout)
		return 1
	}
	r.ok("handshake", "in %v", time.Since(start).Round(time.Millisecond))
	time.Sleep(200 * time.Millisecond)

	// DNS through the tunnel.
	host := hostOf(*ipURL)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	st := time.Now()
	ips, err := tnet.LookupContextHost(ctx, host)
	cancel()
	if err != nil {
		r.fail("dns", "%s via %v: %v", host, dns, err)
	} else {
		r.ok("dns", "%s -> %s (%v, via %v)", host, strings.Join(ips, ", "), time.Since(st).Round(time.Millisecond), dns)
	}

	// Exit IP via tunnel vs direct.
	tunIP, err := fetch(tnet.DialContext, *ipURL)
	if err != nil {
		r.fail("http", "GET %s through tunnel: %v", *ipURL, err)
	} else {
		r.ok("http", "GET %s through tunnel works", *ipURL)
		direct, derr := fetch((&net.Dialer{}).DialContext, *ipURL)
		switch {
		case derr != nil:
			r.ok("exit-ip", "%s (direct IP unknown: %v)", tunIP, derr)
		case direct == tunIP && len(expTunnel)+len(expDirect) > 0:
			r.ok("exit-ip", "%s = direct IP (split routing: see the route checks below)", tunIP)
		case direct == tunIP:
			r.fail("exit-ip", "%s equals the direct IP: traffic is not leaving via the VPN", tunIP)
		default:
			r.ok("exit-ip", "%s (direct: %s)", tunIP, direct)
		}
	}

	// Split routing (Alatyr): compare the IP each service sees through the
	// tunnel with what it sees from this machine directly. Run the tester
	// on the relay machine (or one with the same internet exit).
	route := func(url string, wantTunnel bool) {
		got, err := fetch(tnet.DialContext, url)
		if err != nil {
			r.fail("route", "GET %s through tunnel: %v", url, err)
			return
		}
		direct, err := fetch((&net.Dialer{}).DialContext, url)
		if err != nil {
			r.fail("route", "GET %s directly: %v", url, err)
			return
		}
		viaVPN := got != direct
		switch {
		case viaVPN == wantTunnel && wantTunnel:
			r.ok("route", "%s goes through the VPN (%s, direct %s)", url, got, direct)
		case viaVPN == wantTunnel:
			r.ok("route", "%s goes directly (%s)", url, got)
		case wantTunnel:
			r.fail("route", "%s must go through the VPN but exits directly (%s)", url, got)
		default:
			r.fail("route", "%s must go directly but exits via the VPN (%s, direct %s)", url, got, direct)
		}
	}
	for _, u := range expTunnel {
		route(u, true)
	}
	for _, u := range expDirect {
		route(u, false)
	}

	// Ping.
	if *pings > 0 {
		ping(r, tnet, *pingHost, *pings)
	}

	// Download.
	if *downloadM > 0 {
		download(r, tnet, *downloadM)
	}

	rx, tx := counters(dev)
	fmt.Printf("\ntraffic: received %s, sent %s\n", human(rx), human(tx))
	if r.failed > 0 {
		fmt.Printf("RESULT: FAIL (%d check(s) failed)\n", r.failed)
		return 1
	}
	fmt.Println("RESULT: OK — the tunnel works")
	return 0
}

type viaTunnel struct {
	bind *tunnelBind
	info string
}

// startVia brings up the helper tunnel used as an outside vantage point.
func startVia(path string, level int) (*viaTunnel, func(), error) {
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, nil, fmt.Errorf("via config: %w", err)
	}
	var addr netip.Addr
	for _, a := range cfg.Interface.Addresses {
		if a.Addr().Is4() {
			addr = a.Addr()
		}
	}
	if !addr.IsValid() {
		return nil, nil, fmt.Errorf("via config has no IPv4 Address")
	}
	mtu := cfg.Interface.MTU
	if mtu == 0 {
		mtu = 1280
	}
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, mtu)
	if err != nil {
		return nil, nil, err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(level, "via: "))
	uapi, err := cfg.ClientUAPI()
	if err != nil {
		dev.Close()
		return nil, nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, nil, err
	}
	dev.Up()
	if c, err := tnet.Dial("udp", "1.1.1.1:9"); err == nil {
		c.Write([]byte{0})
		c.Close()
	}
	if waitHandshake(dev, *timeout).IsZero() {
		dev.Close()
		return nil, nil, fmt.Errorf("via tunnel %s: no handshake", cfg.Peers[0].Endpoint)
	}
	time.Sleep(200 * time.Millisecond)
	info := cfg.Peers[0].Endpoint
	if ip, err := fetch(tnet.DialContext, *ipURL); err == nil {
		info = fmt.Sprintf("probing from the internet via %s (outside IP %s)", cfg.Peers[0].Endpoint, ip)
	}
	return &viaTunnel{bind: &tunnelBind{tnet: tnet, laddr: addr}, info: info}, dev.Close, nil
}

func hostOf(u string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	return h
}

func fetch(dial func(context.Context, string, string) (net.Conn, error), url string) (string, error) {
	c := &http.Client{Timeout: *timeout, Transport: &http.Transport{DialContext: dial}}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("unexpected response %q", ip)
	}
	return ip, nil
}

func ping(r *result, tnet *netstack.Net, host string, n int) {
	target, err := netip.ParseAddr(host)
	if err != nil {
		r.fail("ping", "bad host %s", host)
		return
	}
	pc, err := tnet.DialPingAddr(netip.Addr{}, target)
	if err != nil {
		r.fail("ping", "%v", err)
		return
	}
	defer pc.Close()
	var total time.Duration
	got := 0
	for i := 0; i < n; i++ {
		pkt := []byte{8, 0, 0, 0, 0x13, 0x37, byte(i >> 8), byte(i), 'a', 'w', 'g'}
		pc.SetDeadline(time.Now().Add(2 * time.Second))
		st := time.Now()
		if _, err := pc.Write(pkt); err != nil {
			continue
		}
		buf := make([]byte, 1500)
		if _, err := pc.Read(buf); err == nil {
			total += time.Since(st)
			got++
		}
		time.Sleep(100 * time.Millisecond)
	}
	loss := float64(n-got) * 100 / float64(n)
	switch {
	case got == 0:
		r.fail("ping", "%s: no replies (%d sent)", host, n)
	case loss > 20:
		r.warn("ping", "%s: %d/%d replies, %.0f%% loss, avg %v", host, got, n, loss, (total / time.Duration(got)).Round(time.Millisecond))
	default:
		r.ok("ping", "%s: %d/%d replies, %.0f%% loss, avg %v", host, got, n, loss, (total / time.Duration(got)).Round(time.Millisecond))
	}
}

func download(r *result, tnet *netstack.Net, mb int) {
	url := "http://speed.cloudflare.com/__down?bytes=" + strconv.Itoa(mb*1000000)
	c := &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{DialContext: tnet.DialContext}}
	st := time.Now()
	resp, err := c.Get(url)
	if err != nil {
		r.fail("download", "%v", err)
		return
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	d := time.Since(st)
	if err != nil || n != int64(mb*1000000) {
		r.fail("download", "got %s of %d MB: %v", human(uint64(n)), mb, err)
		return
	}
	r.ok("download", "%d MB in %v = %.1f Mbit/s", mb, d.Round(time.Millisecond), float64(n*8)/d.Seconds()/1e6)
}

func waitHandshake(dev *device.Device, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if t := lastHandshake(dev); !t.IsZero() {
			return t
		}
		time.Sleep(100 * time.Millisecond)
	}
	return time.Time{}
}

func ipcValues(dev *device.Device, key string) []string {
	s, err := dev.IpcGet()
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && k == key {
			out = append(out, v)
		}
	}
	return out
}

func lastHandshake(dev *device.Device) time.Time {
	for _, v := range ipcValues(dev, "last_handshake_time_sec") {
		if sec, _ := strconv.ParseInt(v, 10, 64); sec > 0 {
			return time.Unix(sec, 0)
		}
	}
	return time.Time{}
}

func counters(dev *device.Device) (rx, tx uint64) {
	for _, v := range ipcValues(dev, "rx_bytes") {
		n, _ := strconv.ParseUint(v, 10, 64)
		rx += n
	}
	for _, v := range ipcValues(dev, "tx_bytes") {
		n, _ := strconv.ParseUint(v, 10, 64)
		tx += n
	}
	return
}

func human(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
