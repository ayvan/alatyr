package router

import (
	"net/netip"

	"alatyr/internal/rules"
)

// Well-known DoH/DoT resolvers. With "block DoH" on, browsers fail to use
// them and fall back to the system DNS, i.e. ours. use-application-dns.net
// is Firefox's canary: NXDOMAIN there disables its automatic DoH.
var dohList = rules.Parse(`
dns.google
dns.google.com
cloudflare-dns.com
one.one.one.one
dns.quad9.net
dns9.quad9.net
dns10.quad9.net
dns11.quad9.net
doh.opendns.com
dns.adguard.com
dns.adguard-dns.com
unfiltered.adguard-dns.com
family.adguard-dns.com
doh.dns.sb
dns.nextdns.io
doh.cleanbrowsing.org
dns.alidns.com
doh.pub
doh.mullvad.net
dns.mullvad.net
dns.controld.com
freedns.controld.com
common.dot.dns.yandex.net
safe.dot.dns.yandex.net
doh.libredns.gr
dns.twnic.tw
use-application-dns.net
`)

func dohHost(host string) bool {
	_, ok := dohList.MatchDomain(host)
	return ok
}

var dohIPs = func() map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	for _, s := range []string{
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
		"9.9.9.9", "149.112.112.112", "9.9.9.10", "9.9.9.11", "208.67.222.222", "208.67.220.220",
		"94.140.14.14", "94.140.15.15", "94.140.14.140", "76.76.2.0", "76.76.10.0", "185.228.168.9",
		"77.88.8.8", "77.88.8.1", "223.5.5.5", "223.6.6.6", "194.242.2.2",
	} {
		m[netip.MustParseAddr(s)] = true
	}
	return m
}()
