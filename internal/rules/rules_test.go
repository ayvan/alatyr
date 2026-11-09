package rules

import (
	"encoding/base64"
	"net/netip"
	"testing"
)

const abp = `[AutoProxy 0.2.9]
! comment
||google.com
.youtube.com
|https://www.example.net/path
@@||cn.google.com
/^(.*\.)?wikipedia\.org$/
twitter.com
example.org/some/path
*.wildcard.io
||ru
||cdn*.scmp.example
.ua
`

func TestABP(t *testing.T) {
	l := Parse(abp)
	cases := map[string]bool{
		"google.com": true, "www.google.com": true, "cn.google.com": false, "a.cn.google.com": false,
		"notgoogle.com": false, "youtube.com": true, "i.youtube.com": true, "www.example.net": true,
		"en.wikipedia.org": true, "twitter.com": true, "api.twitter.com": true, "example.org": true,
		"x.wildcard.io": true, "yandex.ru": true, "example.com": false,
		"cdn4.scmp.example": true, "a.cdn-x.scmp.example": true, "scmp.example": false, "kyiv.ua": true, "ua.com": false,
	}
	for h, want := range cases {
		if _, got := l.MatchDomain(h); got != want {
			t.Errorf("%s: got %v want %v", h, got, want)
		}
	}
}

func TestBase64(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(abp))
	var wrapped string
	for i := 0; i < len(enc); i += 64 {
		wrapped += enc[i:min(i+64, len(enc))] + "\n"
	}
	l := Parse(wrapped)
	if _, ok := l.MatchDomain("www.google.com"); !ok {
		t.Fatal("base64 list not decoded")
	}
}

func TestFormats(t *testing.T) {
	l := Parse(`# comment
domain:v2.example
full:only.example
keyword:tracker
regexp:^ads\d+\.
DOMAIN-SUFFIX,clash.example,PROXY
0.0.0.0 hosts.example
Пример.рф
149.154.160.0/20
91.108.4.0/22 # telegram
1.2.3.4
2001:b28:f23d::/48
`)
	for h, want := range map[string]bool{
		"a.v2.example": true, "only.example": true, "x.only.example": false, "mytracker.net": true,
		"ads12.foo": true, "clash.example": true, "hosts.example": true, "xn--e1afmkfd.xn--p1ai": true,
	} {
		if _, got := l.MatchDomain(h); got != want {
			t.Errorf("%s: got %v want %v", h, got, want)
		}
	}
	for ip, want := range map[string]bool{
		"149.154.167.50": true, "91.108.5.1": true, "91.108.8.1": false, "1.2.3.4": true, "1.2.3.5": false,
	} {
		r, got := l.MatchIP(netip.MustParseAddr(ip))
		if got != want {
			t.Errorf("%s: got %v (%s) want %v", ip, got, r, want)
		}
	}
	if l.Ignored != 1 { // the IPv6 subnet
		t.Errorf("ignored %d", l.Ignored)
	}
}

func TestMatcherPriority(t *testing.T) {
	sub := Parse("||example.com\n149.154.160.0/20\n")
	directSub := Parse("||example.com\n||yandex.ru\n")
	m := NewMatcher(Parse("mail.example.com"), Parse("yandex.ru"), []Source{
		{Name: "direct-list", Action: Direct, List: directSub},
		{Name: "sub", Action: Tunnel, List: sub},
	})
	check := func(h string, want Action, src string) {
		t.Helper()
		got := m.Domain(h)
		if got.Action != want || got.Source != src {
			t.Errorf("%s: got %+v want %v from %s", h, got, want, src)
		}
	}
	check("mail.example.com", Direct, SourceDirect)
	check("www.example.com", Tunnel, "sub") // tunnel subscription beats direct one
	check("music.yandex.ru", Tunnel, SourceTunnel)
	check("other.org", None, "")
	if r := m.IP(netip.MustParseAddr("149.154.167.50")); r.Action != Tunnel || r.Rule != "149.154.160.0/20" {
		t.Errorf("ip: %+v", r)
	}
}
