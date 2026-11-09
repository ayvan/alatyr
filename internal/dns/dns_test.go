package dns

import (
	"context"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"alatyr/internal/rules"
)

// fakeEx answers every A query with a fixed address and records use.
type fakeEx struct {
	ip    [4]byte
	calls int
}

func (f *fakeEx) Exchange(_ context.Context, _ netip.AddrPort, q []byte) ([]byte, error) {
	f.calls++
	var p dnsmessage.Parser
	h, _ := p.Start(q)
	qs, _ := p.AllQuestions()
	return reply(h, qs, dnsmessage.RCodeSuccess, []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: qs[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.AResource{A: f.ip},
	}}), nil
}

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	q, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func answer(t *testing.T, raw []byte) (dnsmessage.RCode, []netip.Addr) {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	if m.ID != 0x1234 || !m.Response {
		t.Fatalf("bad header %+v", m.Header)
	}
	var ips []netip.Addr
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			ips = append(ips, netip.AddrFrom4(r.A))
		}
	}
	return m.RCode, ips
}

func TestRouting(t *testing.T) {
	tun, dir := &fakeEx{ip: [4]byte{1, 1, 1, 1}}, &fakeEx{ip: [4]byte{2, 2, 2, 2}}
	srv := New(tun, dir, Config{
		Route: func(name string) rules.Action {
			if name == "blocked.example" {
				return rules.Tunnel
			}
			return rules.Direct
		},
		TunnelServers: []netip.AddrPort{netip.MustParseAddrPort("9.9.9.9:53")},
		DirectServers: []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:53")},
		Blocked:       func(name string) bool { return name == "use-application-dns.net" },
	})
	ctx := context.Background()

	if rc, ips := answer(t, srv.Handle(ctx, query(t, "Blocked.Example.", dnsmessage.TypeA))); rc != dnsmessage.RCodeSuccess || len(ips) != 1 || ips[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("tunnel name: %v %v", rc, ips)
	}
	if rc, ips := answer(t, srv.Handle(ctx, query(t, "other.example.", dnsmessage.TypeA))); rc != dnsmessage.RCodeSuccess || ips[0] != netip.MustParseAddr("2.2.2.2") {
		t.Fatalf("direct name: %v %v", rc, ips)
	}
	if tun.calls != 1 || dir.calls != 1 {
		t.Fatalf("calls tunnel=%d direct=%d", tun.calls, dir.calls)
	}
	// AAAA and HTTPS are answered empty without asking upstream.
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeAAAA, typeHTTPS} {
		if rc, ips := answer(t, srv.Handle(ctx, query(t, "blocked.example.", typ))); rc != dnsmessage.RCodeSuccess || len(ips) != 0 {
			t.Fatalf("type %v: %v %v", typ, rc, ips)
		}
	}
	if tun.calls != 1 {
		t.Fatal("AAAA/HTTPS must not be forwarded")
	}
	if rc, _ := answer(t, srv.Handle(ctx, query(t, "use-application-dns.net.", dnsmessage.TypeA))); rc != dnsmessage.RCodeNameError {
		t.Fatalf("canary: %v", rc)
	}
	// Answers are remembered for routing by IP.
	if n := srv.Cache.Names(netip.MustParseAddr("1.1.1.1")); len(n) != 1 || n[0] != "blocked.example" {
		t.Fatalf("cache: %v", n)
	}
	if srv.Handle(ctx, []byte{1, 2, 3}) != nil {
		t.Fatal("garbage must be ignored")
	}
}

func TestIsLocal(t *testing.T) {
	for name, want := range map[string]bool{
		"router": true, "nas.lan": true, "printer.local": true, "example.com": false,
		"1.1.168.192.in-addr.arpa": true, "8.8.8.8.in-addr.arpa": false,
	} {
		if got := isLocal(name, dnsmessage.TypePTR); got != want {
			t.Errorf("%s: got %v", name, got)
		}
	}
}
