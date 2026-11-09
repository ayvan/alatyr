package awgconf

import (
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

const sample = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.126.57.123/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280
Jc = 9
Jmin = 30
Jmax = 90
S1 = 110
S2 = 120
S3 = 47
S4 = 23
H1 = 7291435-486117520
H2 = 602843917-1157629843
H3 = 1249871566-1680354947
H4 = 1781926002-2106438100
I1 = <b 0x0003><r 2><b 0x2112A442><r 12><r 20>

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
Endpoint = 127.0.0.1:51820
`

func newDev(t *testing.T) *device.Device {
	d := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(d.Close)
	return d
}

func TestParseRoundTrip(t *testing.T) {
	c, err := Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	if c.Interface.MTU != 1280 || c.Interface.Params["H4"] != "1781926002-2106438100" || len(c.Peers[0].AllowedIPs) != 2 {
		t.Fatalf("unexpected parse result: %+v", c)
	}
	c2, err := Parse(c.Render())
	if err != nil {
		t.Fatal(err)
	}
	if c2.Render() != c.Render() {
		t.Fatalf("render not stable")
	}
	uapi, err := c.ClientUAPI()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uapi, "s4=23\n") || !strings.Contains(uapi, "endpoint=127.0.0.1:51820\n") {
		t.Fatalf("bad uapi:\n%s", uapi)
	}
	if err := newDev(t).IpcSet(uapi); err != nil {
		t.Fatalf("device rejected config: %v", err)
	}
}

func TestGeneratedProfilesAccepted(t *testing.T) {
	for _, proto := range Protocols {
		for i := 0; i < 50; i++ {
			p, err := GenerateParams(proto)
			if err != nil {
				t.Fatal(err)
			}
			for _, params := range []map[string]string{p, ServerParams(p)} {
				u, err := ParamsUAPI(params)
				if err != nil {
					t.Fatal(err)
				}
				if err := newDev(t).IpcSet(u); err != nil {
					t.Fatalf("%s: device rejected %v: %v", proto, params, err)
				}
			}
		}
	}
}

func TestAmneziaURL(t *testing.T) {
	if u := AmneziaURL("[Interface]\n"); !strings.HasPrefix(u, "vpn://AAAADH") {
		t.Fatalf("unexpected %s", u)
	}
}

func TestAmneziaURLRoundTrip(t *testing.T) {
	got, err := DecodeAmneziaURL(AmneziaURL(sample))
	if err != nil || got != strings.TrimSpace(sample) {
		t.Fatalf("round trip failed: %v", err)
	}
	c, _ := Parse(sample)
	if v := c.Version(); v != "AmneziaWG 2.0" {
		t.Fatalf("version %s", v)
	}
}
