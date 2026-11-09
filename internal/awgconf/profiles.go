package awgconf

import (
	"fmt"
	"math/rand/v2"
	"strconv"
)

// Protocol identifiers for relay listeners.
const (
	ProtoAWG1 = "awg1" // AmneziaWG 1.0
	ProtoAWG2 = "awg2" // AmneziaWG 2.0
	ProtoAWG3 = "awg3" // AmneziaWG 3.1
)

// Protocols lists supported inbound protocols in display order.
var Protocols = []string{ProtoAWG1, ProtoAWG2, ProtoAWG3}

// ProtocolTitle returns a human readable protocol name.
func ProtocolTitle(p string) string {
	switch p {
	case ProtoAWG1:
		return "AmneziaWG 1.0"
	case ProtoAWG2:
		return "AmneziaWG 2.0"
	case ProtoAWG3:
		return "AmneziaWG 3.1"
	}
	return p
}

// ClientOnlyParams are parameters that only matter on the initiating side.
var ClientOnlyParams = map[string]bool{"I1": true, "I2": true, "I3": true, "I4": true, "I5": true}

func rnd(lo, hi int) int { return lo + rand.IntN(hi-lo+1) }

func itoa(n int) string { return strconv.Itoa(n) }

// GenerateParams creates a fresh random obfuscation profile for a protocol.
func GenerateParams(proto string) (map[string]string, error) {
	p := map[string]string{}
	jmin := rnd(20, 60)
	p["Jc"] = itoa(rnd(4, 8))
	p["Jmin"] = itoa(jmin)
	p["Jmax"] = itoa(jmin + rnd(30, 200))

	s1 := rnd(15, 150)
	s2 := rnd(15, 150)
	// Initiation (148) + S1 must differ from response (92) + S2.
	for s1+56 == s2 {
		s2 = rnd(15, 150)
	}
	p["S1"] = itoa(s1)
	p["S2"] = itoa(s2)

	switch proto {
	case ProtoAWG1:
		for k, h := range distinctHeaders() {
			p[k] = strconv.FormatUint(uint64(h), 10)
		}
	case ProtoAWG2:
		p["S3"] = itoa(rnd(15, 60))
		p["S4"] = itoa(rnd(12, 32))
		// Four narrow non-overlapping header ranges, one per quarter of the
		// space. The receiver tells handshake packets from transport ones by
		// size and header range; wide ranges would let random transport
		// bytes look like a handshake header (~width/2^32 chance).
		const lo, hi = 5, 2147483647
		zone := (hi - lo) / 4
		order := rand.Perm(4)
		for i, k := range []string{"H1", "H2", "H3", "H4"} {
			width := rnd(1<<16, 1<<22)
			start := lo + order[i]*zone + rnd(0, zone-width-1)
			p[k] = fmt.Sprintf("%d-%d", start, start+width)
		}
		// STUN-looking signature packet sent by the client before handshakes.
		p["I1"] = fmt.Sprintf("<b 0x0001><r 2><b 0x2112A442><r 12><r %d>", rnd(12, 32))
	case ProtoAWG3:
		// Mirrors the AmneziaVPN 3.1 server profile: headers are encrypted
		// by HeaderProtectionKey, so H1-H4 are single values (random trailers
		// make every long packet a handshake candidate, ranges would cause
		// misclassification). Header protection needs S1-S4 >= 12.
		p["Jmin"] = itoa(rnd(10, 20))
		p["Jmax"] = itoa(rnd(40, 80))
		p["S1"] = itoa(rnd(12, 40))
		p["S2"] = itoa(rnd(12, 40))
		p["S3"] = itoa(rnd(12, 40))
		p["S4"] = itoa(rnd(12, 24))
		for k, h := range distinctHeaders() {
			p[k] = strconv.FormatUint(uint64(h), 10)
		}
		p["I1"] = fmt.Sprintf("<b 0x0001><r 2><b 0x2112A442><r 12><r %d>", rnd(12, 32))
		key, err := GenerateSymmetricKey()
		if err != nil {
			return nil, err
		}
		p["HeaderProtectionKey"] = key
		p["RekeyAfterTime"] = "100-120"
		p["RekeyTimeout"] = "3-7"
		p["RejectAfterTime"] = "150-180"
		p["KeepaliveTimeout"] = "5-15"
		p["MaxHandshakeAttempts"] = "15-20"
		p["RandomTrailers"] = "on"
		p["DisableCookies"] = "on"
	default:
		return nil, fmt.Errorf("unknown protocol %q", proto)
	}
	return p, nil
}

func distinctHeaders() map[string]uint32 {
	out := map[string]uint32{}
	used := map[uint32]bool{}
	for _, k := range []string{"H1", "H2", "H3", "H4"} {
		var h uint32
		for h < 5 || used[h] {
			h = uint32(rnd(5, 2147483647))
		}
		used[h] = true
		out[k] = h
	}
	return out
}

// ServerParams returns the subset of params used by the listening side.
func ServerParams(p map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range p {
		if !ClientOnlyParams[k] {
			out[k] = v
		}
	}
	return out
}
