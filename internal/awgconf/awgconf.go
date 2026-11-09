// Package awgconf parses and renders AmneziaWG (wg-quick style) configuration
// files and converts them into the UAPI format understood by amneziawg-go.
//
// Supported Interface keys cover AmneziaWG 1.0, 1.5, 2.0 and 3.x:
// Jc, Jmin, Jmax, S1-S4, H1-H4, I1-I5, HeaderProtectionKey,
// ContentPaddingAddition, RekeyAfterTime, RekeyTimeout, RejectAfterTime,
// KeepaliveTimeout, MaxHandshakeAttempts, RandomTrailers, DisableCookies.
package awgconf

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ParamOrder is the canonical order of AmneziaWG obfuscation parameters.
var ParamOrder = []string{
	"Jc", "Jmin", "Jmax",
	"S1", "S2", "S3", "S4",
	"H1", "H2", "H3", "H4",
	"I1", "I2", "I3", "I4", "I5",
	"HeaderProtectionKey", "ContentPaddingAddition",
	"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
	"RandomTrailers", "DisableCookies",
}

// paramKind describes how a config value is converted to UAPI.
type paramKind int

const (
	kindPlain paramKind = iota // passed as is
	kindKey                    // base64 key -> hex
	kindBool                   // on/off -> true/false
)

type paramSpec struct {
	uapi string
	kind paramKind
}

var paramSpecs = map[string]paramSpec{
	"jc": {"jc", kindPlain}, "jmin": {"jmin", kindPlain}, "jmax": {"jmax", kindPlain},
	"s1": {"s1", kindPlain}, "s2": {"s2", kindPlain}, "s3": {"s3", kindPlain}, "s4": {"s4", kindPlain},
	"h1": {"h1", kindPlain}, "h2": {"h2", kindPlain}, "h3": {"h3", kindPlain}, "h4": {"h4", kindPlain},
	"i1": {"i1", kindPlain}, "i2": {"i2", kindPlain}, "i3": {"i3", kindPlain}, "i4": {"i4", kindPlain}, "i5": {"i5", kindPlain},
	"headerprotectionkey":    {"header_protection_key", kindKey},
	"contentpaddingaddition": {"content_padding_addition", kindPlain},
	"rekeyaftertime":         {"rekey_after_time", kindPlain},
	"rekeytimeout":           {"rekey_timeout", kindPlain},
	"rejectaftertime":        {"reject_after_time", kindPlain},
	"keepalivetimeout":       {"keepalive_timeout", kindPlain},
	"maxhandshakeattempts":   {"max_handshake_attempts", kindPlain},
	"randomtrailers":         {"random_trailers", kindBool},
	"disablecookies":         {"disable_cookies", kindBool},
}

// canonicalParam returns the canonical spelling of an AWG parameter name.
func canonicalParam(key string) (string, bool) {
	lk := strings.ToLower(key)
	if _, ok := paramSpecs[lk]; !ok {
		return "", false
	}
	for _, k := range ParamOrder {
		if strings.ToLower(k) == lk {
			return k, true
		}
	}
	return "", false
}

// Interface is the [Interface] section.
type Interface struct {
	PrivateKey string
	Addresses  []netip.Prefix
	DNS        []string
	MTU        int
	ListenPort int
	// Params holds AmneziaWG obfuscation parameters keyed by canonical name.
	Params map[string]string
}

// Peer is a [Peer] section.
type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive string
}

// Config is a complete AmneziaWG configuration.
type Config struct {
	Interface Interface
	Peers     []Peer
	// Warnings collects ignored/unknown keys.
	Warnings []string
}

// Parse parses wg-quick style configuration text.
func Parse(text string) (*Config, error) {
	cfg := &Config{Interface: Interface{Params: map[string]string{}}}
	section := ""
	var peer *Peer
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\uFEFF"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
			case "peer":
				cfg.Peers = append(cfg.Peers, Peer{})
				peer = &cfg.Peers[len(cfg.Peers)-1]
			default:
				return nil, fmt.Errorf("line %d: unknown section [%s]", lineNo, section)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		lk := strings.ToLower(key)
		switch section {
		case "interface":
			switch lk {
			case "privatekey":
				cfg.Interface.PrivateKey = value
			case "address":
				for _, a := range splitList(value) {
					p, err := parsePrefix(a)
					if err != nil {
						return nil, fmt.Errorf("line %d: bad Address %q: %v", lineNo, a, err)
					}
					cfg.Interface.Addresses = append(cfg.Interface.Addresses, p)
				}
			case "dns":
				cfg.Interface.DNS = append(cfg.Interface.DNS, splitList(value)...)
			case "mtu":
				n, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("line %d: bad MTU: %v", lineNo, err)
				}
				cfg.Interface.MTU = n
			case "listenport":
				n, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("line %d: bad ListenPort: %v", lineNo, err)
				}
				cfg.Interface.ListenPort = n
			case "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark":
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("ignored Interface key %s", key))
			default:
				if name, ok := canonicalParam(key); ok {
					cfg.Interface.Params[name] = value
				} else {
					cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("unknown Interface key %s ignored", key))
				}
			}
		case "peer":
			switch lk {
			case "publickey":
				peer.PublicKey = value
			case "presharedkey":
				peer.PresharedKey = value
			case "endpoint":
				peer.Endpoint = value
			case "allowedips":
				for _, a := range splitList(value) {
					p, err := parsePrefix(a)
					if err != nil {
						return nil, fmt.Errorf("line %d: bad AllowedIPs %q: %v", lineNo, a, err)
					}
					peer.AllowedIPs = append(peer.AllowedIPs, p)
				}
			case "persistentkeepalive":
				peer.PersistentKeepalive = value
			default:
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("unknown Peer key %s ignored", key))
			}
		default:
			return nil, fmt.Errorf("line %d: key outside of section", lineNo)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cfg.Interface.PrivateKey == "" {
		return nil, fmt.Errorf("missing Interface PrivateKey")
	}
	return cfg, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// KeyToHex converts a base64 WireGuard key to hex as required by UAPI.
func KeyToHex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("invalid key: %v", err)
	}
	if len(b) != 32 {
		return "", fmt.Errorf("invalid key length %d", len(b))
	}
	return hex.EncodeToString(b), nil
}

func boolToUAPI(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "yes":
		return "true", nil
	case "off", "false", "0", "no", "":
		return "false", nil
	}
	return "", fmt.Errorf("invalid boolean %q", v)
}

// ParamsUAPI renders AWG parameters as UAPI lines.
func ParamsUAPI(params map[string]string) (string, error) {
	var b strings.Builder
	for _, name := range ParamOrder {
		v, ok := params[name]
		if !ok || v == "" {
			continue
		}
		spec := paramSpecs[strings.ToLower(name)]
		switch spec.kind {
		case kindKey:
			h, err := KeyToHex(v)
			if err != nil {
				return "", fmt.Errorf("%s: %v", name, err)
			}
			v = h
		case kindBool:
			bv, err := boolToUAPI(v)
			if err != nil {
				return "", fmt.Errorf("%s: %v", name, err)
			}
			v = bv
		}
		fmt.Fprintf(&b, "%s=%s\n", spec.uapi, v)
	}
	return b.String(), nil
}

// ResolveEndpoint resolves host:port to ip:port suitable for UAPI.
func ResolveEndpoint(ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", err
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a, mustPort(port)).String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	// Prefer IPv4: it is the most widely reachable.
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			a, _ := netip.AddrFromSlice(v4)
			return netip.AddrPortFrom(a, mustPort(port)).String(), nil
		}
	}
	if len(ips) > 0 {
		a, _ := netip.AddrFromSlice(ips[0])
		return netip.AddrPortFrom(a, mustPort(port)).String(), nil
	}
	return "", fmt.Errorf("no addresses for %s", host)
}

func mustPort(p string) uint16 {
	n, _ := strconv.ParseUint(p, 10, 16)
	return uint16(n)
}

// ClientUAPI builds a full UAPI "set" body for a client-side config (one or
// more peers with endpoints). Endpoints are resolved via ResolveEndpoint.
func (c *Config) ClientUAPI() (string, error) {
	var b strings.Builder
	pk, err := KeyToHex(c.Interface.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("PrivateKey: %v", err)
	}
	fmt.Fprintf(&b, "private_key=%s\n", pk)
	if c.Interface.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.Interface.ListenPort)
	}
	params, err := ParamsUAPI(c.Interface.Params)
	if err != nil {
		return "", err
	}
	b.WriteString(params)
	b.WriteString("replace_peers=true\n")
	for i, p := range c.Peers {
		s, err := p.UAPI()
		if err != nil {
			return "", fmt.Errorf("peer %d: %v", i+1, err)
		}
		b.WriteString(s)
	}
	return b.String(), nil
}

// UAPI renders a peer as UAPI lines, resolving its endpoint.
func (p *Peer) UAPI() (string, error) {
	var b strings.Builder
	pub, err := KeyToHex(p.PublicKey)
	if err != nil {
		return "", fmt.Errorf("PublicKey: %v", err)
	}
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if p.PresharedKey != "" {
		psk, err := KeyToHex(p.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("PresharedKey: %v", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	if p.Endpoint != "" {
		ep, err := ResolveEndpoint(p.Endpoint)
		if err != nil {
			return "", fmt.Errorf("endpoint %s: %v", p.Endpoint, err)
		}
		fmt.Fprintf(&b, "endpoint=%s\n", ep)
	}
	if p.PersistentKeepalive != "" && p.PersistentKeepalive != "0" && !strings.EqualFold(p.PersistentKeepalive, "off") {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", p.PersistentKeepalive)
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, a := range p.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
	}
	return b.String(), nil
}

// Render produces wg-quick style text.
func (c *Config) Render() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.Interface.PrivateKey)
	if len(c.Interface.Addresses) > 0 {
		var as []string
		for _, a := range c.Interface.Addresses {
			as = append(as, a.String())
		}
		fmt.Fprintf(&b, "Address = %s\n", strings.Join(as, ", "))
	}
	if len(c.Interface.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(c.Interface.DNS, ", "))
	}
	if c.Interface.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.Interface.MTU)
	}
	if c.Interface.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", c.Interface.ListenPort)
	}
	for _, name := range ParamOrder {
		if v, ok := c.Interface.Params[name]; ok && v != "" {
			fmt.Fprintf(&b, "%s = %s\n", name, v)
		}
	}
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if len(p.AllowedIPs) > 0 {
			var as []string
			for _, a := range p.AllowedIPs {
				as = append(as, a.String())
			}
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(as, ", "))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.PersistentKeepalive != "" {
			fmt.Fprintf(&b, "PersistentKeepalive = %s\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}
