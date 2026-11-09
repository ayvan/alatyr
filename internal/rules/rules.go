// Package rules parses domain/subnet lists (ABP/gfwlist, plain domain lists,
// v2ray/clash style entries, hosts files, CIDR lists) and matches hosts and
// IP addresses against them.
package rules

import (
	"bufio"
	"encoding/base64"
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

// Action is a routing decision.
type Action uint8

const (
	None Action = iota
	Direct
	Tunnel
	Block
)

func (a Action) String() string {
	switch a {
	case Direct:
		return "direct"
	case Tunnel:
		return "tunnel"
	case Block:
		return "block"
	}
	return "none"
}

// ParseAction parses "direct" / "tunnel".
func ParseAction(s string) Action {
	switch s {
	case "direct":
		return Direct
	case "tunnel":
		return Tunnel
	}
	return None
}

// set holds one kind of rules (either positive or exceptions).
type set struct {
	suffix   map[string]struct{} // domain and all its subdomains
	exact    map[string]struct{} // this host only
	keywords []string            // substring of the host
	regex    []*regexp.Regexp    // matched against the host
	nets     prefixSet
}

func newSet() set {
	return set{suffix: map[string]struct{}{}, exact: map[string]struct{}{}}
}

func (s *set) size() int {
	return len(s.suffix) + len(s.exact) + len(s.keywords) + len(s.regex) + s.nets.n
}

// domain returns a description of the matching rule.
func (s *set) domain(host string) (string, bool) {
	if _, ok := s.exact[host]; ok {
		return "full:" + host, true
	}
	for h := host; ; {
		if _, ok := s.suffix[h]; ok {
			return h, true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	for _, k := range s.keywords {
		if strings.Contains(host, k) {
			return "keyword:" + k, true
		}
	}
	for _, re := range s.regex {
		if re.MatchString(host) {
			return "/" + re.String() + "/", true
		}
	}
	return "", false
}

// List is a parsed rule list.
type List struct {
	inc, exc set
	// Ignored counts lines that were not understood (URL path patterns,
	// IPv6 subnets, wildcards in the middle...).
	Ignored int
}

// Size returns the number of usable rules.
func (l *List) Size() int { return l.inc.size() + l.exc.size() }

// Domains reports whether the list has domain rules (subnet-only lists
// don't need DNS or sniffing).
func (l *List) Domains() bool {
	return l.inc.size()-l.inc.nets.n+l.exc.size()-l.exc.nets.n > 0
}

// MatchDomain matches a normalized host name. Exceptions (@@) of the list
// cancel its own rules.
func (l *List) MatchDomain(host string) (string, bool) {
	r, ok := l.inc.domain(host)
	if !ok {
		return "", false
	}
	if _, ex := l.exc.domain(host); ex {
		return "", false
	}
	return r, true
}

// MatchIP matches an address against the list's subnets.
func (l *List) MatchIP(ip netip.Addr) (string, bool) {
	p, ok := l.inc.nets.match(ip)
	if !ok {
		return "", false
	}
	if _, ex := l.exc.nets.match(ip); ex {
		return "", false
	}
	return p.String(), true
}

// Parse reads a list in any supported format. Base64-encoded lists
// (gfwlist) are decoded automatically.
func Parse(text string) *List {
	text = maybeBase64(text)
	l := &List{inc: newSet(), exc: newSet()}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l.addLine(sc.Text())
	}
	return l
}

// maybeBase64 decodes base64-wrapped lists (gfwlist) and returns other
// text unchanged.
func maybeBase64(text string) string {
	compact := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\n' || c == '\r' || c == ' ' || c == '\t':
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
			compact = append(compact, c)
		default:
			return text // '.', '#', '|' ... never appear in base64
		}
	}
	if len(compact) < 16 {
		return text
	}
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(string(compact), "="))
	if err != nil {
		return text
	}
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	if printable*100 < len(b)*95 {
		return text
	}
	return string(b)
}

func (l *List) addLine(line string) {
	line = strings.Trim(strings.TrimSpace(line), "\"'")
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" || line[0] == '!' || line[0] == '#' || line[0] == '[' || strings.HasPrefix(line, "//") {
		return
	}
	dst := &l.inc
	if strings.HasPrefix(line, "@@") {
		dst = &l.exc
		line = line[2:]
	}
	if !dst.add(line) {
		l.Ignored++
	}
}

var clashKinds = map[string]string{
	"domain-suffix": "domain", "domain": "full", "domain-keyword": "keyword",
	"ip-cidr": "ip", "ip-cidr6": "ip", "host-suffix": "domain", "host": "full", "host-keyword": "keyword",
}

// add parses a single rule; false means it was not understood.
func (s *set) add(r string) bool {
	// clash / surge: DOMAIN-SUFFIX,example.com[,policy]
	if i := strings.IndexByte(r, ','); i > 0 {
		if kind, ok := clashKinds[strings.ToLower(r[:i])]; ok {
			v := r[i+1:]
			if j := strings.IndexByte(v, ','); j >= 0 {
				v = v[:j]
			}
			r = kind + ":" + strings.TrimSpace(v)
		}
	}
	// v2ray geosite style: domain:, full:, keyword:, regexp:
	if i := strings.IndexByte(r, ':'); i > 0 && !strings.Contains(r[:i], "/") {
		kind, v := strings.ToLower(r[:i]), strings.TrimSpace(r[i+1:])
		switch kind {
		case "domain":
			return s.addSuffix(v)
		case "full":
			if h, ok := normHost(v); ok {
				s.exact[h] = struct{}{}
				return true
			}
			return false
		case "keyword":
			if v = strings.ToLower(v); v != "" {
				s.keywords = append(s.keywords, v)
				return true
			}
			return false
		case "regexp":
			return s.addRegex(v)
		case "ip":
			return s.addNet(v)
		}
	}
	switch {
	case strings.HasPrefix(r, "||"):
		return s.addSuffix(cutHost(r[2:]))
	case strings.HasPrefix(r, "|http://"), strings.HasPrefix(r, "|https://"):
		r = r[strings.Index(r, "//")+2:]
		return s.addSuffix(cutHost(r))
	case len(r) > 2 && r[0] == '/' && r[len(r)-1] == '/':
		return s.addRegex(r[1 : len(r)-1])
	}
	// hosts file: "0.0.0.0 example.com"
	if f := strings.Fields(r); len(f) == 2 {
		if _, err := netip.ParseAddr(f[0]); err == nil {
			return s.addSuffix(f[1])
		}
	}
	if strings.ContainsAny(r, " \t") {
		return false
	}
	if s.addNet(r) {
		return true
	}
	if strings.ContainsAny(r, ":") { // IPv6 address / range
		return false
	}
	// "example.com", ".example.com", "*.example.com", ".ua" (whole zone),
	// ABP "example.com/path"
	zone := strings.HasPrefix(r, ".") || strings.HasPrefix(r, "*.")
	host := cutHost(strings.TrimPrefix(strings.TrimPrefix(r, "*"), "."))
	if !zone && !strings.Contains(host, ".") {
		return false
	}
	return s.addSuffix(host)
}

// cutHost strips everything after the host part of an ABP pattern.
func cutHost(r string) string {
	if i := strings.IndexAny(r, "^/:?|"); i >= 0 {
		r = r[:i]
	}
	return r
}

func (s *set) addSuffix(v string) bool {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "*"), ".")
	if strings.Contains(v, "*") {
		return s.addWildcard(v)
	}
	h, ok := normHost(v)
	if !ok {
		return false
	}
	s.suffix[h] = struct{}{}
	return true
}

// addWildcard handles "cdn*.example.com": the domain and its subdomains,
// '*' matching any part of a name.
func (s *set) addWildcard(v string) bool {
	parts := strings.Split(strings.ToLower(v), "*")
	for i, p := range parts {
		if _, ok := normHost(strings.Trim(p, ".-")); p != "" && strings.Trim(p, ".-") != "" && !ok {
			return false
		}
		parts[i] = regexp.QuoteMeta(p)
	}
	return s.addRegex(`(^|\.)` + strings.Join(parts, `[a-z0-9.-]*`) + `$`)
}

func (s *set) addRegex(v string) bool {
	re, err := regexp.Compile(v)
	if err != nil { // e.g. lookaheads unsupported by RE2
		return false
	}
	s.regex = append(s.regex, re)
	return true
}

func (s *set) addNet(v string) bool {
	if p, err := netip.ParsePrefix(v); err == nil {
		if !p.Addr().Is4() {
			return false
		}
		s.nets.add(p.Masked())
		return true
	}
	if a, err := netip.ParseAddr(v); err == nil {
		a = a.Unmap()
		if !a.Is4() {
			return false
		}
		s.nets.add(netip.PrefixFrom(a, 32))
		return true
	}
	return false
}

// NormHost lowercases a host name, strips the trailing dot and converts
// IDN to punycode. ok is false for things that are not host names.
func NormHost(h string) (string, bool) { return normHost(h) }

func normHost(h string) (string, bool) {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || len(h) > 253 {
		return "", false
	}
	ascii := true
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		case c >= 0x80:
			ascii = false
		default:
			return "", false
		}
	}
	if !ascii {
		p, err := idna.Lookup.ToASCII(h)
		if err != nil {
			return "", false
		}
		h = p
	}
	if strings.HasPrefix(h, ".") || strings.Contains(h, "..") {
		return "", false
	}
	return h, true
}

// prefixSet is a set of IPv4 prefixes grouped by length.
type prefixSet struct {
	byLen [33]map[uint32]struct{}
	lens  []int // lengths in use, longest first
	n     int
}

func (p *prefixSet) add(pr netip.Prefix) {
	bits := pr.Bits()
	m := p.byLen[bits]
	if m == nil {
		m = map[uint32]struct{}{}
		p.byLen[bits] = m
		i := 0
		for i < len(p.lens) && p.lens[i] > bits {
			i++
		}
		p.lens = append(p.lens[:i], append([]int{bits}, p.lens[i:]...)...)
	}
	k := u32(pr.Addr())
	if _, dup := m[k]; !dup {
		m[k] = struct{}{}
		p.n++
	}
}

func (p *prefixSet) match(ip netip.Addr) (netip.Prefix, bool) {
	ip = ip.Unmap()
	if !ip.Is4() || p.n == 0 {
		return netip.Prefix{}, false
	}
	v := u32(ip)
	for _, bits := range p.lens {
		var mask uint32
		if bits > 0 {
			mask = ^uint32(0) << (32 - bits)
		}
		if _, ok := p.byLen[bits][v&mask]; ok {
			pr, _ := ip.Prefix(bits)
			return pr, true
		}
	}
	return netip.Prefix{}, false
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// MarshalText makes actions readable in JSON.
func (a Action) MarshalText() ([]byte, error) { return []byte(a.String()), nil }
