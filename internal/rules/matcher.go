package rules

import "net/netip"

// Source is a subscription list with the action its rules lead to.
type Source struct {
	Name   string
	Action Action
	List   *List
}

// Match is a matching result. Action is None when no rule matched.
type Match struct {
	Action Action `json:"action"`
	Rule   string `json:"rule,omitempty"`
	Source string `json:"source,omitempty"`
}

// Matcher combines the admin's own lists and subscriptions. Priority:
// own exclusions (direct) > own additions (tunnel) > subscriptions (a
// tunnel subscription wins over a direct one; a subscription's @@
// exceptions cancel its own rules) > no match.
type Matcher struct {
	direct, tunnel *List
	subs           []Source
}

// SourceDirect and SourceTunnel name the admin's own lists in Match.Source.
const (
	SourceDirect = "Мои исключения"
	SourceTunnel = "Мои дополнения"
)

// NewMatcher builds a matcher; nil lists are allowed.
func NewMatcher(direct, tunnel *List, subs []Source) *Matcher {
	if direct == nil {
		direct = Parse("")
	}
	if tunnel == nil {
		tunnel = Parse("")
	}
	return &Matcher{direct: direct, tunnel: tunnel, subs: subs}
}

// Domain matches a normalized host name.
func (m *Matcher) Domain(host string) Match {
	if r, ok := m.direct.MatchDomain(host); ok {
		return Match{Direct, r, SourceDirect}
	}
	if r, ok := m.tunnel.MatchDomain(host); ok {
		return Match{Tunnel, r, SourceTunnel}
	}
	return m.subMatch(func(l *List) (string, bool) { return l.MatchDomain(host) })
}

// IP matches an address against subnet rules.
func (m *Matcher) IP(ip netip.Addr) Match {
	if r, ok := m.direct.MatchIP(ip); ok {
		return Match{Direct, r, SourceDirect}
	}
	if r, ok := m.tunnel.MatchIP(ip); ok {
		return Match{Tunnel, r, SourceTunnel}
	}
	return m.subMatch(func(l *List) (string, bool) { return l.MatchIP(ip) })
}

func (m *Matcher) subMatch(f func(*List) (string, bool)) Match {
	var direct Match
	for _, s := range m.subs {
		r, ok := f(s.List)
		if !ok {
			continue
		}
		if s.Action == Tunnel {
			return Match{Tunnel, r, s.Name}
		}
		if direct.Action == None {
			direct = Match{s.Action, r, s.Name}
		}
	}
	return direct
}
