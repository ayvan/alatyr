package store

import (
	"crypto/rand"
	"encoding/hex"
)

// Routing modes.
const (
	// ModeLists: rule lists go to the tunnel, everything else direct.
	ModeLists = "lists"
	// ModeExcept: everything goes to the tunnel except direct rules.
	ModeExcept = "except"
	// ModeFull: everything goes to the tunnel (packet NAT, no routing).
	ModeFull = "full"
)

// QUIC blocking policies.
const (
	QUICAllow   = "allow"
	QUICUnknown = "unknown" // block when the site name cannot be read
	QUICBlock   = "block"
)

// Subscription is a downloadable rule list.
type Subscription struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	// Action for matching hosts: "tunnel" or "direct".
	Action string `json:"action"`
	// Via: download "tunnel" (through the VPN) or "direct".
	Via string `json:"via"`
	// Note is a hint shown in the UI (presets).
	Note string `json:"note,omitempty"`
}

// Routing are the split routing settings, all editable in the web UI.
type Routing struct {
	Mode          string         `json:"mode"`
	Subscriptions []Subscription `json:"subscriptions"`
	// Tunnel ("my additions") and Direct ("my exclusions") are free-form
	// rule lists: domains, *.domains, IPs, subnets, # comments.
	Tunnel string `json:"tunnel"`
	Direct string `json:"direct"`
	// DNSTunnel resolves names routed to the tunnel (through the VPN).
	DNSTunnel []string `json:"dns_tunnel"`
	// DNSDirect resolves other names directly; empty = system resolver.
	DNSDirect []string `json:"dns_direct"`
	// BlockQUIC: allow | unknown | block.
	BlockQUIC string `json:"block_quic"`
	// BlockDoH makes browsers fall back to our DNS: known DoH/DoT servers
	// are refused and the Firefox canary domain returns NXDOMAIN.
	BlockDoH bool `json:"block_doh"`
	// AllowLAN lets users reach private addresses of this machine's
	// network directly (otherwise refused).
	AllowLAN bool `json:"allow_lan"`
	// SniffTimeoutMS is how long to wait for the first bytes of a
	// connection to read the site name.
	SniffTimeoutMS int `json:"sniff_timeout_ms"`
	// AutoUpdate refreshes subscriptions every UpdateHours. When off, a
	// list is downloaded only once (no cache yet) or by "update now".
	AutoUpdate  bool `json:"auto_update"`
	UpdateHours int  `json:"update_hours"`
	// JournalSize is the number of recent connections kept in memory
	// (0 = journal off).
	JournalSize int `json:"journal_size"`
}

// Presets are the built-in subscriptions offered in the UI.
func Presets() []Subscription {
	return []Subscription{
		{ID: "itdog-inside", Name: "Россия: заблокированные сайты (itdoginfo)", Enabled: true, Action: "tunnel", Via: "tunnel",
			URL: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst"},
		{ID: "telegram", Name: "Подсети Telegram", Enabled: true, Action: "tunnel", Via: "tunnel",
			URL: "https://core.telegram.org/resources/cidr.txt"},
		{ID: "itdog-youtube", Name: "YouTube (itdoginfo)", Enabled: false, Action: "tunnel", Via: "tunnel",
			URL: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/youtube.lst"},
		{ID: "antifilter-community", Name: "antifilter: community (подсети)", Enabled: false, Action: "tunnel", Via: "tunnel",
			URL: "https://community.antifilter.download/list/community.lst"},
		{ID: "antifilter-ips", Name: "antifilter: allyouneed (подсети, ~17 тыс.)", Enabled: false, Action: "tunnel", Via: "tunnel",
			URL: "https://antifilter.download/list/allyouneed.lst"},
		{ID: "antifilter-domains", Name: "antifilter: все домены реестра", Enabled: false, Action: "tunnel", Via: "tunnel",
			URL: "https://antifilter.download/list/domains.lst", Note: "~1,8 млн доменов, 35 МБ: нужно ~300 МБ памяти"},
		{ID: "gfwlist", Name: "gfwlist (блокировки Китая)", Enabled: true, Action: "tunnel", Via: "tunnel",
			URL: "https://cdn.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt"},
	}
}

// DefaultRouting is used until the admin saves routing settings.
func DefaultRouting(dnsTunnel []string) Routing {
	return Routing{
		Mode:           ModeLists,
		Subscriptions:  Presets(),
		Tunnel:         "# Мои дополнения: всегда через VPN.\n# Домен (с поддоменами), *.домен, IP или подсеть; по одному в строке.\n",
		Direct:         "# Мои исключения: всегда напрямую. Важнее всех остальных правил.\n",
		DNSTunnel:      append([]string(nil), dnsTunnel...),
		BlockQUIC:      QUICUnknown,
		SniffTimeoutMS: 300,
		UpdateHours:    24,
		JournalSize:    500,
	}
}

func (r Routing) clone() Routing {
	out := r
	out.Subscriptions = append([]Subscription(nil), r.Subscriptions...)
	out.DNSTunnel = append([]string(nil), r.DNSTunnel...)
	out.DNSDirect = append([]string(nil), r.DNSDirect...)
	return out
}

// NewID returns a random subscription ID.
func NewID() string {
	var b [6]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Routing returns a copy of the routing settings.
func (s *Store) Routing() Routing {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.Routing.clone()
}

// SetRouting replaces and persists the routing settings.
func (s *Store) SetRouting(r Routing) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := r.clone()
	s.d.Routing = &c
	return s.saveLocked()
}
