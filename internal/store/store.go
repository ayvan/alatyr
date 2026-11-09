// Package store keeps relay state (server keys, obfuscation profiles, users,
// admin password hash) in a single JSON file.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"alatyr/internal/awgconf"
)

// Server is the listening identity of one inbound protocol.
type Server struct {
	PrivateKey string            `json:"private_key"`
	PublicKey  string            `json:"public_key"`
	Params     map[string]string `json:"params"`
}

// User is a relay client.
type User struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Protocol     string    `json:"protocol"`
	PrivateKey   string    `json:"private_key"`
	PublicKey    string    `json:"public_key"`
	PresharedKey string    `json:"preshared_key"`
	Address      string    `json:"address"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// Listener holds the ports of one inbound protocol.
type Listener struct {
	// Port is the UDP port the relay listens on; 0 disables the protocol.
	Port int `json:"port"`
	// Disabled turns the protocol off while keeping its port.
	Disabled bool `json:"disabled,omitempty"`
	// ExternalPort is written into user configs (router port forwarding);
	// 0 means "same as Port".
	ExternalPort int `json:"external_port,omitempty"`
}

// Active returns the port to listen on, 0 when the protocol is off.
func (l Listener) Active() int {
	if l.Disabled {
		return 0
	}
	return l.Port
}

// Endpoint returns the port users should connect to.
func (l Listener) Endpoint() int {
	if l.ExternalPort > 0 {
		return l.ExternalPort
	}
	return l.Port
}

// Settings are relay options editable from the web UI.
type Settings struct {
	// PublicHost is the host/IP written into user configs; empty means the
	// host used to open the web UI.
	PublicHost string              `json:"public_host"`
	Listeners  map[string]Listener `json:"listeners"`
}

func (st Settings) clone() Settings {
	out := Settings{PublicHost: st.PublicHost, Listeners: map[string]Listener{}}
	for k, v := range st.Listeners {
		out.Listeners[k] = v
	}
	return out
}

type data struct {
	AdminPasswordHash string             `json:"admin_password_hash,omitempty"`
	Settings          *Settings          `json:"settings,omitempty"`
	Routing           *Routing           `json:"routing,omitempty"`
	Servers           map[string]*Server `json:"servers"`
	Users             []*User            `json:"users"`
}

// Store is a concurrency-safe JSON-backed store.
type Store struct {
	mu       sync.Mutex
	path     string
	subnet   netip.Prefix
	d        data
	migrated bool
}

// legacyFile is the state file name used before the rename to Alatyr.
const legacyFile = "relay-data.json"

// Migrated reports whether the state was imported from re-vpnator.
func (s *Store) Migrated() bool { return s.migrated }

// ErrNotFound is returned for unknown users.
var ErrNotFound = errors.New("user not found")

// Open loads (or initialises) the store file. defaults and routing are used
// until they are saved from the web UI.
func Open(path string, subnet netip.Prefix, defaults Settings, routing Routing) (*Store, error) {
	s := &Store{path: path, subnet: subnet.Masked()}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// Migration from re-vpnator: pick up its state file next to ours.
		// The old file is left in place.
		if old, oerr := os.ReadFile(filepath.Join(filepath.Dir(path), legacyFile)); oerr == nil {
			raw, err = old, nil
			s.migrated = true
		}
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &s.d); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if s.d.Servers == nil {
		s.d.Servers = map[string]*Server{}
	}
	if s.d.Settings == nil {
		d := defaults.clone()
		s.d.Settings = &d
	}
	if s.d.Routing == nil {
		r := routing.clone()
		s.d.Routing = &r
	}
	if s.migrated {
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Settings returns a copy of the current settings.
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.Settings.clone()
}

// SetSettings replaces and persists the settings.
func (s *Store) SetSettings(st Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := st.clone()
	s.d.Settings = &c
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(&s.d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// EnsureServer returns the server identity for a protocol, creating it on
// first use.
func (s *Store) EnsureServer(proto string) (*Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if srv, ok := s.d.Servers[proto]; ok {
		return srv, nil
	}
	priv, pub, err := awgconf.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	params, err := awgconf.GenerateParams(proto)
	if err != nil {
		return nil, err
	}
	srv := &Server{PrivateKey: priv, PublicKey: pub, Params: params}
	s.d.Servers[proto] = srv
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return srv, nil
}

// Server returns the server identity for a protocol (nil if missing).
func (s *Store) Server(proto string) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.Servers[proto]
}

// HasPassword reports whether the admin password was set.
func (s *Store) HasPassword() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.AdminPasswordHash != ""
}

// SetPassword stores a bcrypt hash (salt is embedded in the hash string).
func (s *Store) SetPassword(pw string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.AdminPasswordHash = string(h)
	return s.saveLocked()
}

// CheckPassword verifies the admin password.
func (s *Store) CheckPassword(pw string) bool {
	s.mu.Lock()
	h := s.d.AdminPasswordHash
	s.mu.Unlock()
	return h != "" && bcrypt.CompareHashAndPassword([]byte(h), []byte(pw)) == nil
}

// Users returns a copy of all users sorted by creation time.
func (s *Store) Users() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]User, 0, len(s.d.Users))
	for _, u := range s.d.Users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// User returns a user by ID.
func (s *Store) User(id string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.d.Users {
		if u.ID == id {
			return *u, nil
		}
	}
	return User{}, ErrNotFound
}

// AddUser creates a user with fresh keys and the next free address.
func (s *Store) AddUser(name, proto string) (User, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return User{}, errors.New("name must be 1..64 characters")
	}
	priv, pub, err := awgconf.GenerateKeyPair()
	if err != nil {
		return User{}, err
	}
	psk, err := awgconf.GenerateSymmetricKey()
	if err != nil {
		return User{}, err
	}
	var idb [8]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	addr, err := s.nextAddrLocked()
	if err != nil {
		return User{}, err
	}
	u := &User{
		ID:           hex.EncodeToString(idb[:]),
		Name:         name,
		Protocol:     proto,
		PrivateKey:   priv,
		PublicKey:    pub,
		PresharedKey: psk,
		Address:      addr.String(),
		CreatedAt:    time.Now().UTC(),
	}
	s.d.Users = append(s.d.Users, u)
	if err := s.saveLocked(); err != nil {
		s.d.Users = s.d.Users[:len(s.d.Users)-1]
		return User{}, err
	}
	return *u, nil
}

func (s *Store) nextAddrLocked() (netip.Addr, error) {
	used := map[netip.Addr]bool{}
	for _, u := range s.d.Users {
		if a, err := netip.ParseAddr(u.Address); err == nil {
			used[a] = true
		}
	}
	// .0 is the network, .1 is the relay itself.
	a := s.subnet.Addr().Next().Next()
	for s.subnet.Contains(a) {
		next := a.Next()
		if !s.subnet.Contains(next) { // broadcast address
			break
		}
		if !used[a] {
			return a, nil
		}
		a = next
	}
	return netip.Addr{}, errors.New("no free addresses left in subnet")
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(id string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.d.Users {
		if u.ID == id {
			s.d.Users = append(s.d.Users[:i], s.d.Users[i+1:]...)
			return *u, s.saveLocked()
		}
	}
	return User{}, ErrNotFound
}

// SetDisabled enables or disables a user.
func (s *Store) SetDisabled(id string, disabled bool) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.d.Users {
		if u.ID == id {
			u.Disabled = disabled
			return *u, s.saveLocked()
		}
	}
	return User{}, ErrNotFound
}

// ClientConfig renders the user's AmneziaWG config. endpoint is host:port of
// the relay as seen by the user.
func (u User) ClientConfig(srv *Server, endpoint string, dns []string, mtu int) (string, error) {
	addr, err := netip.ParseAddr(u.Address)
	if err != nil {
		return "", err
	}
	cfg := &awgconf.Config{
		Interface: awgconf.Interface{
			PrivateKey: u.PrivateKey,
			Addresses:  []netip.Prefix{netip.PrefixFrom(addr, 32)},
			DNS:        dns,
			MTU:        mtu,
			Params:     srv.Params,
		},
		Peers: []awgconf.Peer{{
			PublicKey:    srv.PublicKey,
			PresharedKey: u.PresharedKey,
			// ::/0 keeps IPv6 from leaking around the tunnel; the relay
			// itself forwards IPv4 only.
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			Endpoint:            endpoint,
			PersistentKeepalive: "25",
		}},
	}
	return cfg.Render(), nil
}
