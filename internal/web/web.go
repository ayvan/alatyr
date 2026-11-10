// Package web serves the admin UI and its JSON API.
package web

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"alatyr/internal/awgconf"
	"alatyr/internal/lists"
	"alatyr/internal/relay"
	"alatyr/internal/router"
	"alatyr/internal/store"
)

//go:embed index.html
var indexHTML []byte

const (
	cookieName = "alatyr_session"
	sessionTTL = 7 * 24 * time.Hour
)

// Options configure the web server.
type Options struct {
	Store  *store.Store
	Relay  *relay.Relay
	Router *router.Router
	Lists  *lists.Manager
	// Apply pushes the stored routing settings to the running service.
	Apply func()
	// DNS is written into user configs.
	DNS []string
	MTU int
}

// Server is the HTTP handler.
type Server struct {
	opts     Options
	mux      *http.ServeMux
	mu       sync.Mutex
	setupMu  sync.Mutex
	sessions map[string]time.Time
	fails    map[string]*failInfo
}

type failInfo struct {
	count int
	until time.Time
}

// New builds the handler.
func New(opts Options) *Server {
	s := &Server{opts: opts, mux: http.NewServeMux(), sessions: map[string]time.Time{}, fails: map[string]*failInfo{}}
	s.mux.HandleFunc("GET /{$}", s.index)
	s.mux.HandleFunc("GET /api/state", s.state)
	s.mux.HandleFunc("POST /api/setup", s.setup)
	s.mux.HandleFunc("POST /api/login", s.login)
	s.mux.HandleFunc("POST /api/logout", s.logout)
	s.mux.HandleFunc("GET /api/settings", s.authOrSetup(s.getSettings))
	s.mux.HandleFunc("POST /api/settings", s.auth(s.postSettings))
	s.mux.HandleFunc("GET /api/wan-ip", s.authOrSetup(s.wanIP))
	s.mux.HandleFunc("GET /api/status", s.auth(s.status))
	s.mux.HandleFunc("GET /api/users", s.auth(s.listUsers))
	s.mux.HandleFunc("POST /api/users", s.auth(s.createUser))
	s.mux.HandleFunc("DELETE /api/users/{id}", s.auth(s.deleteUser))
	s.mux.HandleFunc("POST /api/users/{id}/disabled", s.auth(s.setDisabled))
	s.mux.HandleFunc("GET /api/users/{id}/share", s.auth(s.share))
	s.mux.HandleFunc("GET /api/users/{id}/config", s.auth(s.download))
	s.mux.HandleFunc("GET /api/users/{id}/qr.png", s.auth(s.qr))
	s.mux.HandleFunc("GET /api/routing", s.auth(s.getRouting))
	s.mux.HandleFunc("POST /api/routing", s.auth(s.postRouting))
	s.mux.HandleFunc("GET /api/routing/stats", s.auth(s.routingStats))
	s.mux.HandleFunc("POST /api/routing/update", s.auth(s.updateLists))
	s.mux.HandleFunc("GET /api/routing/check", s.auth(s.checkRoute))
	s.mux.HandleFunc("GET /api/routing/journal", s.auth(s.journal))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	// State-changing requests must carry a custom header, which browsers
	// refuse to send cross-origin without CORS: CSRF protection.
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Requested-With") != "alatyr" {
		jsonErr(w, http.StatusForbidden, "missing X-Requested-With header")
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	w.Write(indexHTML)
}

// --- auth ---

func (s *Server) newSession(w http.ResponseWriter, r *http.Request) {
	var b [32]byte
	rand.Read(b[:])
	tok := hex.EncodeToString(b[:])
	s.mu.Lock()
	now := time.Now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[tok] = now.Add(sessionTTL)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: int(sessionTTL.Seconds()),
	})
}

func (s *Server) loggedIn(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, exp := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(tok), []byte(c.Value)) == 1 {
			return time.Now().Before(exp)
		}
	}
	return false
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.loggedIn(r) {
			jsonErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		h(w, r)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"setup_needed": !s.opts.Store.HasPassword(), "logged_in": s.loggedIn(r)})
}

type pwReq struct {
	Password string `json:"password"`
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string          `json:"password"`
		Settings *store.Settings `json:"settings"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Password) < 8 {
		jsonErr(w, http.StatusBadRequest, "пароль должен быть не короче 8 символов")
		return
	}
	s.setupMu.Lock() // serialise concurrent first-time setups
	defer s.setupMu.Unlock()
	if s.opts.Store.HasPassword() {
		jsonErr(w, http.StatusConflict, "пароль уже задан")
		return
	}
	if req.Settings != nil {
		if err := s.applySettings(*req.Settings); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := s.opts.Store.SetPassword(req.Password); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.newSession(w, r)
	writeJSON(w, map[string]bool{"ok": true})
}

// --- settings ---

type listenerView struct {
	Protocol     string `json:"protocol"`
	Title        string `json:"title"`
	Port         int    `json:"port"`
	ExternalPort int    `json:"external_port"`
	Disabled     bool   `json:"disabled"`
	Running      bool   `json:"running"`
}

func (s *Server) listenerViews() []listenerView {
	st := s.opts.Store.Settings()
	var out []listenerView
	for _, p := range awgconf.Protocols {
		l := st.Listeners[p]
		out = append(out, listenerView{Protocol: p, Title: awgconf.ProtocolTitle(p), Port: l.Port,
			ExternalPort: l.Endpoint(), Disabled: l.Disabled || l.Port == 0, Running: s.opts.Relay.Port(p) != 0})
	}
	return out
}

// authOrSetup allows a request before the first setup (the setup form needs
// it) and requires login afterwards.
func (s *Server) authOrSetup(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Store.HasPassword() && !s.loggedIn(r) {
			jsonErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		h(w, r)
	}
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"public_host":   s.opts.Store.Settings().PublicHost,
		"detected_host": s.requestHost(r),
		"listeners":     s.listenerViews(),
		"primary_ip":    outboundIP(),
		"lan_ips":       lanIPs(),
	})
}

type ifaceAddr struct {
	Iface string `json:"iface"`
	IP    string `json:"ip"`
}

// lanIPs lists private IPv4 addresses of this machine (router port
// forwarding targets).
func lanIPs() []ifaceAddr {
	out := []ifaceAddr{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || virtualIface(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() && ip.IsPrivate() {
				out = append(out, ifaceAddr{Iface: ifc.Name, IP: ip.Unmap().String()})
			}
		}
	}
	return out
}

// virtualIface reports VPN/VM/container interfaces a router cannot forward to.
func virtualIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"utun", "tun", "tap", "wg", "awg", "ppp", "ipsec", "bridge", "docker", "br-", "veth",
		"vmnet", "vboxnet", "virbr", "zt", "tailscale", "llw", "awdl", "anpi", "gif", "stf"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	for _, sub := range []string{"virtualbox", "vmware", "hyper-v", "vethernet", "wireguard", "amnezia", "openvpn", "tap-windows", "loopback"} {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// wanIP asks a public service for this network's external IP (direct, not
// through the VPN). Only called when the admin presses the button.
func (s *Server) wanIP(w http.ResponseWriter, r *http.Request) {
	c := &http.Client{Timeout: 7 * time.Second}
	resp, err := c.Get("http://api.ipify.org/")
	if err != nil {
		jsonErr(w, http.StatusBadGateway, "не удалось определить внешний IP: "+err.Error())
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		jsonErr(w, http.StatusBadGateway, "сервис вернул что-то странное")
		return
	}
	writeJSON(w, map[string]string{"ip": ip})
}

func (s *Server) postSettings(w http.ResponseWriter, r *http.Request) {
	var req store.Settings
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.applySettings(req); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

// applySettings validates, applies to the running relay and persists.
func (s *Server) applySettings(st store.Settings) error {
	st.PublicHost = strings.Trim(strings.TrimSpace(st.PublicHost), "[]")
	if h := st.PublicHost; h != "" {
		if _, err := netip.ParseAddr(h); err != nil && (len(h) > 253 || !hostRe.MatchString(h)) {
			return fmt.Errorf("внешний адрес %q: нужен IP или доменное имя без порта и http://", h)
		}
	}
	ls := map[string]store.Listener{}
	for _, p := range awgconf.Protocols {
		l := st.Listeners[p]
		if l.Port == 0 {
			l.Disabled = true
		}
		if l.ExternalPort == l.Port {
			l.ExternalPort = 0
		}
		ls[p] = l
	}
	st.Listeners = ls
	rl := s.opts.Relay
	if err := rl.CheckListeners(ls); err != nil {
		return err
	}
	old := s.opts.Store.Settings()
	if err := rl.ApplyListeners(ls); err != nil {
		rl.ApplyListeners(old.Listeners) // best effort rollback
		return err
	}
	return s.opts.Store.SetSettings(st)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req pwReq
	if !readJSON(w, r, &req) {
		return
	}
	ip := clientIP(r)
	s.mu.Lock()
	f := s.fails[ip]
	if f != nil && time.Now().Before(f.until) {
		s.mu.Unlock()
		jsonErr(w, http.StatusTooManyRequests, "слишком много попыток, подождите минуту")
		return
	}
	s.mu.Unlock()
	if !s.opts.Store.CheckPassword(req.Password) {
		s.mu.Lock()
		if f == nil {
			f = &failInfo{}
			s.fails[ip] = f
		}
		f.count++
		if f.count >= 5 {
			f.count = 0
			f.until = time.Now().Add(time.Minute)
		}
		s.mu.Unlock()
		jsonErr(w, http.StatusUnauthorized, "неверный пароль")
		return
	}
	s.mu.Lock()
	delete(s.fails, ip)
	s.mu.Unlock()
	s.newSession(w, r)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]bool{"ok": true})
}

// --- status & users ---

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	rl := s.opts.Relay
	writeJSON(w, map[string]any{
		"upstream": map[string]any{
			"endpoint": rl.UpstreamEndpoint(),
			"address":  rl.UpstreamAddr().String(),
			"stats":    rl.UpstreamStats(),
		},
		"listeners":    s.listenerViews(),
		"nat_mappings": rl.NATMappings(),
		"mode":         s.opts.Store.Routing().Mode,
		"public_host":  s.endpointHost(r),
	})
}

type userView struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Protocol  string           `json:"protocol"`
	Title     string           `json:"title"`
	Address   string           `json:"address"`
	Disabled  bool             `json:"disabled"`
	CreatedAt time.Time        `json:"created_at"`
	Stats     *relay.PeerStats `json:"stats,omitempty"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	stats := s.opts.Relay.UserStats()
	out := []userView{}
	for _, u := range s.opts.Store.Users() {
		v := userView{ID: u.ID, Name: u.Name, Protocol: u.Protocol, Title: awgconf.ProtocolTitle(u.Protocol),
			Address: u.Address, Disabled: u.Disabled, CreatedAt: u.CreatedAt}
		if st, ok := stats[u.PublicKey]; ok {
			v.Stats = &st
		}
		out = append(out, v)
	}
	writeJSON(w, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if s.opts.Relay.Port(req.Protocol) == 0 {
		jsonErr(w, http.StatusBadRequest, "протокол выключен в настройках")
		return
	}
	u, err := s.opts.Store.AddUser(req.Name, req.Protocol)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.opts.Relay.AddUser(u); err != nil {
		s.opts.Store.DeleteUser(u.ID)
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]string{"id": u.ID})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.opts.Store.DeleteUser(r.PathValue("id"))
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}
	s.opts.Relay.RemoveUser(u)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) setDisabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Disabled bool `json:"disabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	u, err := s.opts.Store.SetDisabled(r.PathValue("id"), req.Disabled)
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}
	if u.Disabled {
		err = s.opts.Relay.RemoveUser(u)
	} else {
		err = s.opts.Relay.AddUser(u)
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// --- sharing ---

// endpointHost decides what host users should connect to.
func (s *Server) endpointHost(r *http.Request) string {
	if h := s.opts.Store.Settings().PublicHost; h != "" {
		return h
	}
	return s.requestHost(r)
}

// requestHost is the host the web UI was opened with (LAN IP for localhost).
func (s *Server) requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if a, err := netip.ParseAddr(host); (err == nil && a.IsLoopback()) || host == "localhost" || host == "" {
		if ip := outboundIP(); ip != "" {
			return ip
		}
	}
	return host
}

// outboundIP returns the LAN address used for the default route.
func outboundIP() string {
	c, err := net.Dial("udp4", "192.0.2.1:9") // no packet is sent
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func (s *Server) clientConfig(r *http.Request, u store.User) (string, error) {
	srv := s.opts.Store.Server(u.Protocol)
	if srv == nil || s.opts.Relay.Port(u.Protocol) == 0 {
		return "", errors.New("протокол пользователя сейчас выключен")
	}
	port := s.opts.Store.Settings().Listeners[u.Protocol].Endpoint()
	endpoint := net.JoinHostPort(s.endpointHost(r), strconv.Itoa(port))
	return u.ClientConfig(srv, endpoint, s.opts.DNS, s.opts.MTU)
}

func (s *Server) userConfig(w http.ResponseWriter, r *http.Request) (store.User, string, bool) {
	u, err := s.opts.Store.User(r.PathValue("id"))
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return u, "", false
	}
	conf, err := s.clientConfig(r, u)
	if err != nil {
		jsonErr(w, http.StatusConflict, err.Error())
		return u, "", false
	}
	return u, conf, true
}

func (s *Server) share(w http.ResponseWriter, r *http.Request) {
	u, conf, ok := s.userConfig(w, r)
	if !ok {
		return
	}
	st := s.opts.Store.Settings()
	writeJSON(w, map[string]any{
		"name": u.Name, "filename": fileName(u.Name), "config": conf, "url": awgconf.AmneziaURL(conf),
		"protocol": u.Protocol,
		"endpoint": net.JoinHostPort(s.endpointHost(r), strconv.Itoa(st.Listeners[u.Protocol].Endpoint())),
		"host_set": st.PublicHost != "",
	})
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9_=+.-]+`)

var translit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e", 'ж': "zh", 'з': "z", 'и': "i",
	'й': "y", 'к': "k", 'л': "l", 'м': "m", 'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t",
	'у': "u", 'ф': "f", 'х': "h", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "sch", 'ъ': "", 'ы': "y", 'ь': "",
	'э': "e", 'ю': "yu", 'я': "ya", 'і': "i", 'ї': "yi", 'є': "ye", 'ґ': "g",
}

// fileName produces a tunnel-name friendly file name (WireGuard apps use the
// file name as tunnel name, limited to 15 chars).
func fileName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if t, ok := translit[r]; ok {
			b.WriteString(t)
		} else {
			b.WriteRune(r)
		}
	}
	n := unsafeName.ReplaceAllString(b.String(), "_")
	n = strings.Trim(n, "_.")
	if n == "" {
		n = "relay"
	}
	if len(n) > 15 {
		n = n[:15]
	}
	return n + ".conf"
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	u, conf, ok := s.userConfig(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName(u.Name)))
	w.Write([]byte(conf))
}

func (s *Server) qr(w http.ResponseWriter, r *http.Request) {
	_, conf, ok := s.userConfig(w, r)
	if !ok {
		return
	}
	text := conf
	if r.URL.Query().Get("type") == "url" {
		text = awgconf.AmneziaURL(conf)
	}
	var png []byte
	var err error
	for _, lvl := range []qrcode.RecoveryLevel{qrcode.Medium, qrcode.Low} {
		if png, err = qrcode.Encode(text, lvl, 768); err == nil {
			break
		}
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "QR: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return false
	}
	return true
}
