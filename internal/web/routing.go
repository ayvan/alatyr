package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"alatyr/internal/rules"
	"alatyr/internal/store"
)

func (s *Server) getRouting(w http.ResponseWriter, r *http.Request) {
	rt := s.opts.Store.Routing()
	writeJSON(w, map[string]any{
		"settings": rt,
		"statuses": s.opts.Lists.Statuses(),
		"presets":  store.Presets(),
		"own": map[string]any{
			"tunnel": ownStats(rt.Tunnel),
			"direct": ownStats(rt.Direct),
		},
	})
}

func ownStats(text string) map[string]int {
	l := rules.Parse(text)
	return map[string]int{"rules": l.Size(), "ignored": l.Ignored}
}

func (s *Server) routingStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"stats":    s.opts.Router.Stats(),
		"statuses": s.opts.Lists.Statuses(),
	})
}

func (s *Server) postRouting(w http.ResponseWriter, r *http.Request) {
	var req store.Routing
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return
	}
	if err := normRouting(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	old := s.opts.Store.Routing()
	if err := s.opts.Store.SetRouting(req); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	keep := map[string]bool{}
	for _, sub := range req.Subscriptions {
		keep[sub.ID] = true
	}
	for _, sub := range old.Subscriptions {
		if !keep[sub.ID] {
			s.opts.Lists.Forget(sub.ID)
		}
	}
	s.opts.Apply()
	s.opts.Lists.Kick() // downloads newly enabled lists
	writeJSON(w, map[string]bool{"ok": true})
}

// normRouting validates the settings and fills defaults.
func normRouting(rt *store.Routing) error {
	switch rt.Mode {
	case store.ModeLists, store.ModeExcept, store.ModeFull:
	default:
		return fmt.Errorf("неизвестный режим %q", rt.Mode)
	}
	switch rt.BlockQUIC {
	case store.QUICAllow, store.QUICUnknown, store.QUICBlock:
	case "":
		rt.BlockQUIC = store.QUICUnknown
	default:
		return fmt.Errorf("неизвестная политика QUIC %q", rt.BlockQUIC)
	}
	if rt.SniffTimeoutMS < 50 || rt.SniffTimeoutMS > 5000 {
		return fmt.Errorf("ожидание имени сайта: от 50 до 5000 мс")
	}
	if rt.UpdateHours < 1 || rt.UpdateHours > 24*30 {
		return fmt.Errorf("интервал обновления: от 1 до 720 часов")
	}
	if rt.JournalSize < 0 || rt.JournalSize > 10000 {
		return fmt.Errorf("размер журнала: от 0 до 10000")
	}
	var err error
	if rt.DNSTunnel, err = normDNS(rt.DNSTunnel, "DNS через туннель"); err != nil {
		return err
	}
	if len(rt.DNSTunnel) == 0 {
		return fmt.Errorf("DNS через туннель: нужен хотя бы один сервер")
	}
	if rt.DNSDirect, err = normDNS(rt.DNSDirect, "DNS напрямую"); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i := range rt.Subscriptions {
		sub := &rt.Subscriptions[i]
		sub.URL = strings.TrimSpace(sub.URL)
		u, err := url.Parse(sub.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("подписка %q: нужен адрес http(s)://…", sub.Name)
		}
		sub.Name = strings.TrimSpace(sub.Name)
		if sub.Name == "" {
			sub.Name = u.Host
		}
		if sub.ID == "" || seen[sub.ID] || !safeSubID(sub.ID) {
			sub.ID = store.NewID()
		}
		seen[sub.ID] = true
		if sub.Action != "direct" {
			sub.Action = "tunnel"
		}
		if sub.Via != "direct" {
			sub.Via = "tunnel"
		}
	}
	return nil
}

func safeSubID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func normDNS(list []string, what string) ([]string, error) {
	var out []string
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s); err == nil && ap.Addr().Is4() {
			out = append(out, ap.String())
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			out = append(out, a.String())
			continue
		}
		return nil, fmt.Errorf("%s: %q — нужен IPv4-адрес (можно с :порт)", what, s)
	}
	return out, nil
}

func (s *Server) updateLists(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"` // empty = all enabled
	}
	if !readJSON(w, r, &req) {
		return
	}
	n := 0
	for _, sub := range s.opts.Store.Routing().Subscriptions {
		if (req.ID == "" && sub.Enabled) || sub.ID == req.ID {
			go s.opts.Lists.Update(sub)
			n++
		}
	}
	if n == 0 {
		jsonErr(w, http.StatusNotFound, "нет подписок для обновления (включите и сохраните)")
		return
	}
	writeJSON(w, map[string]int{"started": n})
}

func (s *Server) checkRoute(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		jsonErr(w, http.StatusBadRequest, "введите домен или IP")
		return
	}
	d, names := s.opts.Router.Check(q)
	writeJSON(w, map[string]any{"decision": d, "names": names})
}

func (s *Server) journal(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	writeJSON(w, s.opts.Router.Journal(r.URL.Query().Get("filter"), limit))
}
