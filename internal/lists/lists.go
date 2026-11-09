// Package lists downloads rule subscriptions, caches them on disk and keeps
// them parsed in memory.
//
// A subscription is downloaded when it has no cache yet (first start, newly
// enabled, URL changed) or on "update now". With auto update on, it is also
// refreshed every UpdateHours.
package lists

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"alatyr/internal/rules"
	"alatyr/internal/store"
)

const (
	maxSize    = 64 << 20
	retryAfter = 10 * time.Minute
	tick       = time.Minute
)

// Status of one subscription, shown in the web UI.
type Status struct {
	ID       string    `json:"id"`
	Updated  time.Time `json:"updated,omitempty"`
	Rules    int       `json:"rules"`
	Ignored  int       `json:"ignored"`
	Bytes    int       `json:"bytes"`
	Error    string    `json:"error,omitempty"`
	Updating bool      `json:"updating"`
	// Loaded is false until the list is in memory.
	Loaded bool `json:"loaded"`
}

type meta struct {
	URL     string    `json:"url"`
	Updated time.Time `json:"updated"`
}

type item struct {
	list    *rules.List
	url     string
	status  Status
	lastTry time.Time
}

// Manager owns all subscriptions.
type Manager struct {
	dir      string
	clients  map[string]*http.Client // "tunnel", "direct"
	routing  func() store.Routing
	onChange func()

	mu    sync.Mutex
	items map[string]*item
	kick  chan struct{}
	stop  chan struct{}
}

// New creates a manager. routing returns the current settings; onChange is
// called when a list was (re)loaded.
func New(dir string, tunnel, direct *http.Client, routing func() store.Routing, onChange func()) *Manager {
	return &Manager{
		dir:      dir,
		clients:  map[string]*http.Client{"tunnel": tunnel, "direct": direct},
		routing:  routing,
		onChange: onChange,
		items:    map[string]*item{},
		kick:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
	}
}

// Start loads the disk cache and runs the background updater.
func (m *Manager) Start() {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		log.Printf("lists: %v", err)
	}
	for _, s := range m.routing().Subscriptions {
		if s.Enabled {
			m.loadCache(s)
		}
	}
	m.onChange()
	go m.loop()
}

// Close stops the updater.
func (m *Manager) Close() { close(m.stop) }

// Kick makes the updater look at the settings now (after they change).
func (m *Manager) Kick() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

var safeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func (m *Manager) paths(id string) (string, string) {
	return filepath.Join(m.dir, id+".txt"), filepath.Join(m.dir, id+".json")
}

func (m *Manager) get(id string) *item {
	it := m.items[id]
	if it == nil {
		it = &item{status: Status{ID: id}}
		m.items[id] = it
	}
	return it
}

// loadCache reads a cached list if it belongs to the subscription's URL.
func (m *Manager) loadCache(s store.Subscription) {
	if !safeID.MatchString(s.ID) {
		return
	}
	txt, mj := m.paths(s.ID)
	var md meta
	raw, err := os.ReadFile(mj)
	if err != nil || json.Unmarshal(raw, &md) != nil || md.URL != s.URL {
		return
	}
	body, err := os.ReadFile(txt)
	if err != nil {
		return
	}
	l := rules.Parse(string(body))
	m.mu.Lock()
	it := m.get(s.ID)
	it.list, it.url = l, s.URL
	it.status.Updated, it.status.Rules, it.status.Ignored, it.status.Bytes, it.status.Loaded = md.Updated, l.Size(), l.Ignored, len(body), true
	m.mu.Unlock()
	log.Printf("lists: %s: %d rules from cache (%s)", s.Name, l.Size(), md.Updated.Format(time.DateTime))
}

func (m *Manager) loop() {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		m.check()
		select {
		case <-m.stop:
			return
		case <-t.C:
		case <-m.kick:
		}
	}
}

// check downloads what is missing or stale.
func (m *Manager) check() {
	r := m.routing()
	interval := time.Duration(max(r.UpdateHours, 1)) * time.Hour
	now := time.Now()
	changed := false
	for _, s := range r.Subscriptions {
		if !s.Enabled || !safeID.MatchString(s.ID) {
			continue
		}
		m.mu.Lock()
		it := m.items[s.ID]
		urlChanged := it != nil && it.url != "" && it.url != s.URL
		missing := it == nil || it.list == nil || urlChanged
		m.mu.Unlock()
		if missing && it == nil {
			// Enabled after start: maybe there is a cache on disk.
			m.loadCache(s)
			m.mu.Lock()
			it = m.items[s.ID]
			missing = it == nil || it.list == nil
			m.mu.Unlock()
			changed = changed || !missing
		}
		m.mu.Lock()
		var lastTry, updated time.Time
		if it != nil {
			lastTry, updated = it.lastTry, it.status.Updated
		}
		m.mu.Unlock()
		due := false
		switch {
		case missing:
			due = now.Sub(lastTry) > retryAfter
		case r.AutoUpdate:
			due = now.Sub(updated) > interval && now.Sub(lastTry) > retryAfter
		}
		if due {
			m.Update(s)
		}
	}
	if changed {
		m.onChange()
	}
}

// Update downloads a subscription now. Errors keep the previous list.
func (m *Manager) Update(s store.Subscription) error {
	if !safeID.MatchString(s.ID) {
		return errors.New("bad subscription id")
	}
	m.mu.Lock()
	it := m.get(s.ID)
	if it.status.Updating {
		m.mu.Unlock()
		return errors.New("уже обновляется")
	}
	it.status.Updating = true
	it.lastTry = time.Now()
	m.mu.Unlock()

	body, err := m.download(s)
	var l *rules.List
	if err == nil {
		l = rules.Parse(string(body))
		if l.Size() == 0 {
			err = errors.New("в файле не найдено ни одного правила")
		}
	}
	m.mu.Lock()
	it.status.Updating = false
	if err != nil {
		it.status.Error = err.Error()
		m.mu.Unlock()
		log.Printf("lists: %s: %v", s.Name, err)
		return err
	}
	now := time.Now()
	it.list, it.url = l, s.URL
	it.status = Status{ID: s.ID, Updated: now, Rules: l.Size(), Ignored: l.Ignored, Bytes: len(body), Loaded: true}
	m.mu.Unlock()

	txt, mj := m.paths(s.ID)
	if err := writeFile(txt, body); err != nil {
		log.Printf("lists: cache %s: %v", s.Name, err)
	} else if raw, err := json.Marshal(meta{URL: s.URL, Updated: now}); err == nil {
		writeFile(mj, raw)
	}
	log.Printf("lists: %s: downloaded, %d rules (%d lines ignored)", s.Name, l.Size(), l.Ignored)
	m.onChange()
	return nil
}

func (m *Manager) download(s store.Subscription) ([]byte, error) {
	c := m.clients[s.Via]
	if c == nil {
		c = m.clients["tunnel"]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "alatyr")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("скачивание: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("скачивание: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("скачивание: %w", err)
	}
	if len(body) > maxSize {
		return nil, fmt.Errorf("файл больше %d МБ", maxSize>>20)
	}
	return body, nil
}

func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Sources returns the loaded lists of enabled subscriptions.
func (m *Manager) Sources(subs []store.Subscription) []rules.Source {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []rules.Source
	for _, s := range subs {
		it := m.items[s.ID]
		if !s.Enabled || it == nil || it.list == nil || it.url != s.URL {
			continue
		}
		out = append(out, rules.Source{Name: s.Name, Action: rules.ParseAction(s.Action), List: it.list})
	}
	return out
}

// Statuses returns the status of every known subscription.
func (m *Manager) Statuses() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]Status{}
	for id, it := range m.items {
		out[id] = it.status
	}
	return out
}

// Forget drops a removed subscription and its cache.
func (m *Manager) Forget(id string) {
	if !safeID.MatchString(id) {
		return
	}
	m.mu.Lock()
	delete(m.items, id)
	m.mu.Unlock()
	txt, mj := m.paths(id)
	os.Remove(txt)
	os.Remove(mj)
}
