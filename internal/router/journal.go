package router

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"alatyr/internal/rules"
)

// Entry is one routed flow in the journal.
type Entry struct {
	Time  time.Time `json:"time"`
	User  string    `json:"user"`
	Proto string    `json:"proto"`
	Dst   string    `json:"dst"`
	Decision
	Error string `json:"error,omitempty"`
}

type journal struct {
	mu   sync.Mutex
	buf  []Entry
	next int
	full bool
}

func (j *journal) resize(n int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if n == len(j.buf) {
		return
	}
	old := j.listLocked()
	j.buf, j.next, j.full = make([]Entry, n), 0, false
	if n == 0 {
		return
	}
	if len(old) > n {
		old = old[:n]
	}
	for i := len(old) - 1; i >= 0; i-- {
		j.addLocked(old[i])
	}
}

func (j *journal) add(e Entry) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.buf) > 0 {
		j.addLocked(e)
	}
}

func (j *journal) addLocked(e Entry) {
	j.buf[j.next] = e
	j.next = (j.next + 1) % len(j.buf)
	if j.next == 0 {
		j.full = true
	}
}

// listLocked returns entries newest first.
func (j *journal) listLocked() []Entry {
	n := j.next
	if j.full {
		n = len(j.buf)
	}
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		idx := (j.next - 1 - i + len(j.buf)) % len(j.buf)
		out = append(out, j.buf[idx])
	}
	return out
}

type pendingEntry struct {
	e Entry
}

func (p *pendingEntry) set(d Decision) { p.e.Decision = d }

func (r *Router) newEntry(proto string, src, dst netip.AddrPort) *pendingEntry {
	user := src.Addr().String()
	if r.opts.UserName != nil {
		if n := r.opts.UserName(src.Addr()); n != "" {
			user = n
		}
	}
	return &pendingEntry{e: Entry{Time: time.Now(), User: user, Proto: proto, Dst: dst.String()}}
}

func (r *Router) finish(p *pendingEntry, err error) {
	if err != nil {
		p.e.Error = err.Error()
		r.stats.failed.Add(1)
	} else if p.e.Action == rules.Block {
		r.stats.blocked.Add(1)
	}
	r.journal.add(p.e)
}

// Journal returns recent flows, newest first, optionally filtered by a
// substring of the user, host or destination.
func (r *Router) Journal(filter string, limit int) []Entry {
	r.journal.mu.Lock()
	all := r.journal.listLocked()
	r.journal.mu.Unlock()
	filter = strings.ToLower(strings.TrimSpace(filter))
	out := make([]Entry, 0, min(limit, len(all)))
	for _, e := range all {
		if len(out) >= limit {
			break
		}
		if filter != "" && !strings.Contains(strings.ToLower(e.User+" "+e.Host+" "+e.Dst+" "+e.Action.String()), filter) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// --- stats ---

type dirStats struct {
	conns, active, up, down atomic.Int64
}

type counters struct {
	direct, tunnel  dirStats
	blocked, failed atomic.Int64
}

func (c *counters) dir(a rules.Action) *dirStats {
	if a == rules.Tunnel {
		return &c.tunnel
	}
	return &c.direct
}

func (c *counters) open(a rules.Action) {
	d := c.dir(a)
	d.conns.Add(1)
	d.active.Add(1)
}

func (c *counters) close(a rules.Action) { c.dir(a).active.Add(-1) }

func (c *counters) add(a rules.Action, up bool, n int) {
	if up {
		c.dir(a).up.Add(int64(n))
	} else {
		c.dir(a).down.Add(int64(n))
	}
}

// DirStats are counters of one route.
type DirStats struct {
	Conns  int64 `json:"conns"`
	Active int64 `json:"active"`
	Up     int64 `json:"up"`
	Down   int64 `json:"down"`
}

// Stats are routing counters since start.
type Stats struct {
	Direct   DirStats `json:"direct"`
	Tunnel   DirStats `json:"tunnel"`
	Blocked  int64    `json:"blocked"`
	Failed   int64    `json:"failed"`
	DNSCache int      `json:"dns_cache"`
}

// Stats returns the counters.
func (r *Router) Stats() Stats {
	conv := func(d *dirStats) DirStats {
		return DirStats{d.conns.Load(), d.active.Load(), d.up.Load(), d.down.Load()}
	}
	return Stats{
		Direct: conv(&r.stats.direct), Tunnel: conv(&r.stats.tunnel),
		Blocked: r.stats.blocked.Load(), Failed: r.stats.failed.Load(), DNSCache: r.opts.DNS.Cache.Len(),
	}
}
