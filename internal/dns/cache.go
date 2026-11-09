package dns

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// Clients keep using an address well past the record TTL, so the
	// mapping lives at least minKeep.
	minKeep    = 30 * time.Minute
	maxNames   = 4
	maxEntries = 200_000
	gcInterval = 5 * time.Minute
)

type cacheEntry struct {
	names []string // most recent first
	exp   time.Time
}

// Cache maps IPv4 addresses to the names that resolved to them.
type Cache struct {
	mu     sync.Mutex
	m      map[netip.Addr]*cacheEntry
	lastGC time.Time
	now    func() time.Time
}

// NewCache creates an empty cache.
func NewCache() *Cache {
	return &Cache{m: map[netip.Addr]*cacheEntry{}, now: time.Now}
}

// Add remembers that name resolved to ip.
func (c *Cache) Add(ip netip.Addr, name string, ttl time.Duration) {
	now := c.now()
	exp := now.Add(max(ttl, minKeep))
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.lastGC) > gcInterval || len(c.m) >= maxEntries {
		c.gcLocked(now)
	}
	e := c.m[ip]
	if e == nil {
		if len(c.m) >= maxEntries {
			return
		}
		e = &cacheEntry{}
		c.m[ip] = e
	}
	if exp.After(e.exp) {
		e.exp = exp
	}
	for i, n := range e.names {
		if n == name {
			copy(e.names[1:i+1], e.names[:i])
			e.names[0] = name
			return
		}
	}
	e.names = append([]string{name}, e.names...)
	if len(e.names) > maxNames {
		e.names = e.names[:maxNames]
	}
}

// Names returns the names that recently resolved to ip.
func (c *Cache) Names(ip netip.Addr) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[ip]
	if e == nil || c.now().After(e.exp) {
		return nil
	}
	return append([]string(nil), e.names...)
}

// Len returns the number of cached addresses.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

func (c *Cache) gcLocked(now time.Time) {
	c.lastGC = now
	for ip, e := range c.m {
		if now.After(e.exp) {
			delete(c.m, ip)
		}
	}
}
