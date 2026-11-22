package main

import (
	"sync"
	"time"
)

// rateLimiter counts failed attempts per key (client IP, email, user) in a
// fixed window, to slow down password and 2FA-code guessing. In-memory: the
// limits reset on restart, which is acceptable for a single instance.
type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rlEntry
	now     func() time.Time
}

type rlEntry struct {
	fails int
	reset time.Time
}

const rateWindow = 15 * time.Minute

// Failure budgets per window.
const (
	maxFailsPerAccount = 10 // per email / user: password or code guesses
	maxFailsPerIP      = 50 // per client IP across all accounts
)

func newRateLimiter() *rateLimiter {
	return &rateLimiter{entries: map[string]*rlEntry{}, now: time.Now}
}

// blocked reports whether key has used up its failure budget.
func (l *rateLimiter) blocked(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil || l.now().After(e.reset) {
		return false
	}
	return e.fails >= limit
}

func (l *rateLimiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, k := range keys {
		e := l.entries[k]
		if e == nil || now.After(e.reset) {
			e = &rlEntry{reset: now.Add(rateWindow)}
			l.entries[k] = e
		}
		e.fails++
	}
	// Opportunistic cleanup keeps the map bounded.
	if len(l.entries) > 10000 {
		for k, e := range l.entries {
			if now.After(e.reset) {
				delete(l.entries, k)
			}
		}
	}
}

func (l *rateLimiter) clear(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.entries, k)
	}
}
