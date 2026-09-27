package drip

import (
	"net/netip"
	"sync"
	"time"
)

// RateLimiter is a token bucket per network prefix (/24 or /48): each
// prefix may start Burst maze requests at once and Rate more per second
// after that. It bounds how fast a client, or a pool rotating addresses
// inside one network, can make the server render and log pages, which the
// concurrency caps alone don't (short requests free their slot at once).
// Safe for concurrent use; memory is bounded by Capacity.
type RateLimiter struct {
	rate     float64 // tokens per second
	burst    float64
	capacity int
	now      func() time.Time

	mu      sync.Mutex
	buckets map[netip.Prefix]bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter returns a limiter; rate <= 0 disables it (Allow is
// always true). A nil now means time.Now.
func NewRateLimiter(rate float64, burst int, now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{rate: rate, burst: float64(max(burst, 1)), capacity: 100_000, now: now,
		buckets: make(map[netip.Prefix]bucket)}
}

// Allow takes one token from ip's prefix bucket, reporting whether one was
// available. A nil limiter allows everything.
func (r *RateLimiter) Allow(ip netip.Addr) bool {
	if r == nil || r.rate <= 0 {
		return true
	}
	k := PrefixOf(ip)
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[k]
	if !ok {
		if len(r.buckets) >= r.capacity {
			r.evictLocked(now)
		}
		b = bucket{tokens: r.burst, last: now}
	} else if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = min(r.burst, b.tokens+dt*r.rate)
		b.last = now
	}
	if b.tokens < 1 {
		r.buckets[k] = b
		return false
	}
	b.tokens--
	r.buckets[k] = b
	return true
}

// evictLocked drops buckets that have refilled completely (indistinguishable
// from a fresh one), then, if still full, an arbitrary tenth of the rest.
func (r *RateLimiter) evictLocked(now time.Time) {
	full := time.Duration(r.burst / r.rate * float64(time.Second))
	for k, b := range r.buckets {
		if now.Sub(b.last) >= full {
			delete(r.buckets, k)
		}
	}
	drop := len(r.buckets) - r.capacity + r.capacity/10
	for k := range r.buckets {
		if drop <= 0 {
			break
		}
		delete(r.buckets, k)
		drop--
	}
}

// Len is the number of tracked prefixes (for /metrics).
func (r *RateLimiter) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}
