package drip

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Limiter caps concurrent dripped connections globally, per ASN and per
// client IP. It is safe for concurrent use.
//
// Semantics:
//   - asn == 0 means "unknown ASN": the per-ASN cap is skipped for that
//     connection (the global and per-IP caps still apply), so a missing
//     ASN database never lumps every client into one bucket.
//   - IPv4-mapped IPv6 addresses count as their IPv4 address, and IPv6
//     clients are keyed by their /64, since one host usually owns a whole
//     /64 and could otherwise rotate addresses to dodge the per-IP cap.
//   - A cap <= 0 means unlimited.
type Limiter struct {
	global, perASN, perIP int32

	mu     sync.Mutex
	active atomic.Int32 // written under mu, read lock-free by Active
	ips    map[netip.Addr]int32
	asns   map[uint32]int32
}

// NewLimiter returns a Limiter with the given caps.
func NewLimiter(global, perASN, perIP int) *Limiter {
	return &Limiter{
		global: clampCap(global),
		perASN: clampCap(perASN),
		perIP:  clampCap(perIP),
		ips:    make(map[netip.Addr]int32),
		asns:   make(map[uint32]int32),
	}
}

func clampCap(n int) int32 {
	if n <= 0 || n > 1<<30 {
		return 1 << 30
	}
	return int32(n)
}

// ipKey normalises an address to the unit the per-IP cap applies to.
func ipKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return ip
}

// Acquire takes a slot for (ip, asn). It returns false, holding nothing,
// if any cap is already reached. Every true must be paired with Release.
func (l *Limiter) Acquire(ip netip.Addr, asn uint32) bool {
	k := ipKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active.Load() >= l.global {
		return false
	}
	if asn != 0 && l.asns[asn] >= l.perASN {
		return false
	}
	if l.ips[k] >= l.perIP {
		return false
	}
	l.active.Add(1)
	if asn != 0 {
		l.asns[asn]++
	}
	l.ips[k]++
	return true
}

// Release returns a slot taken by a successful Acquire with the same
// arguments. Zeroed entries are deleted so the maps don't grow forever.
// An unmatched Release is ignored rather than driving counts negative.
func (l *Limiter) Release(ip netip.Addr, asn uint32) {
	k := ipKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	n, ok := l.ips[k]
	if !ok {
		return
	}
	if n <= 1 {
		delete(l.ips, k)
	} else {
		l.ips[k] = n - 1
	}
	if asn != 0 {
		if a := l.asns[asn]; a <= 1 {
			delete(l.asns, asn)
		} else {
			l.asns[asn] = a - 1
		}
	}
	if l.active.Load() > 0 {
		l.active.Add(-1)
	}
}

// Active returns the current number of held slots.
func (l *Limiter) Active() int { return int(l.active.Load()) }

// sizes reports map sizes (tests).
func (l *Limiter) sizes() (ips, asns int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ips), len(l.asns)
}

// Egress is a daily egress byte counter that resets at UTC midnight. It is
// safe for concurrent use; a nil *Egress is a no-op counter.
type Egress struct {
	capBytes int64
	now      func() time.Time
	day      atomic.Int64 // days since the Unix epoch (UTC) of the current count
	bytes    atomic.Int64
}

// NewEgress returns a counter with a daily cap. capBytes <= 0 disables the
// cap (Exceeded is always false). A nil now means time.Now.
func NewEgress(capBytes int64, now func() time.Time) *Egress {
	if now == nil {
		now = time.Now
	}
	e := &Egress{capBytes: capBytes, now: now}
	e.day.Store(utcDay(now()))
	return e
}

func utcDay(t time.Time) int64 {
	s := t.UTC().Unix()
	d := s / 86400
	if s%86400 < 0 {
		d-- // floor for pre-1970 clocks
	}
	return d
}

// roll resets the counter when the UTC date has moved forward. A clock
// stepping backwards does not reset it. Bytes added concurrently with a
// rollover may land on either day; that imprecision is acceptable.
func (e *Egress) roll() {
	d := utcDay(e.now())
	for {
		cur := e.day.Load()
		if d <= cur {
			return
		}
		if e.day.CompareAndSwap(cur, d) {
			e.bytes.Store(0)
			return
		}
	}
}

// Add records n bytes sent.
func (e *Egress) Add(n int64) {
	if e == nil || n <= 0 {
		return
	}
	e.roll()
	e.bytes.Add(n)
}

// Exceeded reports whether today's bytes have reached the cap.
func (e *Egress) Exceeded() bool {
	if e == nil || e.capBytes <= 0 {
		return false
	}
	e.roll()
	return e.bytes.Load() >= e.capBytes
}

// Today returns bytes sent since the last UTC midnight.
func (e *Egress) Today() int64 {
	if e == nil {
		return 0
	}
	e.roll()
	return e.bytes.Load()
}
