package drip

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestPrefixCap(t *testing.T) {
	l := NewLimiter(100, 100, 5).WithPrefixCap(3)
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	// Three different IPs in one /24 fill the prefix; a fourth is refused
	// even though its own per-IP count is zero.
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if !l.Acquire(a(ip), 0) {
			t.Fatalf("%s refused", ip)
		}
	}
	if l.Acquire(a("198.51.100.4"), 0) {
		t.Fatal("prefix cap not enforced")
	}
	if !l.Acquire(a("198.51.101.1"), 0) {
		t.Fatal("a different /24 must be unaffected")
	}
	// IPv6: one /48 shared across /64s.
	l6 := NewLimiter(100, 100, 5).WithPrefixCap(1)
	if !l6.Acquire(a("2001:db8:1:1::1"), 0) || l6.Acquire(a("2001:db8:1:2::1"), 0) {
		t.Fatal("v6 /48 prefix cap")
	}
	// Releases drain the prefix map.
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.101.1"} {
		l.Release(a(ip), 0)
	}
	if n := l.prefixCount(); n != 0 || l.Active() != 0 {
		t.Fatalf("prefix map not drained: %d active %d", n, l.Active())
	}
	if !l.Acquire(a("198.51.100.4"), 0) {
		t.Fatal("slot not freed")
	}
	// Default (no WithPrefixCap) is unlimited.
	u := NewLimiter(100, 100, 100)
	for i := range 50 {
		if !u.Acquire(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 0) {
			t.Fatal("default prefix cap must be unlimited")
		}
	}
	if PrefixOf(a("::ffff:192.0.2.9")).String() != "192.0.2.0/24" {
		t.Error("4in6 must use the IPv4 /24")
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := NewRateLimiter(2, 5, func() time.Time { return now })
	ip := netip.MustParseAddr("203.0.113.9")
	same24 := netip.MustParseAddr("203.0.113.200")
	for i := range 5 {
		if !r.Allow(ip) {
			t.Fatalf("burst request %d refused", i)
		}
	}
	if r.Allow(same24) {
		t.Fatal("rotating inside the /24 must share the bucket")
	}
	if !r.Allow(netip.MustParseAddr("203.0.114.1")) {
		t.Fatal("other /24 must have its own bucket")
	}
	now = now.Add(time.Second) // +2 tokens
	for i, want := range []bool{true, true, false} {
		if got := r.Allow(ip); got != want {
			t.Fatalf("refill at 2/s: request %d allowed=%v", i, got)
		}
	}
	now = now.Add(time.Hour) // refills to burst, not beyond
	for i := range 5 {
		if !r.Allow(ip) {
			t.Fatalf("after long idle, request %d refused", i)
		}
	}
	if r.Allow(ip) {
		t.Fatal("tokens must cap at burst")
	}
	var nr *RateLimiter
	if !nr.Allow(ip) || !NewRateLimiter(0, 1, nil).Allow(ip) {
		t.Fatal("nil or rate<=0 must allow everything")
	}
}

func TestRateLimiterBoundedAndConcurrent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	r := NewRateLimiter(1, 1, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	r.capacity = 100
	for i := range 1000 {
		r.Allow(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}))
	}
	if r.Len() > 100 {
		t.Fatalf("capacity exceeded: %d", r.Len())
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 500 {
				r.Allow(netip.AddrFrom4([4]byte{172, 16, byte(g), byte(i)}))
			}
		})
	}
	wg.Wait()
}
