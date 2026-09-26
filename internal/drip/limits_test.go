package drip

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

var (
	ipA = netip.MustParseAddr("192.0.2.1")
	ipB = netip.MustParseAddr("192.0.2.2")
	ipC = netip.MustParseAddr("198.51.100.7")
)

func TestLimiterPerIP(t *testing.T) {
	l := NewLimiter(100, 100, 2)
	for range 2 {
		if !l.Acquire(ipA, 1) {
			t.Fatal("first two should succeed")
		}
	}
	if l.Acquire(ipA, 1) {
		t.Fatal("third from same IP should fail")
	}
	if !l.Acquire(ipB, 1) {
		t.Fatal("other IP should succeed")
	}
	if l.Active() != 3 {
		t.Fatalf("active %d", l.Active())
	}
	l.Release(ipA, 1)
	if !l.Acquire(ipA, 1) {
		t.Fatal("should succeed after release")
	}
	// IPv4-mapped IPv6 is the same client.
	if l.Acquire(netip.MustParseAddr("::ffff:192.0.2.1"), 1) {
		t.Fatal("mapped address should share the IPv4 bucket")
	}
}

func TestLimiterIPv6Slash64(t *testing.T) {
	l := NewLimiter(100, 100, 2)
	a := netip.MustParseAddr("2001:db8:1:2::1")
	b := netip.MustParseAddr("2001:db8:1:2:ffff::9")
	c := netip.MustParseAddr("2001:db8:1:3::1")
	if !l.Acquire(a, 0) || !l.Acquire(b, 0) {
		t.Fatal("first two in /64 should succeed")
	}
	if l.Acquire(netip.MustParseAddr("2001:db8:1:2::abcd"), 0) {
		t.Fatal("third in same /64 should fail")
	}
	if !l.Acquire(c, 0) {
		t.Fatal("different /64 should succeed")
	}
	l.Release(a, 0)
	l.Release(b, 0)
	l.Release(c, 0)
	if ips, _ := l.sizes(); ips != 0 || l.Active() != 0 {
		t.Fatalf("not emptied: ips=%d active=%d", ips, l.Active())
	}
}

func TestLimiterPerASN(t *testing.T) {
	l := NewLimiter(100, 2, 10)
	if !l.Acquire(ipA, 64500) || !l.Acquire(ipB, 64500) {
		t.Fatal("first two in ASN should succeed")
	}
	if l.Acquire(ipC, 64500) {
		t.Fatal("third in ASN should fail")
	}
	if l.Active() != 2 {
		t.Fatalf("failed Acquire must hold nothing, active=%d", l.Active())
	}
	if !l.Acquire(ipC, 64501) {
		t.Fatal("other ASN should succeed")
	}
	// Unknown ASN (0) skips the per-ASN cap.
	for i := range 5 {
		ip := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})
		if !l.Acquire(ip, 0) {
			t.Fatalf("asn 0 acquire %d failed", i)
		}
	}
	if _, asns := l.sizes(); asns != 2 {
		t.Fatalf("asn 0 must not be tracked, asns=%d", asns)
	}
}

func TestLimiterGlobal(t *testing.T) {
	l := NewLimiter(3, 100, 100)
	for i := range 3 {
		if !l.Acquire(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), uint32(i+1)) {
			t.Fatal("under global cap should succeed")
		}
	}
	if l.Acquire(ipA, 99) {
		t.Fatal("over global cap should fail")
	}
	if ips, asns := l.sizes(); ips != 3 || asns != 3 {
		t.Fatalf("failed Acquire leaked entries: ips=%d asns=%d", ips, asns)
	}
}

func TestLimiterUnmatchedRelease(t *testing.T) {
	l := NewLimiter(10, 10, 10)
	l.Release(ipA, 5)
	if l.Active() != 0 {
		t.Fatal("unmatched release changed active")
	}
	if !l.Acquire(ipA, 5) {
		t.Fatal("acquire failed")
	}
	l.Release(ipA, 5)
	l.Release(ipA, 5)
	if ips, asns := l.sizes(); l.Active() != 0 || ips != 0 || asns != 0 {
		t.Fatal("double release corrupted state")
	}
}

func TestLimiterZeroCapsUnlimited(t *testing.T) {
	l := NewLimiter(0, -1, 0)
	for range 1000 {
		if !l.Acquire(ipA, 1) {
			t.Fatal("caps <= 0 should be unlimited")
		}
	}
}

func TestLimiterConcurrent(t *testing.T) {
	const global, perASN, perIP = 50, 20, 3
	l := NewLimiter(global, perASN, perIP)
	var wg sync.WaitGroup
	var mu sync.Mutex
	peak := 0
	for g := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{10, 1, byte(g % 16), 1})
			asn := uint32(g%4) + 1
			for range 500 {
				if l.Acquire(ip, asn) {
					if a := l.Active(); a > global {
						t.Errorf("active %d over global cap", a)
					}
					mu.Lock()
					peak = max(peak, l.Active())
					mu.Unlock()
					l.Release(ip, asn)
				}
			}
		}()
	}
	wg.Wait()
	ips, asns := l.sizes()
	if l.Active() != 0 || ips != 0 || asns != 0 {
		t.Fatalf("after release: active=%d ips=%d asns=%d", l.Active(), ips, asns)
	}
	if peak == 0 {
		t.Fatal("nothing ever acquired")
	}
}

func TestEgressRollover(t *testing.T) {
	now := time.Date(2026, 3, 1, 23, 59, 59, 0, time.UTC)
	e := NewEgress(1000, func() time.Time { return now })
	e.Add(600)
	if e.Exceeded() || e.Today() != 600 {
		t.Fatalf("today %d", e.Today())
	}
	e.Add(400)
	if !e.Exceeded() {
		t.Fatal("should be exceeded at cap")
	}
	now = now.Add(time.Second) // UTC midnight
	if e.Exceeded() || e.Today() != 0 {
		t.Fatalf("should reset at UTC midnight, today=%d", e.Today())
	}
	e.Add(10)
	now = now.Add(-2 * time.Second) // clock steps back: no reset
	if e.Today() != 10 {
		t.Fatalf("backwards clock reset counter: %d", e.Today())
	}
}

func TestEgressUsesUTC(t *testing.T) {
	// 09:00 in UTC+10 on Mar 2 is 23:00 UTC on Mar 1.
	zone := time.FixedZone("plus10", 10*3600)
	now := time.Date(2026, 3, 2, 9, 0, 0, 0, zone)
	e := NewEgress(0, func() time.Time { return now })
	e.Add(5)
	now = time.Date(2026, 3, 2, 9, 59, 0, 0, zone) // still Mar 1 UTC
	if e.Today() != 5 {
		t.Fatal("reset on local-date change instead of UTC")
	}
	now = time.Date(2026, 3, 2, 10, 0, 0, 0, zone) // Mar 2 00:00 UTC
	if e.Today() != 0 {
		t.Fatal("did not reset at UTC midnight")
	}
}

func TestEgressCapDisabled(t *testing.T) {
	for _, c := range []int64{0, -1} {
		e := NewEgress(c, nil)
		e.Add(1 << 40)
		if e.Exceeded() {
			t.Fatalf("cap %d should disable Exceeded", c)
		}
		if e.Today() != 1<<40 {
			t.Fatal("bytes still counted when cap disabled")
		}
	}
	var nilE *Egress
	nilE.Add(5)
	if nilE.Exceeded() || nilE.Today() != 0 {
		t.Fatal("nil Egress should be a no-op")
	}
}

func TestEgressConcurrent(t *testing.T) {
	fixed := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	e := NewEgress(0, func() time.Time { return fixed })
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				e.Add(3)
			}
		}()
	}
	wg.Wait()
	if e.Today() != 16*1000*3 {
		t.Fatalf("today %d", e.Today())
	}
}

func BenchmarkLimiterParallel(b *testing.B) {
	l := NewLimiter(1<<20, 1<<20, 1<<20)
	b.RunParallel(func(pb *testing.PB) {
		ip := netip.AddrFrom4([4]byte{10, 0, 0, 1})
		for pb.Next() {
			if l.Acquire(ip, 7) {
				l.Release(ip, 7)
			}
		}
	})
}
