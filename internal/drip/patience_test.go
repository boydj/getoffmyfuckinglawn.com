package drip

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func TestKeyFor(t *testing.T) {
	a := KeyFor(netip.MustParseAddr("203.0.113.7"), 64500, "Bot/1")
	b := KeyFor(netip.MustParseAddr("198.51.100.9"), 64500, "Bot/1")
	if a != b {
		t.Errorf("same ASN+UA must share a key across IPs: %+v vs %+v", a, b)
	}
	c := KeyFor(netip.MustParseAddr("203.0.113.7"), 0, "Bot/1")
	d := KeyFor(netip.MustParseAddr("203.0.113.200"), 0, "Bot/1")
	e := KeyFor(netip.MustParseAddr("203.0.114.7"), 0, "Bot/1")
	if c != d || c == e || c.Net.String() != "203.0.113.0/24" {
		t.Errorf("unknown ASN keys by /24: %+v %+v %+v", c, d, e)
	}
	v6 := KeyFor(netip.MustParseAddr("2001:db8:1:2::9"), 0, "x")
	if v6.Net.String() != "2001:db8:1::/48" {
		t.Errorf("v6 key: %v", v6.Net)
	}
	long := KeyFor(netip.Addr{}, 1, strings.Repeat("u", 1000))
	if len(long.UA) != maxKeyUA {
		t.Errorf("UA not truncated: %d", len(long.UA))
	}
}

func TestPatienceLearnsAndProbes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := NewPatience(PatienceOptions{Max: 10 * time.Minute, Factor: 0.8, Now: func() time.Time { return now }})
	k := KeyFor(netip.MustParseAddr("203.0.113.7"), 64500, "Bot/1")

	if b := p.Budget(k); b != 10*time.Minute {
		t.Fatalf("unknown client gets Max, got %v", b)
	}
	// A patient client that waits out the whole budget is not tracked.
	p.Observe(k, 5*time.Minute, Completed)
	if p.Len() != 0 {
		t.Fatal("clients that never give up must not be tracked")
	}
	// It hangs up after 30s: next budget is 24s.
	p.Observe(k, 30*time.Second, ClientGone)
	if b := p.Budget(k); b != 24*time.Second {
		t.Fatalf("budget after 30s timeout: %v", b)
	}
	// Completing within budget nudges the estimate up by 2%.
	p.Observe(k, 24*time.Second, Completed)
	if b := p.Budget(k); b != time.Duration(float64(30*time.Second)*1.02*0.8) {
		t.Fatalf("probe up: %v", b)
	}
	// A later, shorter timeout wins.
	p.Observe(k, 10*time.Second, WriteFailed)
	if b := p.Budget(k); b != 8*time.Second {
		t.Fatalf("after 10s timeout: %v", b)
	}
	// Floor and cap.
	p.Observe(k, 10*time.Millisecond, ClientGone)
	if b := p.Budget(k); b != minBudget {
		t.Fatalf("floor: %v", b)
	}
	p.Observe(k, time.Hour, ClientGone)
	if b := p.Budget(k); b != 10*time.Minute {
		t.Fatalf("cap: %v", b)
	}
	// Forgotten after the TTL.
	p.Observe(k, 30*time.Second, ClientGone)
	now = now.Add(25 * time.Hour)
	if b := p.Budget(k); b != 10*time.Minute {
		t.Fatalf("expired entry must fall back to Max: %v", b)
	}
	// An expired entry doesn't feed the growth path.
	p.Observe(k, time.Minute, Completed)
	if b := p.Budget(k); b != 10*time.Minute {
		t.Fatalf("expired + completed: %v", b)
	}
}

func TestPatienceNilAndCapacity(t *testing.T) {
	var np *Patience
	if np.Budget(PatienceKey{}) != 0 || np.Len() != 0 {
		t.Fatal("nil tracker must be inert")
	}
	np.Observe(PatienceKey{}, time.Second, ClientGone) // must not panic

	p := NewPatience(PatienceOptions{Max: time.Minute, Capacity: 100})
	for i := range 1000 {
		p.Observe(PatienceKey{ASN: uint32(i + 1)}, time.Second, ClientGone)
	}
	if n := p.Len(); n > 100 {
		t.Fatalf("capacity exceeded: %d", n)
	}
}

func TestPatienceConcurrent(t *testing.T) {
	p := NewPatience(PatienceOptions{Max: time.Minute, Capacity: 50})
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				k := PatienceKey{ASN: uint32(g*1000 + i%100 + 1), UA: "x"}
				p.Observe(k, time.Duration(i)*time.Millisecond, Outcome(i%4))
				p.Budget(k)
			}
		}()
	}
	wg.Wait()
	if p.Len() > 50 {
		t.Fatalf("capacity exceeded: %d", p.Len())
	}
}

func TestDripWithLeadAndBudget(t *testing.T) {
	clk := newFakeClock() // timers fire at once, advancing the clock
	d := NewDripper(Options{ChunkBytes: 4, Interval: time.Second, MaxDuration: time.Hour, Jitter: -1}, clk, nil)
	w := &recWriter{}
	n, o, err := d.DripWith(context.Background(), w, body(100), 1, Plan{Lead: 40, MaxDuration: 3 * time.Second})
	if err != nil || n != 100 || o != CutOff {
		t.Fatalf("n=%d o=%v err=%v", n, o, err)
	}
	// Lead at once, a chunk per second until the 3s budget, then the rest.
	want := []int{40, 4, 4, 52}
	if len(w.writes) != len(want) {
		t.Fatalf("writes %v, want %v", w.writes, want)
	}
	for i := range want {
		if w.writes[i] != want[i] {
			t.Fatalf("writes %v, want %v", w.writes, want)
		}
	}
	if clk.totalWait() != 3*time.Second {
		t.Fatalf("waited %v, want the 3s budget", clk.totalWait())
	}
	if o.String() != "cutoff" || Completed.String() != "complete" || ClientGone.String() != "client_gone" ||
		WriteFailed.String() != "write_error" || Outcome(9).String() != "unknown" {
		t.Fatal("outcome names")
	}

	// Lead larger than the body: one write, Completed.
	w2 := &recWriter{}
	if n, o, err := d.DripWith(context.Background(), w2, body(10), 1, Plan{Lead: 400}); n != 10 || o != Completed || err != nil || len(w2.writes) != 1 {
		t.Fatalf("lead > body: n=%d o=%v err=%v writes=%v", n, o, err, w2.writes)
	}
	// Whole body within budget: Completed.
	if _, o, _ := d.DripWith(context.Background(), &recWriter{}, body(12), 1, Plan{}); o != Completed {
		t.Fatalf("short body: %v", o)
	}
	// Client gone.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, o, _ := d.DripWith(ctx, &recWriter{}, body(100), 1, Plan{}); o != ClientGone {
		t.Fatalf("canceled ctx: %v", o)
	}
	// Write failure.
	if _, o, _ := d.DripWith(context.Background(), &recWriter{failAt: 2}, body(100), 1, Plan{}); o != WriteFailed {
		t.Fatalf("write error: %v", o)
	}
}

func TestPatienceDoesNotPinLongUA(t *testing.T) {
	p := NewPatience(PatienceOptions{Max: time.Minute})
	huge := strings.Repeat("x", 16<<10)
	k := KeyFor(netip.MustParseAddr("203.0.113.1"), 1, huge)
	p.Observe(k, time.Second, ClientGone)
	for stored := range p.m {
		if unsafe.StringData(stored.UA) == unsafe.StringData(huge) {
			t.Fatal("stored key shares the original UA's memory")
		}
		if len(stored.UA) != maxKeyUA {
			t.Fatalf("stored UA len %d", len(stored.UA))
		}
	}
	if p.Budget(k) != 800*time.Millisecond {
		t.Fatalf("lookup with the sliced key must still hit: %v", p.Budget(k))
	}
}
