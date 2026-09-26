package drip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock advances instantly: every timer fires as soon as it is armed,
// moving the clock forward by its duration. In manual mode timers never
// fire.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	waits  []time.Duration
	record bool
	manual bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), record: true}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	t := &fakeTimer{c: c, ch: make(chan time.Time, 1)}
	t.Reset(d)
	return t
}

func (c *fakeClock) totalWait() time.Duration {
	var s time.Duration
	for _, w := range c.waits {
		s += w
	}
	return s
}

type fakeTimer struct {
	c  *fakeClock
	ch chan time.Time
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }
func (t *fakeTimer) Stop() bool          { return true }
func (t *fakeTimer) Reset(d time.Duration) {
	c := t.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.record {
		c.waits = append(c.waits, d)
	}
	if c.manual {
		return
	}
	c.now = c.now.Add(d)
	select {
	case t.ch <- c.now:
	default:
	}
}

// recWriter records writes and flushes; it can fail the Nth write.
type recWriter struct {
	mu      sync.Mutex
	hdr     http.Header
	writes  []int
	body    bytes.Buffer
	flushes int
	failAt  int // 1-based write index that fails; 0 = never
	onWrite func()
}

func (w *recWriter) Header() http.Header {
	if w.hdr == nil {
		w.hdr = http.Header{}
	}
	return w.hdr
}
func (w *recWriter) WriteHeader(int) {}
func (w *recWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	if w.failAt > 0 && len(w.writes)+1 == w.failAt {
		w.writes = append(w.writes, 0)
		w.mu.Unlock()
		return 0, errors.New("boom")
	}
	w.writes = append(w.writes, len(p))
	w.body.Write(p)
	f := w.onWrite
	w.mu.Unlock()
	if f != nil {
		f()
	}
	return len(p), nil
}
func (w *recWriter) Flush() {
	w.mu.Lock()
	w.flushes++
	w.mu.Unlock()
}

func body(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

func TestDripChunksAndFlushes(t *testing.T) {
	clk := newFakeClock()
	eg := NewEgress(0, clk.Now)
	d := NewDripper(Options{ChunkBytes: 16, Interval: time.Second, MaxDuration: 10 * time.Minute, Jitter: -1}, clk, eg)
	w := &recWriter{}
	b := body(100)
	n, err := d.Drip(context.Background(), w, b, 1)
	if err != nil || n != 100 {
		t.Fatalf("Drip = %d, %v", n, err)
	}
	want := []int{16, 16, 16, 16, 16, 16, 4}
	if len(w.writes) != len(want) {
		t.Fatalf("writes %v want %v", w.writes, want)
	}
	for i := range want {
		if w.writes[i] != want[i] {
			t.Fatalf("writes %v want %v", w.writes, want)
		}
	}
	if w.flushes != 7 {
		t.Fatalf("flushes %d want 7", w.flushes)
	}
	if !bytes.Equal(w.body.Bytes(), b) {
		t.Fatal("body mismatch")
	}
	if len(clk.waits) != 6 || clk.totalWait() != 6*time.Second {
		t.Fatalf("waits %v", clk.waits)
	}
	if eg.Today() != 100 {
		t.Fatalf("egress %d", eg.Today())
	}
}

func TestDripJitterBounds(t *testing.T) {
	run := func(jitter float64, seed uint64) []time.Duration {
		clk := newFakeClock()
		d := NewDripper(Options{ChunkBytes: 1, Interval: time.Second, Jitter: jitter}, clk, nil)
		if _, err := d.Drip(context.Background(), &recWriter{}, body(1001), seed); err != nil {
			t.Fatal(err)
		}
		return clk.waits
	}
	waits := run(0, 42) // 0 = DefaultJitter
	if len(waits) != 1000 {
		t.Fatalf("%d waits", len(waits))
	}
	lo, hi := time.Duration(1<<62), time.Duration(0)
	for _, w := range waits {
		if w < 700*time.Millisecond || w > 1300*time.Millisecond {
			t.Fatalf("wait %v outside ±30%%", w)
		}
		lo, hi = min(lo, w), max(hi, w)
	}
	if lo > 750*time.Millisecond || hi < 1250*time.Millisecond {
		t.Fatalf("jitter poorly spread: %v..%v", lo, hi)
	}
	again := run(0, 42)
	other := run(0, 43)
	same, diff := true, false
	for i := range waits {
		same = same && waits[i] == again[i]
		diff = diff || waits[i] != other[i]
	}
	if !same || !diff {
		t.Fatalf("jitter should be deterministic per seed (same=%v) and vary by seed (diff=%v)", same, diff)
	}
	for _, w := range run(-1, 42) {
		if w != time.Second {
			t.Fatalf("negative jitter should disable jitter, got %v", w)
		}
	}
	for _, w := range run(5, 42) {
		if w < 0 || w > 2*time.Second {
			t.Fatalf("jitter >1 should clamp to 1, got %v", w)
		}
	}
}

func TestDripMaxDuration(t *testing.T) {
	clk := newFakeClock()
	d := NewDripper(Options{ChunkBytes: 16, Interval: time.Second, MaxDuration: 5 * time.Second, Jitter: -1}, clk, nil)
	w := &recWriter{}
	n, err := d.Drip(context.Background(), w, body(1000), 1)
	if err != nil || n != 1000 {
		t.Fatalf("Drip = %d, %v", n, err)
	}
	if got := len(w.writes); got != 6 || w.writes[5] != 1000-5*16 {
		t.Fatalf("writes %v: want 5 chunks then remainder", w.writes)
	}
	if clk.totalWait() != 5*time.Second {
		t.Fatalf("total wait %v want 5s", clk.totalWait())
	}

	// With jitter, the last wait is trimmed so the cutoff lands on time.
	clk = newFakeClock()
	d = NewDripper(Options{ChunkBytes: 1, Interval: time.Second, MaxDuration: 5 * time.Second}, clk, nil)
	if _, err := d.Drip(context.Background(), &recWriter{}, body(1000), 7); err != nil {
		t.Fatal(err)
	}
	if clk.totalWait() != 5*time.Second {
		t.Fatalf("jittered total wait %v want exactly 5s", clk.totalWait())
	}
}

func TestDripContextCancel(t *testing.T) {
	clk := newFakeClock()
	clk.manual = true
	d := NewDripper(Options{ChunkBytes: 16, Interval: time.Hour}, clk, nil)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan struct{}, 1)
	w := &recWriter{onWrite: func() {
		select {
		case first <- struct{}{}:
		default:
		}
	}}
	done := make(chan error, 1)
	var n int64
	go func() {
		var err error
		n, err = d.Drip(ctx, w, body(1000), 1)
		done <- err
	}()
	<-first
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || n != 16 {
			t.Fatalf("Drip = %d, %v", n, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Drip did not stop after cancel")
	}

	// Already-cancelled context writes nothing.
	n, err := d.Drip(ctx, &recWriter{}, body(10), 1)
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled Drip = %d, %v", n, err)
	}
}

func TestDripWriteError(t *testing.T) {
	clk := newFakeClock()
	eg := NewEgress(0, clk.Now)
	d := NewDripper(Options{ChunkBytes: 16, Interval: time.Second}, clk, eg)
	w := &recWriter{failAt: 3}
	n, err := d.Drip(context.Background(), w, body(1000), 1)
	if err == nil || n != 32 {
		t.Fatalf("Drip = %d, %v; want 32 and error", n, err)
	}
	if len(w.writes) != 3 || eg.Today() != 32 {
		t.Fatalf("writes %v egress %d", w.writes, eg.Today())
	}
}

func TestFastAndZeroInterval(t *testing.T) {
	eg := NewEgress(0, nil)
	d := NewDripper(Options{ChunkBytes: 16}, nil, eg)
	w := &recWriter{}
	if n, err := d.Fast(w, body(500)); n != 500 || err != nil {
		t.Fatalf("Fast = %d, %v", n, err)
	}
	if n, err := d.Drip(context.Background(), w, body(500), 1); n != 500 || err != nil {
		t.Fatalf("Drip with zero interval = %d, %v", n, err)
	}
	if len(w.writes) != 2 || eg.Today() != 1000 {
		t.Fatalf("writes %v egress %d", w.writes, eg.Today())
	}
	// Nil egress is allowed.
	if n, _ := NewDripper(Options{}, nil, nil).Fast(&recWriter{}, body(3)); n != 3 {
		t.Fatal("Fast with nil egress")
	}
}

type discardWriter struct{ h http.Header }

func (w *discardWriter) Header() http.Header         { return w.h }
func (w *discardWriter) WriteHeader(int)             {}
func (w *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *discardWriter) Flush()                      {}

func TestDripNoPerChunkAllocs(t *testing.T) {
	clk := newFakeClock()
	clk.record = false
	d := NewDripper(Options{ChunkBytes: 16, Interval: time.Second}, clk, NewEgress(0, clk.Now))
	w := &discardWriter{h: http.Header{}}
	small, large := body(16*10), body(16*1000)
	ctx := context.Background()
	a1 := testing.AllocsPerRun(20, func() { d.Drip(ctx, w, small, 1) })
	a2 := testing.AllocsPerRun(20, func() { d.Drip(ctx, w, large, 1) })
	if a2 > a1 || a2 > 8 {
		t.Fatalf("allocs grow with chunk count: 10 chunks=%.1f, 1000 chunks=%.1f", a1, a2)
	}
}

// TestDripRealSocket checks against a real HTTP server that the client
// sees bytes before the body is done, and that a disconnect ends Drip fast.
func TestDripRealSocket(t *testing.T) {
	d := NewDripper(Options{ChunkBytes: 16, Interval: 5 * time.Millisecond, MaxDuration: time.Minute}, RealClock{}, nil)
	page := body(16 * 400) // ~2s of dripping
	var finished atomic.Bool
	type result struct {
		n   int64
		err error
		at  time.Time
	}
	res := make(chan result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		http.NewResponseController(w).Flush()
		n, err := d.Drip(r.Context(), w, page, 99)
		finished.Store(true)
		res <- result{n, err, time.Now()}
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	got := 0
	for got < 48 {
		n, err := resp.Body.Read(buf)
		got += n
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if finished.Load() {
		t.Fatal("handler finished before client read its first bytes")
	}
	closed := time.Now()
	resp.Body.Close()
	select {
	case r := <-res:
		if r.err == nil || r.n >= int64(len(page)) {
			t.Fatalf("Drip = %d, %v; want early stop with error", r.n, r.err)
		}
		if lag := r.at.Sub(closed); lag > 500*time.Millisecond {
			t.Fatalf("Drip took %v to notice disconnect", lag)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Drip did not stop after client disconnect")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
}
