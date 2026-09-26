package logstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "lawn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func count(t *testing.T, s *Store, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := s.DB().QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func req(ip, ua, path string, start, end int64, viol bool, depth int) Request {
	return Request{TsStart: start, TsEnd: end, IP: ip, UserAgent: ua, Method: "GET", Path: path,
		Depth: depth, IsViolation: viol, BytesSent: 100, Dripped: true, Status: 200, ASN: 64500, ASNOrg: "EXAMPLE-AS"}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWriterBatchFull(t *testing.T) {
	s := openTemp(t)
	// Huge flush interval: only a full batch triggers a write.
	w := NewWriter(s, 100, 3, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	for i := range 3 {
		if !w.LogRequest(req("192.0.2.1", "ua", "/lawn/x", int64(i), 0, true, 1)) {
			t.Fatal("dropped")
		}
	}
	waitFor(t, func() bool { return w.Stats().Written == 3 })
	if n := count(t, s, "SELECT COUNT(*) FROM requests"); n != 3 {
		t.Fatalf("rows=%d", n)
	}
	// Two more rows stay buffered (batch not full, no tick) until shutdown.
	w.LogRequest(req("192.0.2.1", "ua", "/lawn/y", 10, 0, true, 1))
	w.LogRobots(RobotsFetch{IP: "192.0.2.1", UserAgent: "ua", Ts: 9})
	time.Sleep(50 * time.Millisecond)
	if n := count(t, s, "SELECT COUNT(*) FROM requests"); n != 3 {
		t.Fatalf("partial batch written early: %d", n)
	}
	cancel()
	<-done
	if n := count(t, s, "SELECT COUNT(*) FROM requests"); n != 4 {
		t.Fatalf("after drain rows=%d", n)
	}
	if n := count(t, s, "SELECT COUNT(*) FROM robots_fetches"); n != 1 {
		t.Fatalf("robots=%d", n)
	}
	st := w.Stats()
	if st.Written != 5 || st.Dropped != 0 || st.Errors != 0 || st.Queued != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestWriterFlushInterval(t *testing.T) {
	s := openTemp(t)
	w := NewWriter(s, 100, 1000, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	w.LogRequest(req("192.0.2.1", "ua", "/", 1, 0, false, -1))
	w.LogRobots(RobotsFetch{IP: "192.0.2.1", Ts: 1})
	waitFor(t, func() bool { return w.Stats().Written == 2 })
	var depth any
	if err := s.DB().QueryRow("SELECT depth FROM requests").Scan(&depth); err != nil || depth != nil {
		t.Fatalf("depth should be NULL: %v %v", depth, err)
	}
}

func TestWriterNonBlockingDrop(t *testing.T) {
	s := openTemp(t)
	w := NewWriter(s, 2, 10, time.Hour) // Run never started
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 10 {
			w.LogRequest(req("192.0.2.1", "ua", "/lawn/x", int64(i), 0, true, 1))
			w.LogRobots(RobotsFetch{IP: "192.0.2.1", Ts: int64(i)})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("LogRequest blocked")
	}
	st := w.Stats()
	if st.Dropped != 16 || st.Queued != 4 {
		t.Fatalf("stats %+v", st)
	}
	if w.LogRequest(Request{}) {
		t.Fatal("expected false when full")
	}
}

func TestWriterDrainOnShutdown(t *testing.T) {
	s := openTemp(t)
	w := NewWriter(s, 1000, 7, time.Hour)
	for i := range 500 {
		w.LogRequest(req("192.0.2.1", "ua", "/lawn/x", int64(i), 0, true, 1))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: Run must still drain everything queued.
	w.Run(ctx)
	if n := count(t, s, "SELECT COUNT(*) FROM requests"); n != 500 {
		t.Fatalf("rows=%d", n)
	}
	if st := w.Stats(); st.Written != 500 || st.Queued != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestWriterErrorsCounted(t *testing.T) {
	s := openTemp(t)
	w := NewWriter(s, 10, 10, time.Hour)
	s.Close() // every insert now fails
	w.LogRequest(req("192.0.2.1", "ua", "/", 1, 0, false, -1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.Run(ctx)
	if st := w.Stats(); st.Errors != 1 || st.Written != 0 {
		t.Fatalf("stats %+v", st)
	}
}
