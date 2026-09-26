package logstore

import "testing"

const minute = int64(60_000)

func TestHeldMs(t *testing.T) {
	for _, c := range []struct{ s, e, want int64 }{
		{1000, 61000, 60000},
		{1000, 0, 0},   // never finished
		{1000, 500, 0}, // clock skew guard
		{1000, 1000, 0},
	} {
		if got := HeldMs(c.s, c.e); got != c.want {
			t.Errorf("HeldMs(%d,%d)=%d want %d", c.s, c.e, got, c.want)
		}
	}
}

func TestDeriveSessionsGap(t *testing.T) {
	gap := 10 * minute
	ev := []Event{
		{TsStart: 0, TsEnd: 0, IsRobots: true},
		{TsStart: 1 * minute, TsEnd: 11 * minute, IsViolation: true, Depth: 0, Bytes: 100}, // held 10m
		// starts 5m after previous END (but 15m after its start): same session
		{TsStart: 16 * minute, TsEnd: 17 * minute, IsViolation: true, Depth: 3, Bytes: 50},
		// 10m gap exactly: new session
		{TsStart: 27 * minute, TsEnd: 28 * minute, IsViolation: true, Depth: 1, Bytes: 10},
		{TsStart: 29 * minute, IsRobots: true},
		{TsStart: 30 * minute, TsEnd: 30*minute + 500, IsViolation: true, Depth: 2},
	}
	s := DeriveSessions(ev, gap)
	if len(s) != 2 {
		t.Fatalf("got %d sessions: %+v", len(s), s)
	}
	a, b := s[0], s[1]
	if a.Requests != 3 || a.Pages != 2 || a.HeldMs != 11*minute || a.Bytes != 150 || a.MaxDepth != 3 {
		t.Errorf("session a: %+v", a)
	}
	if !a.ReadRules || a.FirstLawn != 1*minute || a.Start != 0 || a.End != 17*minute {
		t.Errorf("session a flags: %+v", a)
	}
	// robots.txt fetched only AFTER the first lawn hit of session b.
	if b.ReadRules || b.Pages != 2 || b.HeldMs != minute+500 || b.MaxDepth != 2 {
		t.Errorf("session b: %+v", b)
	}
}

func TestDeriveSessionsNoViolations(t *testing.T) {
	s := DeriveSessions([]Event{{TsStart: 5, IsRobots: true}}, minute)
	if len(s) != 1 || s[0].Pages != 0 || s[0].FirstLawn != 0 || s[0].ReadRules {
		t.Fatalf("%+v", s)
	}
	if DeriveSessions(nil, minute) != nil {
		t.Fatal("nil in, nil out")
	}
}
