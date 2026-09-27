package logstore

import (
	"context"
	"testing"
	"time"
)

type aggRow struct {
	pages, held, bytes, maxDepth, sessions, readRules, first, last int64
	asn                                                            int64
	asnOrg                                                         string
}

func getAgg(t *testing.T, s *Store, day, ip, ua string) (aggRow, bool) {
	t.Helper()
	var a aggRow
	err := s.DB().QueryRow(`SELECT pages, held_ms, bytes_sent, max_depth, sessions, read_rules, first_ts, last_ts, asn, asn_org
	 FROM daily_aggregates WHERE day=? AND ip=? AND user_agent=?`, day, ip, ua).
		Scan(&a.pages, &a.held, &a.bytes, &a.maxDepth, &a.sessions, &a.readRules, &a.first, &a.last, &a.asn, &a.asnOrg)
	if err != nil {
		return a, false
	}
	return a, true
}

func at(day string, hh, mm int) int64 {
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		panic(err)
	}
	return t.Add(time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute).UnixMilli()
}

func TestRetentionCutoff(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 30, 0, 0, time.FixedZone("x", -5*3600))
	got := RetentionCutoff(now, 90)
	want := time.Date(2026, 3, 12, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRollup(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC) // cutoff 2026-03-12
	const gap = 10 * minute
	const ipA, uaA = "192.0.2.1", "BotA"
	d1, d2, d3 := "2026-03-10", "2026-03-11", "2026-03-12"
	s1 := 1000 * int64(1)
	rows := []Request{
		req(ipA, uaA, "/robots.txt", at(d1, 10, 0), at(d1, 10, 0), false, -1),
		req(ipA, uaA, "/lawn/a", at(d1, 10, 1), at(d1, 10, 1)+60*s1, true, 1),
		req(ipA, uaA, "/lawn/b", at(d1, 10, 5), at(d1, 10, 5)+30*s1, true, 3),
		req(ipA, uaA, "/lawn/c", at(d1, 14, 0), at(d1, 14, 0)+10*s1, true, 2),
		req(ipA, uaA, "/lawn/d", at(d1, 23, 58), at(d1, 23, 59), true, 1),
		// continues the 23:58 session across midnight
		req(ipA, uaA, "/lawn/e", at(d2, 0, 3), at(d2, 0, 4), true, 2),
		req(ipA, uaA, "/lawn/f", at(d2, 5, 0), 0, true, 1), // never finished
		// after the cutoff: stays raw
		req(ipA, uaA, "/lawn/g", at(d3, 1, 0), at(d3, 1, 1), true, 1),
		// non-violator: deleted, no aggregate
		req("198.51.100.7", "", "/", at(d1, 9, 0), at(d1, 9, 0), false, -1),
	}
	if err := s.InsertRequests(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertRobotsFetches(ctx, []RobotsFetch{
		{IP: ipA, UserAgent: uaA, Ts: at(d1, 10, 0)},
		{IP: ipA, UserAgent: uaA, Ts: at(d3, 0, 0)},
	}); err != nil {
		t.Fatal(err)
	}

	n, err := s.Rollup(ctx, now, 90, gap)
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Fatalf("rolled %d want 8", n)
	}
	a1, ok := getAgg(t, s, d1, ipA, uaA)
	if !ok {
		t.Fatal("no d1 aggregate")
	}
	want1 := aggRow{pages: 4, held: 160 * s1, bytes: 400, maxDepth: 3, sessions: 3, readRules: 1,
		first: at(d1, 10, 1), last: at(d1, 23, 59), asn: 64500, asnOrg: "EXAMPLE-AS"}
	if a1 != want1 {
		t.Fatalf("d1\n got %+v\nwant %+v", a1, want1)
	}
	a2, ok := getAgg(t, s, d2, ipA, uaA)
	if !ok {
		t.Fatal("no d2 aggregate")
	}
	want2 := aggRow{pages: 2, held: 60 * s1, bytes: 200, maxDepth: 2, sessions: 1, readRules: 0,
		first: at(d2, 0, 3), last: at(d2, 5, 0), asn: 64500, asnOrg: "EXAMPLE-AS"}
	if a2 != want2 {
		t.Fatalf("d2\n got %+v\nwant %+v", a2, want2)
	}
	if c := count(t, s, "SELECT COUNT(*) FROM daily_aggregates"); c != 2 {
		t.Fatalf("aggregates=%d", c)
	}
	if c := count(t, s, "SELECT COUNT(*) FROM requests"); c != 1 {
		t.Fatalf("remaining requests=%d", c)
	}
	if c := count(t, s, "SELECT COUNT(*) FROM robots_fetches"); c != 1 {
		t.Fatalf("remaining robots=%d", c)
	}

	// Idempotent.
	n, err = s.Rollup(ctx, now, 90, gap)
	if err != nil || n != 0 {
		t.Fatalf("second rollup n=%d err=%v", n, err)
	}
	if a, _ := getAgg(t, s, d1, ipA, uaA); a != want1 {
		t.Fatalf("changed on rerun: %+v", a)
	}

	// Late row for an already-rolled day merges.
	if err := s.InsertRequests(ctx, []Request{req(ipA, uaA, "/lawn/late", at(d1, 12, 0), at(d1, 12, 0)+5*s1, true, 9)}); err != nil {
		t.Fatal(err)
	}
	n, err = s.Rollup(ctx, now, 90, gap)
	if err != nil || n != 1 {
		t.Fatalf("merge rollup n=%d err=%v", n, err)
	}
	a1, _ = getAgg(t, s, d1, ipA, uaA)
	want1.pages, want1.held, want1.bytes, want1.maxDepth, want1.sessions = 5, 165*s1, 500, 9, 4
	if a1 != want1 {
		t.Fatalf("merged\n got %+v\nwant %+v", a1, want1)
	}
}

func TestRollupReadRulesOnlyBeforeFirstLawn(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	now := time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)
	d := "2026-01-05"
	if err := s.InsertRequests(ctx, []Request{
		req("192.0.2.9", "B", "/lawn/a", at(d, 1, 0), at(d, 1, 1), true, 0),
		req("192.0.2.9", "B", "/robots.txt", at(d, 1, 2), at(d, 1, 2), false, -1),
		req("192.0.2.9", "B", "/lawn/b", at(d, 1, 3), at(d, 1, 4), true, 1),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollup(ctx, now, 30, 10*minute); err != nil {
		t.Fatal(err)
	}
	a, ok := getAgg(t, s, d, "192.0.2.9", "B")
	if !ok || a.sessions != 1 || a.readRules != 0 || a.pages != 2 {
		t.Fatalf("%+v ok=%v", a, ok)
	}
}

func TestRollupArgs(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Rollup(context.Background(), time.Now(), 0, 1); err == nil {
		t.Fatal("keepDays 0 accepted")
	}
	if _, err := s.Rollup(context.Background(), time.Now(), 1, 0); err == nil {
		t.Fatal("gap 0 accepted")
	}
}

func TestPruneIdentities(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	for _, id := range []Identity{
		{IP: "192.0.2.1", UserAgent: "a", Status: StatusAnonymous, Method: MethodNone, CheckedAt: old}, // orphan: pruned
		{IP: "192.0.2.2", UserAgent: "b", Status: StatusAnonymous, Method: MethodNone, CheckedAt: old}, // has request
		{IP: "192.0.2.3", UserAgent: "c", Status: StatusVerified, Method: MethodRDNS, CheckedAt: old},  // has aggregate
		{IP: "192.0.2.4", UserAgent: "d", Status: StatusAnonymous, Method: MethodNone, CheckedAt: old + 10*dayMs},
	} {
		if err := s.UpsertIdentity(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.InsertRequests(ctx, []Request{req("192.0.2.2", "b", "/", 1, 1, false, -1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO daily_aggregates (day, ip, user_agent, pages, held_ms, bytes_sent, sessions, read_rules, first_ts, last_ts)
	 VALUES ('2025-01-01','192.0.2.3','c',1,0,0,1,0,0,0)`); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneIdentities(ctx, time.UnixMilli(old+dayMs))
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, ok, _ := s.GetIdentity(ctx, "192.0.2.1", "a"); ok {
		t.Fatal("orphan not pruned")
	}
}

func TestRollupDailyVisitsKeepsEveryVisitor(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC) // cutoff 2026-03-12
	d1 := "2026-03-10"
	good, bad := "GoodBot/1.0", "BadBot/1.0"
	rows := []Request{
		// A compliant bot: reads robots.txt, sees the bait pages, never enters /lawn/.
		req("192.0.2.10", good, "/robots.txt", at(d1, 8, 0), at(d1, 8, 0), false, -1),
		req("192.0.2.10", good, "/", at(d1, 8, 1), at(d1, 8, 1)+5, false, -1),
		req("192.0.2.10", good, "/sitemap.xml", at(d1, 8, 2), at(d1, 8, 2), false, -1),
		req("192.0.2.10", good, "/shame/", at(d1, 9, 0), at(d1, 9, 0), false, -1),
		// A HEAD returns no body: counted as a request, not as reading robots.txt.
		{TsStart: at(d1, 8, 30), TsEnd: at(d1, 8, 30), IP: "192.0.2.10", UserAgent: good, Method: "HEAD", Path: "/robots.txt", Depth: -1},
		// A violator.
		req("192.0.2.20", bad, "/", at(d1, 10, 0), at(d1, 10, 0), false, -1),
		req("192.0.2.20", bad, "/lawn/x", at(d1, 10, 1), at(d1, 10, 3), true, 0),
	}
	if err := s.InsertRequests(ctx, rows); err != nil {
		t.Fatal(err)
	}
	for range 2 { // idempotent: the second run finds nothing left to roll
		if _, err := s.Rollup(ctx, now, 90, 10*minute); err != nil {
			t.Fatal(err)
		}
	}
	type visit struct{ requests, robots, bait, violations, first, last int64 }
	get := func(ip, ua string) visit {
		var v visit
		if err := s.DB().QueryRow(`SELECT requests, robots, bait_views, violations, first_ts, last_ts
		 FROM daily_visits WHERE day=? AND ip=? AND user_agent=?`, d1, ip, ua).
			Scan(&v.requests, &v.robots, &v.bait, &v.violations, &v.first, &v.last); err != nil {
			t.Fatalf("%s: %v", ua, err)
		}
		return v
	}
	if g := get("192.0.2.10", good); g != (visit{5, 1, 2, 0, at(d1, 8, 0), at(d1, 9, 0)}) {
		t.Errorf("compliant bot: %+v", g)
	}
	if b := get("192.0.2.20", bad); b != (visit{2, 0, 1, 1, at(d1, 10, 0), at(d1, 10, 3)}) {
		t.Errorf("violator: %+v", b)
	}
	var raw int
	s.DB().QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&raw)
	if raw != 0 {
		t.Errorf("raw rows left: %d", raw)
	}
}

func TestHosts(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	if _, ok, err := s.GetHost(ctx, "192.0.2.1"); ok || err != nil {
		t.Fatalf("empty: ok=%v err=%v", ok, err)
	}
	if err := s.UpsertHost(ctx, Host{IP: "192.0.2.1", PTR: "crawl-1.example.net", CheckedAt: 5}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertHost(ctx, Host{IP: "192.0.2.1", PTR: "", CheckedAt: 9}); err != nil {
		t.Fatal(err)
	}
	h, ok, err := s.GetHost(ctx, "192.0.2.1")
	if !ok || err != nil || h.PTR != "" || h.CheckedAt != 9 {
		t.Fatalf("got %+v ok=%v err=%v", h, ok, err)
	}
}
