package shame

import (
	"context"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// Fixed fake clock for every test.
var testNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func fakeNow() time.Time { return testNow }

const testRobots = "User-agent: *\nDisallow: /lawn/\n"

func openStore(t *testing.T) *logstore.Store {
	t.Helper()
	s, err := logstore.Open(t.TempDir() + "/x.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// fx builds request fixtures relative to testNow.
type fx struct {
	rows []logstore.Request
	ids  []logstore.Identity
}

func ms(ago time.Duration) int64 { return testNow.Add(-ago).UnixMilli() }

// lawn adds a violation that started `ago` before now and was held `held`.
func (f *fx) lawn(ip, ua string, asn uint32, asnOrg string, ago, held time.Duration, depth int, bytes int64, path string) {
	start := ms(ago)
	f.rows = append(f.rows, logstore.Request{
		TsStart: start, TsEnd: start + held.Milliseconds(), IP: ip, ASN: asn, ASNOrg: asnOrg,
		UserAgent: ua, Method: "GET", Path: path, Depth: depth, IsViolation: true,
		BytesSent: bytes, Dripped: true, Status: 200,
	})
}

func (f *fx) robots(ip, ua string, asn uint32, asnOrg string, ago time.Duration) {
	start := ms(ago)
	f.rows = append(f.rows, logstore.Request{
		TsStart: start, TsEnd: start + 5, IP: ip, ASN: asn, ASNOrg: asnOrg, UserAgent: ua,
		Method: "GET", Path: "/robots.txt", Depth: -1, BytesSent: 30, Status: 200,
	})
}

func (f *fx) home(ip, ua string, ago time.Duration) {
	start := ms(ago)
	f.rows = append(f.rows, logstore.Request{
		TsStart: start, TsEnd: start + 5, IP: ip, UserAgent: ua, Method: "GET", Path: "/", Depth: -1, Status: 200,
	})
}

func (f *fx) id(ip, ua, org, status string) {
	f.ids = append(f.ids, logstore.Identity{IP: ip, UserAgent: ua, ClaimedOrg: org, Status: status,
		Method: logstore.MethodRDNS, CheckedAt: testNow.UnixMilli()})
}

func (f *fx) load(t *testing.T, s *logstore.Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.InsertRequests(ctx, f.rows); err != nil {
		t.Fatal(err)
	}
	for _, id := range f.ids {
		if err := s.UpsertIdentity(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
}

type dailyRow struct {
	day, ip, ua         string
	asn                 int64
	asnOrg              string
	pages, held, bytes  int64
	depth               int
	sessions, readRules int64
	first, last         int64
}

func insertDaily(t *testing.T, s *logstore.Store, rows ...dailyRow) {
	t.Helper()
	for _, r := range rows {
		_, err := s.DB().Exec(`INSERT INTO daily_aggregates (day, ip, user_agent, asn, asn_org, pages, held_ms,
		  bytes_sent, max_depth, sessions, read_rules, first_ts, last_ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.day, r.ip, r.ua, r.asn, r.asnOrg, r.pages, r.held, r.bytes, r.depth, r.sessions, r.readRules, r.first, r.last)
		if err != nil {
			t.Fatal(err)
		}
	}
}

const (
	uaAcme  = "AcmeBot/1.0 (+https://acme.example/bot)"
	uaByte  = "ByteThing/2.0"
	uaCurl  = "curl/8.0"
	uaNoise = "Mozilla/5.0 (X11; Linux x86_64)"
)

// standardFixture has one of each identity status (see TestCollect for the
// expected numbers).
func standardFixture(t *testing.T) *logstore.Store {
	t.Helper()
	s := openStore(t)
	var f fx
	// Verified Acme AI, IP .10: robots then two lawn hits in one session, 2h ago.
	f.robots("203.0.113.10", uaAcme, 64500, "ACME-AI", 2*time.Hour)
	f.lawn("203.0.113.10", uaAcme, 64500, "ACME-AI", 2*time.Hour-time.Minute, 10*time.Minute, 1, 100, "/lawn/AAAA")
	// starts 1m after the previous end: same session.
	f.lawn("203.0.113.10", uaAcme, 64500, "ACME-AI", 2*time.Hour-12*time.Minute, 5*time.Minute, 2, 50, "/lawn/archive/2019/BBBB")
	f.id("203.0.113.10", uaAcme, "Acme AI", logstore.StatusVerified)
	// Verified Acme AI, IP .11: one lawn hit 3 days ago, no robots.
	f.lawn("203.0.113.11", uaAcme, 64500, "ACME-AI", 72*time.Hour, 30*time.Minute, 5, 10, "/lawn/CCCC")
	f.id("203.0.113.11", uaAcme, "Acme AI", logstore.StatusVerified)

	// Spoofed "Acme AI" from a shady host, 60 hits 10 days ago, 1 min apart, 30s each.
	for i := 0; i < 60; i++ {
		f.lawn("198.51.100.77", uaAcme, 64666, "SHADY-HOST", 10*24*time.Hour-time.Duration(i)*time.Minute, 30*time.Second, i%7, 20, "/lawn/DDDD")
	}
	f.id("198.51.100.77", uaAcme, "Acme AI", logstore.StatusSpoofed)
	// Small spoofed group over IPv6 (below blocklist min).
	f.lawn("2001:db8:1:2::5", uaAcme, 64667, "TINY-HOST", 3*time.Hour, time.Minute, 1, 5, "/lawn/EEEE")
	f.lawn("2001:db8:1:2::5", uaAcme, 64667, "TINY-HOST", 3*time.Hour-2*time.Minute, time.Minute, 2, 5, "/lawn/<bad path>")
	f.id("2001:db8:1:2::5", uaAcme, "Acme AI", logstore.StatusSpoofed)

	// Unverifiable Byte Corp, 1 hit 1h ago.
	f.lawn("192.0.2.44", uaByte, 64510, "BYTE-NET", time.Hour, 2*time.Minute, 3, 7, "/lawn/FFFF")
	f.id("192.0.2.44", uaByte, "Byte Corp", logstore.StatusUnverifiable)

	// Anonymous with no identity row: reads robots, then 2 lawn hits, 5h ago.
	f.robots("100.64.3.9", uaCurl, 64520, "EYEBALL-ISP", 5*time.Hour)
	f.lawn("100.64.3.9", uaCurl, 64520, "EYEBALL-ISP", 5*time.Hour-time.Minute, time.Minute, 1, 1, "/lawn/GGGG")
	f.lawn("100.64.3.9", uaCurl, 64520, "EYEBALL-ISP", 5*time.Hour-3*time.Minute, time.Minute, 2, 1, "/lawn/HHHH")
	// Anonymous IPv6 with an explicit identity row; robots AFTER lawn (not read-rules).
	f.lawn("2001:db8:abcd:12::1", uaNoise, 64520, "EYEBALL-ISP", 20*24*time.Hour, 4*time.Minute, 1, 3, "/lawn/IIII")
	f.robots("2001:db8:abcd:12::1", uaNoise, 64520, "EYEBALL-ISP", 20*24*time.Hour-5*time.Minute)
	f.id("2001:db8:abcd:12::1", uaNoise, "", logstore.StatusAnonymous)

	// Polite client: robots + homepage only. Must never appear.
	f.robots("192.0.2.200", uaNoise, 64999, "POLITE-NET", time.Hour)
	f.home("192.0.2.200", uaNoise, time.Hour-time.Minute)
	f.load(t, s)

	// Rolled-up history for a third Acme IP: all-time only.
	old := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC).UnixMilli()
	insertDaily(t, s, dailyRow{day: "2026-01-01", ip: "203.0.113.12", ua: uaAcme, asn: 64500, asnOrg: "ACME-AI",
		pages: 10, held: 3_600_000, bytes: 1000, depth: 9, sessions: 2, readRules: 1, first: old, last: old + 3_600_000})
	if err := s.UpsertIdentity(context.Background(), logstore.Identity{IP: "203.0.113.12", UserAgent: uaAcme,
		ClaimedOrg: "Acme AI", Status: logstore.StatusVerified, Method: logstore.MethodRDNS, CheckedAt: 1}); err != nil {
		t.Fatal(err)
	}
	return s
}

func testOptions(t *testing.T, s *logstore.Store) Options {
	return Options{
		DB: s.DB(), PublicDir: t.TempDir(), RobotsTxt: testRobots, BaseURL: "https://lawn.example",
		SessionGap: 10 * time.Minute, BlocklistMin: 50, Now: fakeNow,
	}
}
