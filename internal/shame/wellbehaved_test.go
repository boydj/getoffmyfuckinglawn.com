package shame

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

type visitRow struct {
	day, ip, ua                               string
	asn                                       int64
	asnOrg                                    string
	requests, robots, bait, viol, first, last int64
}

func insertVisits(t *testing.T, s *logstore.Store, rows ...visitRow) {
	t.Helper()
	for _, r := range rows {
		_, err := s.DB().Exec(`INSERT INTO daily_visits (day, ip, user_agent, asn, asn_org, requests, robots,
		  bait_views, violations, first_ts, last_ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			r.day, r.ip, r.ua, r.asn, r.asnOrg, r.requests, r.robots, r.bait, r.viol, r.first, r.last)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// get adds a non-/lawn/ request.
func (f *fx) get(ip, ua string, asn uint32, asnOrg, method, path string, ago time.Duration) {
	start := ms(ago)
	f.rows = append(f.rows, logstore.Request{
		TsStart: start, TsEnd: start + 5, IP: ip, ASN: asn, ASNOrg: asnOrg, UserAgent: ua,
		Method: method, Path: path, Depth: -1, BytesSent: 30, Status: 200,
	})
}

const (
	uaGood    = "GoodBot/1.0 (+https://good.example/bot)"
	uaPolite  = "polite-fetcher/1.0"
	uaArchive = "Archivist/1.0"
)

var (
	febDay = time.Date(2026, 2, 1, 8, 0, 0, 0, time.UTC).UnixMilli()
	marDay = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC).UnixMilli()
	aprDay = time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC).UnixMilli()
	hourMs = time.Hour.Milliseconds()
)

// addWellBehaved adds the well-behaved fixture clients to s (see the test
// case letters in TestWellBehavedEligibility).
func addWellBehaved(t *testing.T, s *logstore.Store) {
	t.Helper()
	var f fx
	// (a) verified crawler: robots.txt, then / and /sitemap.xml; plus rolled-up history.
	f.get("203.0.113.20", uaGood, 64600, "GOOD-NET", "GET", "/robots.txt", 3*time.Hour)
	f.get("203.0.113.20", uaGood, 64600, "GOOD-NET", "GET", "/", 3*time.Hour-time.Minute)
	f.get("203.0.113.20", uaGood, 64600, "GOOD-NET", "GET", "/sitemap.xml", 3*time.Hour-2*time.Minute)
	f.id("203.0.113.20", uaGood, "Good Search", logstore.StatusVerified)
	// (b) anonymous (no identity row): robots.txt with a query, and a non-bait page, 2 days ago.
	f.get("100.64.9.9", uaPolite, 64601, "EYEBALL-2", "GET", "/robots.txt?x=1", 48*time.Hour)
	f.get("100.64.9.9", uaPolite, 64601, "EYEBALL-2", "GET", "/about", 48*time.Hour-time.Minute)
	// (c) read robots.txt, then one /lawn/ hit: shame only.
	f.get("192.0.2.30", "Turncoat/1.0", 64604, "TURN-NET", "GET", "/robots.txt", 5*time.Hour)
	f.lawn("192.0.2.30", "Turncoat/1.0", 64604, "TURN-NET", 5*time.Hour-time.Minute, time.Minute, 1, 10, "/lawn/TTTT")
	// (d) never fetched robots.txt.
	f.get("192.0.2.40", "NoRobots/1.0", 64605, "NR-NET", "GET", "/", time.Hour)
	f.get("192.0.2.40", "NoRobots/1.0", 64605, "NR-NET", "GET", "/sitemap.xml", time.Hour)
	// (e) spoofed "Good Search" UA that stayed off the lawn.
	f.get("2001:db8:77::50", uaGood, 64602, "SHADY-2", "GET", "/robots.txt", 6*time.Hour)
	f.get("2001:db8:77::50", uaGood, 64602, "SHADY-2", "GET", "/", 6*time.Hour-time.Minute)
	f.id("2001:db8:77::50", uaGood, "Good Search", logstore.StatusSpoofed)
	// (g) clean raw rows, but daily_visits shows an old /lawn/ request.
	f.get("100.64.22.1", "Relapsed/1.0", 64606, "REL-NET", "GET", "/robots.txt", time.Hour)
	// (h) only HEAD /robots.txt: never read the rules.
	f.get("100.64.23.1", "Header/1.0", 64607, "HEAD-NET", "HEAD", "/robots.txt", time.Hour)
	f.load(t, s)
	insertVisits(t, s,
		// (a) older history merges into all-time.
		visitRow{day: "2026-02-01", ip: "203.0.113.20", ua: uaGood, asn: 64600, asnOrg: "GOOD-NET",
			requests: 5, robots: 1, bait: 0, first: febDay, last: febDay + hourMs},
		// (f) rolled-up history only, compliant.
		visitRow{day: "2026-03-01", ip: "100.64.20.1", ua: uaArchive, asn: 64603, asnOrg: "OLD-NET",
			requests: 10, robots: 2, bait: 1, first: marDay, last: marDay + hourMs},
		visitRow{day: "2026-03-02", ip: "100.64.20.1", ua: uaArchive, asn: 64603, asnOrg: "OLD-NET",
			requests: 4, robots: 0, bait: 0, first: marDay + 24*hourMs, last: marDay + 25*hourMs},
		// (f') daily_visits clean, but daily_aggregates shows violations.
		visitRow{day: "2026-03-01", ip: "100.64.21.1", ua: "Sneaky/1.0", asn: 64603, asnOrg: "OLD-NET",
			requests: 3, robots: 1, first: marDay, last: marDay + 1},
		// (g)
		visitRow{day: "2026-04-01", ip: "100.64.22.1", ua: "Relapsed/1.0", asn: 64606, asnOrg: "REL-NET",
			requests: 3, robots: 1, viol: 1, first: aprDay, last: aprDay + 1},
	)
	insertDaily(t, s, dailyRow{day: "2026-01-15", ip: "100.64.21.1", ua: "Sneaky/1.0", asn: 64603, asnOrg: "OLD-NET",
		pages: 2, held: 1000, bytes: 10, depth: 1, sessions: 1, first: marDay - 40*24*hourMs, last: marDay - 40*24*hourMs + 1})
}

func wbFind(r *Report, kind, name string) *WellBehavedGroup {
	for _, g := range r.WellBehaved {
		if g.Kind == kind && g.Name == name {
			return g
		}
	}
	return nil
}

func TestWellBehavedEligibility(t *testing.T) {
	s := openStore(t)
	addWellBehaved(t, s)
	r := collect(t, s)
	for _, g := range r.WellBehaved {
		t.Logf("wb: %s %q %q clients=%d cidrs=%v all=%+v", g.Kind, g.Name, g.Sub, g.Clients, g.CIDRs, g.W[WAll])
	}
	if len(r.WellBehaved) != 4 {
		t.Fatalf("well-behaved groups: %d, want (a) (b) (e) (f)", len(r.WellBehaved))
	}

	// (a) verified: credited to the org, individual IP, all-time merges daily_visits.
	a := wbFind(r, logstore.StatusVerified, "Good Search")
	if a == nil {
		t.Fatal("(a) verified crawler not listed")
	}
	if a.Clients != 1 || !slices.Equal(a.CIDRs, []string{"203.0.113.20/32"}) || a.Sub != "" {
		t.Errorf("(a) %+v", a)
	}
	if w := a.W[W24h]; w.Requests != 3 || w.Robots != 1 || w.Bait != 2 || w.FirstSeen != ms(3*time.Hour) || w.LastSeen != ms(3*time.Hour-2*time.Minute)+5 {
		t.Errorf("(a) 24h %+v", w)
	}
	if w := a.W[WAll]; w.Requests != 8 || w.Robots != 2 || !w.SawBait() || w.FirstSeen != febDay || w.LastSeen != a.W[W24h].LastSeen {
		t.Errorf("(a) all %+v", w)
	}
	if len(a.UAs) != 1 || a.UAs[0].UA != uaGood || a.UAs[0].Requests != 8 {
		t.Errorf("(a) uas %+v", a.UAs)
	}
	if len(a.ASNs) != 1 || a.ASNs[0].Label != "AS64600 GOOD-NET" {
		t.Errorf("(a) asns %+v", a.ASNs)
	}

	// (b) anonymous: under its ASN, /24 only, windows from raw rows.
	b := wbFind(r, logstore.StatusAnonymous, "AS64601 EYEBALL-2")
	if b == nil {
		t.Fatal("(b) anonymous client not listed")
	}
	if !slices.Equal(b.CIDRs, []string{"100.64.9.0/24"}) || b.ClaimedOrg != "" {
		t.Errorf("(b) %+v", b)
	}
	if b.W[W24h].Requests != 0 || b.W[W7d].Requests != 2 || b.W[W30d].Requests != 2 || b.W[WAll].Requests != 2 ||
		b.W[WAll].Robots != 1 || b.W[WAll].SawBait() {
		t.Errorf("(b) windows %+v", b.W)
	}

	// (e) spoofed: under its ASN, labelled, never credited to Good Search.
	e := wbFind(r, logstore.StatusSpoofed, "AS64602 SHADY-2")
	if e == nil {
		t.Fatal("(e) spoofed compliant client not listed")
	}
	if e.ClaimedOrg != "Good Search" || !strings.Contains(e.Sub, "claimed Good Search") || !strings.Contains(e.Sub, "failed Good Search's") ||
		!slices.Equal(e.CIDRs, []string{"2001:db8:77::/48"}) || !e.W[WAll].SawBait() {
		t.Errorf("(e) %+v", e)
	}
	for _, g := range r.WellBehaved {
		if g.Name == "Good Search" && g.Kind != logstore.StatusVerified {
			t.Errorf("spoofed client credited to the claimed org: %+v", g)
		}
	}

	// (f) rolled-up history only: all-time counts, no window counts.
	f := wbFind(r, logstore.StatusAnonymous, "AS64603 OLD-NET")
	if f == nil {
		t.Fatal("(f) rolled-up client not listed")
	}
	if f.Clients != 1 || f.W[WAll].Requests != 14 || f.W[WAll].Robots != 2 || !f.W[WAll].SawBait() ||
		f.W[WAll].FirstSeen != marDay || f.W[WAll].LastSeen != marDay+25*hourMs || f.W[W30d].Requests != 0 ||
		!slices.Equal(f.CIDRs, []string{"100.64.20.0/24"}) || len(f.UAs) != 1 || f.UAs[0].UA != uaArchive {
		t.Errorf("(f) %+v", f)
	}

	// (c) (d) (f') (g) (h) are absent.
	for _, g := range r.WellBehaved {
		for _, ua := range g.UAs {
			switch ua.UA {
			case "Turncoat/1.0", "NoRobots/1.0", "Sneaky/1.0", "Relapsed/1.0", "Header/1.0":
				t.Errorf("ineligible client listed: %s in %s", ua.UA, g.Name)
			}
		}
	}
	// (c) is still on the wall of shame.
	if g := findGroup(r.Groups, logstore.StatusAnonymous, "AS64604 TURN-NET"); g == nil || g.W[WAll].Pages != 1 || g.W[WAll].ReadRules != 1 {
		t.Errorf("(c) should be on the wall: %+v", g)
	}

	// Order: most recently seen first.
	for i := 1; i < len(r.WellBehaved); i++ {
		if r.WellBehaved[i-1].W[WAll].LastSeen < r.WellBehaved[i].W[WAll].LastSeen {
			t.Errorf("not sorted by last seen at %d", i)
		}
	}
	if r.WellBehavedClients() != 4 {
		t.Errorf("clients %d", r.WellBehavedClients())
	}

	// Feed atoms mirror the groups here (one ASN each).
	if len(r.WellBehavedFeed) != 4 {
		t.Fatalf("feed %d", len(r.WellBehavedFeed))
	}
	byOrg := map[string]WellBehavedEntry{}
	for _, e := range r.WellBehavedFeed {
		byOrg[e.Status+"|"+e.Org] = e
		for _, c := range e.CIDRs {
			if !publishable(c, e.Status) {
				t.Errorf("feed cidr %s for %s", c, e.Status)
			}
		}
	}
	if v := byOrg["verified|Good Search"]; v.Requests != 8 || v.Robots != 2 || !v.SawBait || *v.ASN != 64600 ||
		v.FirstSeen != "2026-02-01T08:00:00Z" || !slices.Equal(v.CIDRs, []string{"203.0.113.20/32"}) {
		t.Errorf("feed verified %+v", v)
	}
	if sp, ok := byOrg["spoofed|AS64602 SHADY-2"]; !ok || sp.ClaimedOrg != "Good Search" || sp.ASNOrg != "SHADY-2" {
		t.Errorf("feed spoofed %+v", sp)
	}
}

// Every classified-anonymous edge case (verified without org, unknown
// status) fails safe on the well-behaved page too.
func TestWellBehavedIdentityFailSafe(t *testing.T) {
	s := openStore(t)
	var f fx
	f.get("203.0.113.70", "Q", 64610, "Q-NET", "GET", "/robots.txt", time.Hour)
	f.id("203.0.113.70", "Q", "", logstore.StatusVerified)
	f.get("203.0.113.71", "W", 64610, "Q-NET", "GET", "/robots.txt", time.Hour)
	f.id("203.0.113.71", "W", "Weird", "unclassified")
	f.load(t, s)
	r := collect(t, s)
	if len(r.WellBehaved) != 1 {
		t.Fatalf("groups %d", len(r.WellBehaved))
	}
	g := r.WellBehaved[0]
	if g.Kind != logstore.StatusAnonymous || g.Clients != 2 || !slices.Equal(g.CIDRs, []string{"203.0.113.0/24"}) {
		t.Errorf("%+v", g)
	}
}

func TestBuildWellBehaved(t *testing.T) {
	s := standardFixture(t)
	opt := testOptions(t, s)
	before := build(t, opt)
	root := filepath.Join(opt.PublicDir, "shame")
	blBefore := read(t, filepath.Join(root, "blocklist.txt"))
	feedBefore := read(t, filepath.Join(root, "feed.json"))

	addWellBehaved(t, s)
	r := build(t, opt)
	if bl := read(t, filepath.Join(root, "blocklist.txt")); bl != blBefore || !slices.Equal(r.Blocklist, before.Blocklist) {
		t.Errorf("blocklist changed by compliant clients:\n%s\nvs\n%s", bl, blBefore)
	}
	for _, c := range r.Blocklist {
		switch c {
		case "203.0.113.20/32", "2001:db8:77::/48", "100.64.9.0/24", "100.64.20.0/24", "192.0.2.0/24":
			t.Errorf("well-behaved client in blocklist: %s", c)
		}
	}
	// feed.json gains only the violators (c) and (f'), never a compliant client.
	var feed []FeedEntry
	if err := json.Unmarshal([]byte(read(t, filepath.Join(root, "feed.json"))), &feed); err != nil {
		t.Fatal(err)
	}
	if len(feed) != len(before.Feed)+2 || feedBefore == "" {
		t.Errorf("feed entries %d, before %d", len(feed), len(before.Feed))
	}
	for _, e := range feed {
		for _, c := range e.CIDRs {
			switch c {
			case "203.0.113.20/32", "2001:db8:77::/48", "100.64.9.0/24", "100.64.20.0/24":
				t.Errorf("compliant client in feed.json: %+v", e)
			}
		}
	}

	html := read(t, filepath.Join(root, "well-behaved", "index.html"))
	checkPage(t, "well-behaved", html)
	for _, want := range []string{
		"Well-behaved crawlers", "Read the rules. Stayed off the lawn.",
		"203.0.113.20/32", "100.64.9.0/24", "100.64.20.0/24", "192.0.2.0/24",
		"Good Search", "AS64601 EYEBALL-2", "AS64602 SHADY-2", "claimed Good Search", "AS64999 POLITE-NET", "2001:db8:77::/48",
		`class="b b-verified">verified<`, `class="b b-spoofed">spoofed UA<`, `class="b b-anonymous">anonymous<`,
		"GoodBot/1.0", "polite-fetcher/1.0", "Saw the bait", `href="../well-behaved.json"`, `href="../"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("well-behaved page missing %q", want)
		}
	}
	for _, bad := range []string{"100.64.9.9", "2001:db8:77::50", "100.64.20.1", "192.0.2.200", "Turncoat", "NoRobots", "Sneaky", "Relapsed", "Header/1.0", "/lawn/TTTT"} {
		if strings.Contains(html, bad) {
			t.Errorf("well-behaved page contains %q", bad)
		}
	}
	for _, m := range ipv4Host.FindAllString(html, -1) {
		if m != "203.0.113.20/32" {
			t.Errorf("individual IP of a non-verified client: %s", m)
		}
	}
	// The spoofed row sits in its own section, not with the verified org.
	vi, si := strings.Index(html, `id="verified"`), strings.Index(html, `id="spoofed"`)
	if vi < 0 || si < 0 || strings.Contains(html[vi:si], "2001:db8:77::/48") {
		t.Error("spoofed client shown in the verified section")
	}

	// well-behaved.json matches the report and has exactly the documented keys.
	raw := read(t, filepath.Join(root, "well-behaved.json"))
	var got []map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	keys := []string{"org", "claimed_org", "status", "asn", "asn_org", "cidrs", "robots_fetches", "requests", "saw_bait", "first_seen", "last_seen", "trait_clients", "traits"}
	if len(got) != len(r.WellBehavedFeed) || len(got) != 5 {
		t.Fatalf("well-behaved.json entries %d, report %d", len(got), len(r.WellBehavedFeed))
	}
	for _, e := range got {
		if len(e) != len(keys) {
			t.Errorf("entry keys %v", e)
		}
		for _, k := range keys {
			if _, ok := e[k]; !ok {
				t.Errorf("entry missing %s", k)
			}
		}
		for _, k := range []string{"first_seen", "last_seen"} {
			if ts, err := time.Parse(time.RFC3339, e[k].(string)); err != nil || ts.Location() != time.UTC {
				t.Errorf("%s %v", k, e[k])
			}
		}
	}
	want, _ := json.MarshalIndent(r.WellBehavedFeed, "", " ")
	if raw != string(want)+"\n" {
		t.Error("well-behaved.json differs from the report")
	}

	// Linked from the wall and org pages.
	if idx := read(t, filepath.Join(root, "index.html")); !strings.Contains(idx, `href="well-behaved/"`) || !strings.Contains(idx, `href="well-behaved.json"`) {
		t.Error("index does not link the well-behaved page")
	}
	if org := read(t, filepath.Join(root, "org", "acme-ai", "index.html")); !strings.Contains(org, `href="../../well-behaved/"`) {
		t.Error("org page does not link the well-behaved page")
	}
}

func TestBuildWellBehavedEmpty(t *testing.T) {
	opt := testOptions(t, openStore(t))
	r := build(t, opt)
	root := filepath.Join(opt.PublicDir, "shame")
	html := read(t, filepath.Join(root, "well-behaved", "index.html"))
	checkPage(t, "empty well-behaved", html)
	if !strings.Contains(html, "Nobody here yet") || r.WellBehavedFeed == nil {
		t.Error("empty page")
	}
	if strings.TrimSpace(read(t, filepath.Join(root, "well-behaved.json"))) != "[]" {
		t.Error("empty well-behaved.json should be []")
	}
}

func TestWriteStatsWellBehaved(t *testing.T) {
	s := standardFixture(t)
	addWellBehaved(t, s)
	r := collect(t, s)
	var b bytes.Buffer
	if err := WriteStats(&b, r, "24h", 10); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Well-behaved (read robots.txt, never entered /lawn/): 5 groups, 5 clients", "Good Search",
		"AS64602 SHADY-2", "claimed Good Search", "AS64999 POLITE-NET", "SAW BAIT"} {
		if !strings.Contains(out, want) {
			t.Errorf("stats missing %q:\n%s", want, out)
		}
	}
	// 2 days old / rolled up: not active in 24h.
	if strings.Contains(out, "EYEBALL-2") || strings.Contains(out, "OLD-NET") {
		t.Errorf("stale well-behaved group in 24h:\n%s", out)
	}
	for _, ip := range []string{"203.0.113.20", "100.64.9.9", "2001:db8:77::50"} {
		if strings.Contains(out, ip) {
			t.Errorf("stats printed IP %s", ip)
		}
	}
	b.Reset()
	if err := WriteStats(&b, r, "all", 2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "5 groups active in window all") || !strings.Contains(b.String(), "(3 more not shown)") {
		t.Errorf("all window:\n%s", b.String())
	}
	b.Reset()
	if err := WriteStats(&b, collect(t, openStore(t)), "7d", 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "None in this window.") {
		t.Errorf("empty:\n%s", b.String())
	}
}

// TestBuildWellBehavedLarge: hundreds of compliant orgs and networks, one
// with many UAs and networks; the page stays under 50 KB and says so.
func TestBuildWellBehavedLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("large fixture")
	}
	s := openStore(t)
	var f fx
	longUA := strings.Repeat("Mozilla/5.0 (compatible; VeryLongPoliteCrawler; +info) ", 8)
	for i := 0; i < 400; i++ {
		asn := uint32(66000 + i)
		asnOrg := fmt.Sprintf("HOSTING-PROVIDER-WITH-A-LONG-NAME-%03d Networks Ltd", i)
		ip := fmt.Sprintf("10.%d.%d.1", i/256, i%256)
		ua := fmt.Sprintf("PoliteBot%03d/1.0 %s", i, longUA)
		f.get(ip, ua, asn, asnOrg, "GET", "/robots.txt", time.Duration(i)*time.Minute)
		f.get(ip, ua, asn, asnOrg, "GET", "/", time.Duration(i)*time.Minute)
		f.id(ip, ua, fmt.Sprintf("Polite Crawler Company Number %03d Incorporated", i), logstore.StatusVerified)
		aip := fmt.Sprintf("100.%d.%d.9", 64+i/256, i%256)
		f.get(aip, "anon"+ua, asn, asnOrg, "GET", "/robots.txt", time.Duration(i)*time.Minute)
		sip := fmt.Sprintf("172.16.%d.%d", i/256, i%256)
		f.get(sip, ua, asn, asnOrg, "GET", "/robots.txt", time.Duration(i)*time.Minute)
		f.id(sip, ua, fmt.Sprintf("Polite Crawler Company Number %03d Incorporated", i), logstore.StatusSpoofed)
		uip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		f.get(uip, "U"+ua, asn, asnOrg, "GET", "/robots.txt", time.Duration(i)*time.Minute)
		f.id(uip, "U"+ua, fmt.Sprintf("Unverifiable Crawler %03d", i), logstore.StatusUnverifiable)
	}
	// One huge anonymous network: 500 clients, 500 UAs, 100 /24s.
	for i := 0; i < 500; i++ {
		ip := fmt.Sprintf("11.%d.%d.1", i%100, i/100)
		f.get(ip, fmt.Sprintf("Fetcher/%d %s", i, longUA), 65998, "HUGE-EYEBALL-ISP", "GET", "/robots.txt", time.Minute)
	}
	f.load(t, s)
	opt := testOptions(t, s)
	r := build(t, opt)
	if len(r.WellBehaved) != 1601 {
		t.Errorf("groups %d", len(r.WellBehaved))
	}
	html := read(t, filepath.Join(opt.PublicDir, "shame", "well-behaved", "index.html"))
	checkPage(t, "large well-behaved", html)
	t.Logf("well-behaved page: %d bytes", len(html))
	if !strings.Contains(html, "most recently seen first. The full list is in") || !strings.Contains(html, "more</small>") {
		t.Error("large page should note truncation")
	}
	for _, m := range ipv4Host.FindAllString(html, -1) {
		if !strings.HasPrefix(m, "10.") {
			t.Errorf("non-verified /32: %s", m)
		}
	}
	var got []WellBehavedEntry
	if err := json.Unmarshal([]byte(read(t, filepath.Join(opt.PublicDir, "shame", "well-behaved.json"))), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1601 {
		t.Errorf("json entries %d", len(got))
	}
	if _, err := Collect(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
}
