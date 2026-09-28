package bots

import (
	"bytes"
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/attrib"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

const crawlersYAML = `
- org: Google
  name: Googlebot
  ua_patterns: ['\bGooglebot\b']
  verify: {method: rdns, domains: [googlebot.com]}
`

func fixture(t *testing.T) (*logstore.Store, []attrib.Crawler, time.Time) {
	t.Helper()
	s, err := logstore.Open(filepath.Join(t.TempDir(), "lawn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	cr, err := attrib.ParseCrawlers([]byte(crawlersYAML))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	ms := func(d time.Duration) int64 { return now.Add(-d).UnixMilli() }
	req := func(ip, ua, path string, ago time.Duration, asn uint32, org string, hdr bool) logstore.Request {
		r := logstore.Request{TsStart: ms(ago), TsEnd: ms(ago) + 10, IP: ip, UserAgent: ua, Method: "GET", Path: path,
			Depth: -1, ASN: asn, ASNOrg: org, IsViolation: strings.HasPrefix(path, "/lawn/")}
		if r.IsViolation {
			r.Depth = 2
		}
		if hdr {
			r.HeaderNames = "Accept,User-Agent"
			r.Proto = "HTTP/1.1"
			r.TLS = "tls1.3 TLS_AES_128_GCM_SHA256 http/1.1"
		}
		return r
	}
	google := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	shiny := "Mozilla/5.0 (compatible; ShinyNewCrawler/0.3; +https://shiny.example/crawler)"
	bad := "Mozilla/5.0 (compatible; GreedyBot/1.0)"
	firefox := "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
	rows := []logstore.Request{
		// Known crawler, compliant, seen for a long time (see daily_visits below).
		req("66.249.66.1", google, "/robots.txt", 2*time.Hour, 15169, "GOOGLE", true),
		req("66.249.66.1", google, "/", 2*time.Hour, 15169, "GOOGLE", true),
		// Unknown, brand new, compliant, advertises a contact URL.
		req("203.0.113.5", shiny, "/robots.txt", 3*time.Hour, 64500, "SHINY-AS", true),
		req("203.0.113.5", shiny, "/sitemap.xml", 3*time.Hour, 64500, "SHINY-AS", true),
		// Violator.
		req("198.51.100.9", bad, "/", time.Hour, 64501, "HOSTING-AS", true),
		req("198.51.100.9", bad, "/lawn/abc", time.Hour, 64501, "HOSTING-AS", true),
		// A person with a browser: Accept-Language sent, no robots.txt -> not a bot.
		req("192.0.2.50", firefox, "/", time.Hour, 64502, "EYEBALL-ISP", false),
		// Headless scraper with a browser UA: no Accept-Language, hosting ASN.
		req("198.51.100.77", firefox, "/", 30*time.Minute, 64501, "HOSTING-AS", true),
		// Outside a 24h window.
		req("203.0.113.99", "OldTool/1.0", "/", 5*24*time.Hour, 64503, "OLD-AS", true),
	}
	// The browser row carries Accept-Language (it's what real browsers send).
	rows[6].HeaderNames, rows[6].AcceptLanguage = "Accept,Accept-Language,User-Agent", "en-US"
	rows[2].Country, rows[3].Country = "DE", "DE"
	ctx := context.Background()
	if err := s.InsertRequests(ctx, rows); err != nil {
		t.Fatal(err)
	}
	// Googlebot history rolled up long ago; a bot only in daily_visits.
	for _, q := range []string{
		`INSERT INTO daily_visits VALUES ('2026-01-02','66.249.66.1','` + google + `',15169,'GOOGLE',10,2,1,0,1767312000000,1767315600000)`,
		`INSERT INTO daily_visits VALUES ('2026-01-03','192.0.2.200','ArchiveWalker/2.0',64504,'ARCHIVE-AS',4,1,1,0,1767398400000,1767398500000)`,
	} {
		if _, err := s.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertIdentity(ctx, logstore.Identity{IP: "66.249.66.1", UserAgent: google, ClaimedOrg: "Google",
		Status: logstore.StatusVerified, Method: logstore.MethodRDNS, CheckedAt: 1}); err != nil {
		t.Fatal(err)
	}
	for ip, ptr := range map[string]string{"66.249.66.1": "crawl-66-249-66-1.googlebot.com", "203.0.113.5": "crawler-5.shiny.example"} {
		if err := s.UpsertHost(ctx, logstore.Host{IP: ip, PTR: ptr, CheckedAt: 1}); err != nil {
			t.Fatal(err)
		}
	}
	return s, cr, now
}

func byToken(r *Report) map[string]*Bot {
	m := map[string]*Bot{}
	for _, b := range r.Bots {
		m[b.Token] = b
	}
	return m
}

func TestCollect24h(t *testing.T) {
	s, cr, now := fixture(t)
	r, err := Collect(context.Background(), Options{DB: s.DB(), Crawlers: cr, Since: 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	m := byToken(r)
	g := m["Googlebot"]
	if g == nil || g.Known != "Google (Googlebot)" || g.Verdict != VerdictCompliant || g.New || g.Statuses["verified"] != 1 ||
		g.PTRDomains["googlebot.com"] == 0 || g.Requests != 2 {
		t.Errorf("googlebot: %+v", g)
	}
	sh := m["ShinyNewCrawler"]
	if sh == nil || sh.Known != "" || !sh.New || sh.Verdict != VerdictCompliant || sh.Contact != "https://shiny.example/crawler" ||
		sh.PTRDomains["shiny.example"] == 0 || !sh.Reasons["ptr-looks-like-crawler"] || !sh.Reasons["fetched-robots.txt"] {
		t.Errorf("shiny: %+v", sh)
	}
	if b := m["GreedyBot"]; b == nil || b.Verdict != VerdictEntered || b.Violations != 1 || b.MaxDepth != 2 {
		t.Errorf("greedy: %+v", b)
	}
	head := m["browser-like UA @ AS64501 HOSTING-AS"]
	if head == nil || !head.Reasons["no-accept-language"] {
		t.Errorf("headless scraper not grouped by network: %+v", m)
	}
	if _, ok := m["browser-like UA @ AS64502 EYEBALL-ISP"]; ok {
		t.Error("a real browser must not be reported")
	}
	if _, ok := m["OldTool"]; ok {
		t.Error("OldTool is outside the 24h window")
	}
	if _, ok := m["ArchiveWalker"]; ok {
		t.Error("rolled-up history is only included with --since all")
	}
	// New bots sort first, and unknown before known; Googlebot (known, not new) is last.
	if !r.Bots[0].New || r.Bots[0].Known != "" || r.Bots[len(r.Bots)-1].Token != "Googlebot" {
		for _, b := range r.Bots {
			t.Logf("%s new=%v known=%q", b.Token, b.New, b.Known)
		}
		t.Error("sort order")
	}

	var out bytes.Buffer
	Write(&out, r, WriteOptions{UnknownOnly: true, Details: 5})
	txt := out.String()
	for _, want := range []string{"ShinyNewCrawler", "NEW UNKNOWN", "crawlers.yaml stub", `ua_patterns: ['\bShinyNewCrawler\b']`,
		"contact:      https://shiny.example/crawler", "PTR domains:  shiny.example"} {
		if !strings.Contains(txt, want) {
			t.Errorf("report missing %q\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "Googlebot") {
		t.Error("--unknown must hide known crawlers")
	}
}

func TestCollectAllIncludesRolledUp(t *testing.T) {
	s, cr, now := fixture(t)
	r, err := Collect(context.Background(), Options{DB: s.DB(), Crawlers: cr, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	m := byToken(r)
	if a := m["ArchiveWalker"]; a == nil || a.Verdict != VerdictCompliant || a.New || a.Robots != 1 {
		t.Errorf("rolled-up bot: %+v", a)
	}
	// Googlebot's raw and rolled-up visits are merged; first seen is January.
	if g := m["Googlebot"]; g == nil || g.Requests != 12 || g.FirstSeen != 1767312000000 {
		t.Errorf("googlebot merged: %+v", g)
	}
	// --all adds the human too.
	r2, _ := Collect(context.Background(), Options{DB: s.DB(), Crawlers: cr, All: true, Now: func() time.Time { return now }})
	if _, ok := byToken(r2)["browser-like UA @ AS64502 EYEBALL-ISP"]; !ok {
		t.Error("--all should include clients without bot signals")
	}
}

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Duration{"all": 0, "": 0, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := ParseSince(in); err != nil || got != want {
			t.Errorf("ParseSince(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"7x", "-1h", "0d", "d", "7dd"} {
		if _, err := ParseSince(bad); err == nil {
			t.Errorf("ParseSince(%q) should fail", bad)
		}
	}
}

func TestHumanDur(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Hour: "1h", 90 * time.Minute: "1h30m", 48 * time.Hour: "2d", 45 * time.Second: "45s"} {
		if got := humanDur(d); got != want {
			t.Errorf("humanDur(%v)=%q want %q", d, got, want)
		}
	}
}

func TestFrontier(t *testing.T) {
	s, cr, now := fixture(t)
	ua := "FrontierBot/1.0"
	base := now.Add(-time.Hour).UnixMilli()
	sec := int64(1000)
	lawn := func(ip, ua string, start, end int64, page, parent uint32) logstore.Request {
		return logstore.Request{TsStart: base + start, TsEnd: base + end, IP: ip, UserAgent: ua, Method: "GET",
			Path: "/lawn/p", Depth: 1, IsViolation: true, Dripped: true, PageID: page, ParentID: parent}
	}
	rows := []logstore.Request{
		lawn("198.51.100.1", ua, 0, 60*sec, 100, 0),                 // parent, drips for 60s
		lawn("198.51.100.2", ua, 10*sec, 70*sec, 101, 100),          // other IP, parent still open
		lawn("198.51.100.1", ua, 90*sec, 150*sec, 102, 100),         // after the parent finished
		lawn("198.51.100.1", ua, 20*sec, 80*sec, 103, 999),          // parent never fetched
		lawn("198.51.100.1", ua, -10*sec, 50*sec, 104, 100),         // before the parent
		lawn("198.51.100.3", "Other/1.0", 10*sec, 70*sec, 105, 100), // a different UA's parent
	}
	if err := s.InsertRequests(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	r, err := Collect(context.Background(), Options{DB: s.DB(), Crawlers: cr, Since: 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	b := byToken(r)["FrontierBot"]
	if b == nil || b.Children != 4 || b.Follows != 2 || b.Open != 1 {
		t.Fatalf("frontier: %+v", b)
	}
	if o := byToken(r)["Other"]; o == nil || o.Children != 1 || o.Follows != 0 {
		t.Errorf("other UA must not match FrontierBot's parent: %+v", o)
	}
	var out bytes.Buffer
	Write(&out, r, WriteOptions{Details: 10})
	if txt := out.String(); !strings.Contains(txt, "4 child fetches; 2 followed a parent fetch by this UA, 1 while the parent was still dripping (50%)") {
		t.Errorf("report:\n%s", txt)
	}

	// The parent lookup must use the page_id index, not scan requests.
	var plan strings.Builder
	rs, err := s.DB().Query(`EXPLAIN QUERY PLAN SELECT 1 FROM requests p WHERE p.page_id = ? AND p.user_agent IS ?`, 1, ua)
	if err != nil {
		t.Fatal(err)
	}
	for rs.Next() {
		var id, parent, unused int
		var detail string
		if err := rs.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail + "\n")
	}
	rs.Close()
	if !strings.Contains(plan.String(), "idx_req_page") {
		t.Errorf("parent lookup does not use idx_req_page:\n%s", plan.String())
	}
}

func TestExcludeAndCountries(t *testing.T) {
	s, cr, now := fixture(t)
	opt := Options{DB: s.DB(), Crawlers: cr, Now: func() time.Time { return now }}
	r, err := Collect(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	m := byToken(r)
	if sh := m["ShinyNewCrawler"]; sh == nil || sh.Countries["DE"] != 2 {
		t.Fatalf("countries: %+v", sh)
	}
	var out bytes.Buffer
	Write(&out, r, WriteOptions{Details: 10})
	if !strings.Contains(out.String(), "countries:    DE") {
		t.Errorf("report lacks countries:\n%s", out.String())
	}
	// Operator networks vanish, from raw rows and rollups alike.
	opt.Exclude = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("192.0.2.200/32")}
	r, err = Collect(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	m = byToken(r)
	for _, gone := range []string{"ShinyNewCrawler", "ArchiveWalker"} {
		if _, ok := m[gone]; ok {
			t.Errorf("%s is on an excluded network", gone)
		}
	}
	if _, ok := m["Googlebot"]; !ok {
		t.Error("exclusion removed an unrelated bot")
	}
}
