package shame

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

func collect(t *testing.T, s *logstore.Store) *Report {
	t.Helper()
	r, err := Collect(context.Background(), testOptions(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func findGroup(gs []*Group, kind, name string) *Group {
	for _, g := range gs {
		if g.Kind == kind && g.Name == name {
			return g
		}
	}
	return nil
}

const min_ = int64(60_000)

func TestCollectVerified(t *testing.T) {
	r := collect(t, standardFixture(t))
	if len(r.Verified) != 1 {
		t.Fatalf("verified groups: %d", len(r.Verified))
	}
	g := r.Verified[0]
	if g.Name != "Acme AI" || g.Slug != "acme-ai" || !g.OwnPage || !slices.Equal(g.Statuses, []string{"verified"}) {
		t.Fatalf("group: %+v", g)
	}
	d24, d7, d30, all := g.W[W24h], g.W[W7d], g.W[W30d], g.W[WAll]
	// 24h: IP .10 only: 2 pages, 15m held, 1 session that read the rules.
	if d24.Pages != 2 || d24.HeldMs != 15*min_ || d24.Sessions != 1 || d24.ReadRules != 1 || d24.MaxDepth != 2 || d24.Bytes != 150 {
		t.Errorf("24h: %+v", d24)
	}
	if d24.FirstSeen != ms(2*time.Hour-time.Minute) || d24.LastSeen != ms(2*time.Hour-12*time.Minute)+5*min_ {
		t.Errorf("24h seen: %+v", d24)
	}
	// 7d adds IP .11 (3 days ago).
	if d7.Pages != 3 || d7.HeldMs != 45*min_ || d7.Sessions != 2 || d7.ReadRules != 1 || d7.MaxDepth != 5 {
		t.Errorf("7d: %+v", d7)
	}
	if d30 != d7 {
		t.Errorf("30d %+v != 7d %+v", d30, d7)
	}
	// All-time adds the daily_aggregates row.
	if all.Pages != 13 || all.HeldMs != 105*min_ || all.Sessions != 4 || all.ReadRules != 2 || all.MaxDepth != 9 || all.Bytes != 1160 {
		t.Errorf("all: %+v", all)
	}
	if all.FirstSeen != time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC).UnixMilli() || all.LastSeen != d24.LastSeen {
		t.Errorf("all seen: %+v", all)
	}
	want := []string{"203.0.113.10/32", "203.0.113.11/32", "203.0.113.12/32"}
	if !slices.Equal(g.CIDRs, want) {
		t.Errorf("cidrs %v", g.CIDRs)
	}
	if len(g.TopUAs) != 1 || g.TopUAs[0].UA != uaAcme || g.TopUAs[0].Pages != 13 {
		t.Errorf("UAs %+v", g.TopUAs)
	}
	if !slices.Equal(g.Paths, []string{"/lawn/archive/2019/BBBB", "/lawn/AAAA", "/lawn/CCCC"}) {
		t.Errorf("paths %v", g.Paths)
	}
	if len(g.Daily) != 3 || g.Daily[0].Date != "2026-01-01" || g.Daily[0].Pages != 10 || g.Daily[2].Date != "2026-09-26" || g.Daily[2].Pages != 2 || g.Daily[2].Sessions != 1 {
		t.Errorf("daily %+v", g.Daily)
	}
	if len(g.ASNs) != 1 || g.ASNs[0].Label != "AS64500 ACME-AI" {
		t.Errorf("asns %+v", g.ASNs)
	}
}

func TestCollectLiarsUnverifiableAnonymous(t *testing.T) {
	r := collect(t, standardFixture(t))
	if len(r.Liars) != 2 {
		t.Fatalf("liars: %d", len(r.Liars))
	}
	shady, tiny := r.Liars[0], r.Liars[1]
	if shady.Name != "Acme AI" || shady.ASN != 64666 || shady.Sub != "from AS64666 SHADY-HOST" || shady.Slug != "spoofed-acme-ai-as64666-shady-host" {
		t.Errorf("shady: %+v", shady)
	}
	if a := shady.W[WAll]; a.Pages != 60 || a.HeldMs != 30*min_ || a.Sessions != 1 || a.MaxDepth != 6 {
		t.Errorf("shady all: %+v", a)
	}
	if shady.W[W7d].Pages != 0 || shady.W[W30d].Pages != 60 {
		t.Errorf("shady windows: %+v", shady.W)
	}
	if !slices.Equal(shady.CIDRs, []string{"198.51.100.0/24"}) {
		t.Errorf("shady cidrs %v", shady.CIDRs)
	}
	if !slices.Equal(tiny.CIDRs, []string{"2001:db8:1::/48"}) || tiny.W[WAll].Pages != 2 {
		t.Errorf("tiny: %+v", tiny)
	}
	// crafted path is not published
	if !slices.Equal(tiny.Paths, []string{"/lawn/EEEE"}) {
		t.Errorf("tiny paths: %v", tiny.Paths)
	}

	if len(r.Unverifiable) != 1 {
		t.Fatalf("unverifiable: %d", len(r.Unverifiable))
	}
	u := r.Unverifiable[0]
	if u.Name != "Byte Corp" || u.Slug != "byte-corp-unverifiable" || !slices.Equal(u.CIDRs, []string{"192.0.2.0/24"}) || u.W[W24h].Pages != 1 {
		t.Errorf("unverifiable: %+v", u)
	}

	anon := findGroup(r.Groups, "anonymous", "AS64520 EYEBALL-ISP")
	if anon == nil {
		t.Fatalf("no anonymous group in %d groups", len(r.Groups))
	}
	if anon.OwnPage || anon.Slug != "as64520-eyeball-isp" {
		t.Errorf("anon slug %+v", anon)
	}
	if a := anon.W[WAll]; a.Pages != 3 || a.Sessions != 2 || a.ReadRules != 1 {
		t.Errorf("anon all: %+v", a)
	}
	if anon.W[W24h].Pages != 2 || anon.W[W7d].Pages != 2 || anon.W[W30d].Pages != 3 {
		t.Errorf("anon windows: %+v", anon.W)
	}
	if !slices.Equal(anon.CIDRs, []string{"100.64.3.0/24", "2001:db8:abcd::/48"}) {
		t.Errorf("anon cidrs: %v", anon.CIDRs)
	}

	// Top ASNs: one row per ASN, all statuses; polite client absent.
	if len(r.ASNs) != 5 {
		t.Errorf("asns: %d", len(r.ASNs))
	}
	for _, g := range r.ASNs {
		if g.ASN == 64999 {
			t.Error("polite client listed")
		}
		if !g.OwnPage || !strings.HasPrefix(g.Slug, "as") {
			t.Errorf("asn group %+v", g)
		}
	}
	acme := findGroup(r.ASNs, KindASN, "AS64500 ACME-AI")
	if acme == nil || acme.W[WAll].Pages != 13 || len(acme.Members) != 1 || acme.Members[0].Slug != "acme-ai" {
		t.Errorf("acme asn: %+v", acme)
	}
	eye := findGroup(r.ASNs, KindASN, "AS64520 EYEBALL-ISP")
	if eye == nil || !slices.Equal(eye.Statuses, []string{"anonymous"}) {
		t.Errorf("eyeball asn: %+v", eye)
	}

	// Section 4: verified Acme (2 flagged sessions) and anonymous eyeball (1).
	if len(r.ReadRules) != 2 || r.ReadRules[0].Name != "Acme AI" || r.ReadRules[1].Kind != "anonymous" {
		for _, g := range r.ReadRules {
			t.Logf("rr: %s %s %+v", g.Kind, g.Name, g.W[WAll])
		}
		t.Errorf("read rules section wrong")
	}

	// Global counters.
	if tot := r.Totals[WAll]; tot.Pages != 13+62+1+3 || tot.MaxDepth != 9 {
		t.Errorf("totals all: %+v", tot)
	}
	if tot := r.Totals[W24h]; tot.Pages != 2+2+1+2 {
		t.Errorf("totals 24h: %+v", tot)
	}
	// Every group has a status; offenders list covers every primary group.
	if len(r.Groups) != 5 {
		t.Errorf("groups: %d", len(r.Groups))
	}
}

func TestFeedEntries(t *testing.T) {
	r := collect(t, standardFixture(t))
	byKey := map[string]FeedEntry{}
	for _, e := range r.Feed {
		byKey[e.Status+"|"+e.Org+"|"+e.ASNOrg] = e
		for _, c := range e.CIDRs {
			if !publishable(c, e.Status) {
				t.Errorf("feed cidr %s for %s", c, e.Status)
			}
		}
	}
	if len(r.Feed) != 5 {
		t.Errorf("feed entries: %d %+v", len(r.Feed), r.Feed)
	}
	v, ok := byKey["verified|Acme AI|ACME-AI"]
	if !ok || v.Pages != 13 || v.HoursHeld != 1.75 || v.MaxDepth != 9 || *v.ASN != 64500 || len(v.CIDRs) != 3 ||
		v.FirstSeen != "2026-01-01T10:00:00Z" || v.LastSeen == "" {
		t.Errorf("verified entry %+v", v)
	}
	sp, ok := byKey["spoofed|Acme AI|SHADY-HOST"]
	if !ok || sp.Pages != 60 || sp.HoursHeld != 0.5 || !slices.Equal(sp.CIDRs, []string{"198.51.100.0/24"}) {
		t.Errorf("spoofed entry %+v", sp)
	}
	u, ok := byKey["unverifiable|Byte Corp|BYTE-NET"]
	if !ok || !slices.Equal(u.CIDRs, []string{"192.0.2.0/24"}) {
		t.Errorf("unverifiable entry %+v", u)
	}
	a, ok := byKey["anonymous|AS64520 EYEBALL-ISP|EYEBALL-ISP"]
	if !ok || a.Pages != 3 || !slices.Equal(a.CIDRs, []string{"100.64.3.0/24", "2001:db8:abcd::/48"}) {
		t.Errorf("anonymous entry %+v", a)
	}
}

func TestBlocklist(t *testing.T) {
	r := collect(t, standardFixture(t))
	want := []string{"198.51.100.0/24", "203.0.113.10/32", "203.0.113.11/32", "203.0.113.12/32"}
	if !slices.Equal(r.Blocklist, want) {
		t.Fatalf("blocklist %v want %v", r.Blocklist, want)
	}
	txt := string(BlocklistText(r, "https://lawn.example/"))
	lines := strings.Split(strings.TrimSpace(txt), "\n")
	if !strings.HasPrefix(lines[0], "#") || !strings.Contains(txt, "# generated 2026-09-26T12:00:00Z\n") ||
		!strings.Contains(txt, "# details: https://lawn.example/#methodology\n") || !strings.Contains(txt, "# methodology:") ||
		!strings.Contains(txt, ">= 50") {
		t.Errorf("header:\n%s", txt)
	}
	var body []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") {
			body = append(body, l)
		}
	}
	if !slices.Equal(body, want) {
		t.Errorf("body %v", body)
	}

	// Lower threshold pulls in the small spoofed /48, never anonymous/unverifiable.
	opt := testOptions(t, standardFixture(t))
	opt.BlocklistMin = 1
	r2, err := Collect(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	want2 := []string{"198.51.100.0/24", "203.0.113.10/32", "203.0.113.11/32", "203.0.113.12/32", "2001:db8:1::/48"}
	if !slices.Equal(r2.Blocklist, want2) {
		t.Errorf("blocklist min=1 %v", r2.Blocklist)
	}
}

func TestSessionsSplitAndTimeHeld(t *testing.T) {
	s := openStore(t)
	var f fx
	// Three hits: two in one session (gap measured from end), one after a 10m gap.
	f.lawn("192.0.2.1", "X", 64501, "NET", 3*time.Hour, 20*time.Minute, 1, 10, "/lawn/a")
	f.lawn("192.0.2.1", "X", 64501, "NET", 3*time.Hour-25*time.Minute, time.Minute, 2, 10, "/lawn/b")
	f.lawn("192.0.2.1", "X", 64501, "NET", 3*time.Hour-36*time.Minute, 0, 3, 10, "/lawn/c") // exactly 10m after end
	// Unfinished request (ts_end NULL) counts as a page with zero time held.
	f.rows = append(f.rows, logstore.Request{TsStart: ms(time.Hour), IP: "192.0.2.1", UserAgent: "X", ASN: 64501,
		ASNOrg: "NET", Path: "/lawn/d", Depth: 4, IsViolation: true, Status: 200})
	// Same IP, different UA: separate pair, separate session.
	f.lawn("192.0.2.1", "Y", 64501, "NET", 3*time.Hour, time.Minute, 1, 10, "/lawn/e")
	f.load(t, s)
	r := collect(t, s)
	g := findGroup(r.Groups, "anonymous", "AS64501 NET")
	if g == nil {
		t.Fatal("missing group")
	}
	a := g.W[WAll]
	if a.Pages != 5 || a.HeldMs != 22*min_ || a.Sessions != 4 || a.MaxDepth != 4 || a.Bytes != 40 {
		t.Errorf("all: %+v", a)
	}
	if len(g.TopUAs) != 2 || g.TopUAs[0].UA != "X" || g.TopUAs[0].Pages != 4 {
		t.Errorf("uas %+v", g.TopUAs)
	}
}

func TestWindowStraddlingSession(t *testing.T) {
	// A session that crosses the 24h cutoff: only the in-window part counts.
	s := openStore(t)
	var f fx
	f.lawn("192.0.2.9", "Z", 64502, "NET2", 24*time.Hour+2*time.Minute, time.Minute, 1, 1, "/lawn/a")
	f.lawn("192.0.2.9", "Z", 64502, "NET2", 24*time.Hour-2*time.Minute, time.Minute, 2, 1, "/lawn/b")
	f.load(t, s)
	g := findGroup(collect(t, s).Groups, "anonymous", "AS64502 NET2")
	if g.W[W24h].Pages != 1 || g.W[W24h].Sessions != 1 || g.W[W24h].HeldMs != min_ || g.W[W24h].FirstSeen != ms(24*time.Hour-2*time.Minute) {
		t.Errorf("24h %+v", g.W[W24h])
	}
	if g.W[WAll].Pages != 2 || g.W[WAll].Sessions != 1 {
		t.Errorf("all %+v", g.W[WAll])
	}
}

func TestIdentityEdgeCases(t *testing.T) {
	s := openStore(t)
	var f fx
	// verified status but no claimed org -> anonymous (never confirmed, /24).
	f.lawn("203.0.113.50", "Q", 64503, "Q-NET", time.Hour, time.Minute, 1, 1, "/lawn/a")
	f.id("203.0.113.50", "Q", "", logstore.StatusVerified)
	// unknown status string -> anonymous.
	f.lawn("203.0.113.51", "W", 64503, "Q-NET", time.Hour, time.Minute, 1, 1, "/lawn/a")
	f.id("203.0.113.51", "W", "Weird", "unclassified")
	// NULL user agent and unknown ASN.
	f.rows = append(f.rows, logstore.Request{TsStart: ms(time.Hour), TsEnd: ms(time.Hour) + 1000, IP: "198.18.0.1",
		Path: "/lawn/z", IsViolation: true, Depth: 0})
	f.load(t, s)
	if _, err := s.DB().Exec(`UPDATE requests SET user_agent = NULL WHERE ip = '198.18.0.1'`); err != nil {
		t.Fatal(err)
	}
	r := collect(t, s)
	if len(r.Verified) != 0 || len(r.Unverifiable) != 0 || len(r.Liars) != 0 {
		t.Fatalf("misclassified: %d %d %d", len(r.Verified), len(r.Unverifiable), len(r.Liars))
	}
	for _, e := range r.Feed {
		if e.Status != "anonymous" {
			t.Errorf("entry %+v", e)
		}
		for _, c := range e.CIDRs {
			if strings.HasSuffix(c, "/32") {
				t.Errorf("individual IP published: %s", c)
			}
		}
	}
	unk := findGroup(r.ASNs, KindASN, "unknown ASN")
	if unk == nil || unk.Slug != "unknown-asn" || unk.TopUAs[0].UA != "" {
		t.Errorf("unknown asn group %+v", unk)
	}
	if len(r.Blocklist) != 0 {
		t.Errorf("blocklist %v", r.Blocklist)
	}
}

func TestSlugUniqueness(t *testing.T) {
	s := openStore(t)
	var f fx
	// Two verified orgs that slugify identically, plus an org named like an ASN slug.
	f.lawn("192.0.2.1", "A", 64510, "N", time.Hour, time.Minute, 1, 1, "/lawn/a")
	f.id("192.0.2.1", "A", "Foo Bar", logstore.StatusVerified)
	f.lawn("192.0.2.2", "B", 64510, "N", time.Hour, time.Minute, 1, 1, "/lawn/a")
	f.id("192.0.2.2", "B", "foo-bar", logstore.StatusVerified)
	f.lawn("192.0.2.3", "C", 64510, "N", time.Hour, time.Minute, 1, 1, "/lawn/a")
	f.id("192.0.2.3", "C", "AS64510 N", logstore.StatusVerified)
	f.load(t, s)
	r := collect(t, s)
	seen := map[string]bool{}
	for _, g := range r.Pages {
		if seen[g.Slug] {
			t.Errorf("duplicate slug %s", g.Slug)
		}
		seen[g.Slug] = true
	}
	if len(r.Pages) != 4 {
		t.Errorf("pages %d", len(r.Pages))
	}
}

func TestWriteStats(t *testing.T) {
	r := collect(t, standardFixture(t))
	var b bytes.Buffer
	if err := WriteStats(&b, r, "24h", 10); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"window 24h", "Acme AI", "verified", "claimed, unverifiable", "anonymous", "spoofed UA", "AS64667 TINY-HOST"} {
		if !strings.Contains(out, want) {
			t.Errorf("stats missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SHADY") { // 10 days old: not in 24h
		t.Errorf("stale group in 24h:\n%s", out)
	}
	b.Reset()
	if err := WriteStats(&b, r, "all", 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "(4 more not shown)") {
		t.Errorf("limit:\n%s", b.String())
	}
	if err := WriteStats(&b, r, "1y", 1); err == nil {
		t.Error("want error for bad window")
	}
	// No IP ever appears in stats output (only groups and networks).
	if strings.Contains(out, "100.64.3.9") || strings.Contains(out, "203.0.113.10") {
		t.Error("stats printed an IP")
	}
}

func TestCollectEmpty(t *testing.T) {
	r := collect(t, openStore(t))
	if len(r.Groups) != 0 || len(r.Feed) != 0 || len(r.Blocklist) != 0 || r.Feed == nil {
		t.Errorf("%+v", r)
	}
	if _, err := Collect(context.Background(), Options{}); err == nil {
		t.Error("nil DB accepted")
	}
}
