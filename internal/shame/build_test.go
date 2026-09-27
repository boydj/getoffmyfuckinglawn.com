package shame

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
	"github.com/boydj/getoffmyfuckinglawn.com/web"
)

func build(t *testing.T, opt Options) *Report {
	t.Helper()
	opt.Templates = web.Templates("")
	r, err := Build(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) > 0 {
		t.Errorf("warnings: %v", r.Warnings)
	}
	return r
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var ipv4Host = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/32\b`)

// hasEventHandler reports an on*= attribute (e.g. onload=).
func hasEventHandler(lower string) bool {
	for i := 0; ; {
		j := strings.Index(lower[i:], " on")
		if j < 0 {
			return false
		}
		k := i + j + 3
		for k < len(lower) && lower[k] >= 'a' && lower[k] <= 'z' {
			k++
		}
		if k > i+j+3 && k < len(lower) && lower[k] == '=' {
			return true
		}
		i = i + j + 3
	}
}

// checkPage asserts the static-page rules on one HTML file.
func checkPage(t *testing.T, path, html string) {
	t.Helper()
	if len(html) >= MaxPageBytes {
		t.Errorf("%s: %d bytes >= %d", path, len(html), MaxPageBytes)
	}
	lower := strings.ToLower(html)
	if strings.Contains(lower, "<script") || strings.Contains(lower, "javascript:") || hasEventHandler(lower) {
		t.Errorf("%s: contains script", path)
	}
	// UA strings may mention URLs as escaped text; links and assets may not.
	for _, bad := range []string{`="http`, `='http`, `=http`, `="//`, `='//`, `url(`, `@import`} {
		if strings.Contains(lower, bad) {
			t.Errorf("%s: external reference %q", path, bad)
		}
	}
	if strings.Count(html, "<style>") != 1 || strings.Contains(html, "<link") || strings.Contains(html, "<img") || strings.Contains(html, "@import") {
		t.Errorf("%s: stylesheet/asset rules", path)
	}
	if !strings.Contains(html, "prefers-color-scheme:dark") {
		t.Errorf("%s: no dark mode", path)
	}
	if !strings.Contains(html, "<pre>User-agent: *\nDisallow: /lawn/\n</pre>") {
		t.Errorf("%s: footer robots.txt missing", path)
	}
	if !strings.Contains(html, `href="/#methodology"`) {
		t.Errorf("%s: methodology link missing", path)
	}
}

func TestBuildStandard(t *testing.T) {
	s := standardFixture(t)
	opt := testOptions(t, s)
	r := build(t, opt)
	root := filepath.Join(opt.PublicDir, "shame")

	idx := read(t, filepath.Join(root, "index.html"))
	checkPage(t, "index.html", idx)
	for _, want := range []string{
		"Verified offenders", "Hall of Liars", "Top ASNs", "Read the rules, ignored them", "Claimed, unverifiable",
		`href="org/acme-ai/"`, `href="org/spoofed-acme-ai-as64666-shady-host/"`, `href="org/byte-corp-unverifiable/"`,
		`href="org/as64520-eyeball-isp/"`, `class="b b-verified">verified<`, `class="b b-spoofed">spoofed UA<`,
		`class="b b-unverifiable">claimed, unverifiable<`, `class="b b-anonymous">anonymous<`,
		"1.75", // Acme all-time hours
	} {
		if !strings.Contains(idx, want) {
			t.Errorf("index missing %q", want)
		}
	}
	// No IP of an unverified client, in any form, on any page.
	for _, p := range r.Pages {
		html := read(t, filepath.Join(root, "org", p.Slug, "index.html"))
		checkPage(t, p.Slug, html)
		for _, ip := range []string{"100.64.3.9", "198.51.100.77", "192.0.2.44", "2001:db8:1:2::5", "2001:db8:abcd:12::1"} {
			if strings.Contains(html, ip) {
				t.Errorf("%s leaks %s", p.Slug, ip)
			}
		}
		if p.Kind != logstore.StatusVerified && p.Kind != KindASN && ipv4Host.MatchString(html) {
			t.Errorf("%s: /32 on non-verified page", p.Slug)
		}
	}
	if strings.Contains(idx, "100.64.3.9") {
		t.Error("index leaks IP")
	}

	acme := read(t, filepath.Join(root, "org", "acme-ai", "index.html"))
	for _, want := range []string{"203.0.113.10/32", "AcmeBot/1.0", "/lawn/archive/2019/BBBB", "2026-01-01", "<svg", "<polyline", "AS64500 ACME-AI", "passed Acme AI"} {
		if !strings.Contains(acme, want) {
			t.Errorf("acme page missing %q", want)
		}
	}
	shady := read(t, filepath.Join(root, "org", "spoofed-acme-ai-as64666-shady-host", "index.html"))
	for _, want := range []string{"198.51.100.0/24", "spoofed UA", "failed Acme AI"} {
		if !strings.Contains(shady, want) {
			t.Errorf("shady page missing %q", want)
		}
	}
	eye := read(t, filepath.Join(root, "org", "as64520-eyeball-isp", "index.html"))
	for _, want := range []string{"100.64.3.0/24", "2001:db8:abcd::/48", "(no known crawler UA)", "curl/8.0"} {
		if !strings.Contains(eye, want) {
			t.Errorf("eyeball page missing %q", want)
		}
	}

	// feed.json
	var feed []map[string]any
	if err := json.Unmarshal([]byte(read(t, filepath.Join(root, "feed.json"))), &feed); err != nil {
		t.Fatal(err)
	}
	if len(feed) != 5 {
		t.Errorf("feed len %d", len(feed))
	}
	keys := []string{"org", "status", "asn", "asn_org", "cidrs", "hours_held", "pages", "max_depth", "first_seen", "last_seen"}
	for _, e := range feed {
		if len(e) != len(keys) {
			t.Errorf("feed entry keys: %v", e)
		}
		for _, k := range keys {
			if _, ok := e[k]; !ok {
				t.Errorf("feed entry missing %s", k)
			}
		}
		if _, err := time.Parse(time.RFC3339, e["last_seen"].(string)); err != nil {
			t.Errorf("last_seen %v", e["last_seen"])
		}
	}

	bl := read(t, filepath.Join(root, "blocklist.txt"))
	if !strings.HasPrefix(bl, "# ") || !strings.HasSuffix(bl, "203.0.113.12/32\n") {
		t.Errorf("blocklist:\n%s", bl)
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestBuildAtomicSwapTwice(t *testing.T) {
	s := standardFixture(t)
	opt := testOptions(t, s)
	opt.PublicDir = filepath.Join(opt.PublicDir, "public") // does not exist yet
	// A stale temp dir from a crashed run and an unrelated sibling.
	build(t, opt)
	stale := filepath.Join(opt.PublicDir, tmpPrefix+"crashed")
	if err := os.Mkdir(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(opt.PublicDir, "keep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file only the old tree has must be gone after the swap.
	marker := filepath.Join(opt.PublicDir, "shame", "org", "old-marker")
	if err := os.MkdirAll(marker, 0o755); err != nil {
		t.Fatal(err)
	}
	// Second build with more data.
	var f fx
	f.lawn("192.0.2.77", "NewBot", 64777, "NEW-NET", time.Minute*30, time.Minute, 1, 1, "/lawn/new")
	f.load(t, s)
	r := build(t, opt)

	got := strings.Join(listDir(t, opt.PublicDir), ",")
	if got != "keep.txt,shame" {
		t.Errorf("public dir: %s", got)
	}
	root := filepath.Join(opt.PublicDir, "shame")
	if strings.Join(listDir(t, root), ",") != "blocklist.txt,feed.json,index.html,org,well-behaved,well-behaved.json" {
		t.Errorf("shame dir: %v", listDir(t, root))
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("old tree survived")
	}
	orgs := listDir(t, filepath.Join(root, "org"))
	if len(orgs) != len(r.Pages) {
		t.Errorf("org dirs %d pages %d", len(orgs), len(r.Pages))
	}
	if !strings.Contains(read(t, filepath.Join(root, "index.html")), "AS64777 NEW-NET") {
		t.Error("second build not visible")
	}
	st, err := os.Stat(root)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("shame dir perms %v %v", st.Mode(), err)
	}
}

func TestSwapFirstBuildAndRestore(t *testing.T) {
	pub := t.TempDir()
	tmp, _ := os.MkdirTemp(pub, tmpPrefix)
	os.WriteFile(filepath.Join(tmp, "index.html"), []byte("v1"), 0o644)
	if err := swapDir(pub, tmp); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(pub, "shame", "index.html")) != "v1" {
		t.Fatal("v1")
	}
	// Swapping in a missing dir fails and restores the old tree.
	if err := swapDir(pub, filepath.Join(pub, tmpPrefix+"missing")); err == nil {
		t.Fatal("want error")
	}
	if read(t, filepath.Join(pub, "shame", "index.html")) != "v1" {
		t.Fatal("old tree not restored")
	}
	if strings.Join(listDir(t, pub), ",") != "shame" {
		t.Errorf("leftovers: %v", listDir(t, pub))
	}
}

func TestBuildErrors(t *testing.T) {
	s := openStore(t)
	opt := testOptions(t, s)
	if _, err := Build(context.Background(), opt); err == nil {
		t.Error("nil templates accepted")
	}
	opt.Templates = web.Templates("")
	opt.PublicDir = ""
	if _, err := Build(context.Background(), opt); err == nil {
		t.Error("empty public dir accepted")
	}
	// Empty DB builds fine.
	opt = testOptions(t, s)
	r := build(t, opt)
	idx := read(t, filepath.Join(opt.PublicDir, "shame", "index.html"))
	checkPage(t, "empty index", idx)
	if !strings.Contains(idx, "Nobody here yet") || len(r.Feed) != 0 {
		t.Error("empty build")
	}
	if strings.TrimSpace(read(t, filepath.Join(opt.PublicDir, "shame", "feed.json"))) != "[]" {
		t.Error("empty feed should be []")
	}
}

// TestBuildLargeFixture: 300 orgs of each kind, a huge org with hundreds of
// IPs, UAs and days of history; every page stays under 50 KB.
func TestBuildLargeFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("large fixture")
	}
	s := openStore(t)
	var f fx
	longUA := strings.Repeat("Mozilla/5.0 (compatible; VeryLongCrawlerName; +info) ", 8)
	for i := 0; i < 300; i++ {
		asn := uint32(65000 + i)
		asnOrg := fmt.Sprintf("HOSTING-PROVIDER-WITH-A-LONG-NAME-%03d Networks Ltd", i)
		vip := fmt.Sprintf("10.%d.%d.1", i/256, i%256)
		org := fmt.Sprintf("Example Crawler Company Number %03d Incorporated", i)
		ua := fmt.Sprintf("ExampleBot%03d/1.0 %s", i, longUA)
		f.robots(vip, ua, asn, asnOrg, 2*time.Hour+time.Minute)
		f.lawn(vip, ua, asn, asnOrg, 2*time.Hour, time.Duration(i+1)*time.Second, i%40, 1000, "/lawn/x")
		f.id(vip, ua, org, logstore.StatusVerified)
		sip := fmt.Sprintf("172.16.%d.%d", i/256, i%256)
		f.robots(sip, ua, asn, asnOrg, time.Hour+time.Minute)
		f.lawn(sip, ua, asn, asnOrg, time.Hour, time.Second, 1, 10, "/lawn/y")
		f.id(sip, ua, org, logstore.StatusSpoofed)
		uip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		f.lawn(uip, "Unverifiable"+ua, asn, asnOrg, time.Hour, time.Second, 1, 10, "/lawn/z")
		f.id(uip, "Unverifiable"+ua, org, logstore.StatusUnverifiable)
		aip := fmt.Sprintf("100.%d.%d.9", 64+i/256, i%256)
		f.robots(aip, "anon"+ua, asn, asnOrg, time.Hour+time.Minute)
		f.lawn(aip, "anon"+ua, asn, asnOrg, time.Hour, time.Second, 1, 10, "/lawn/w")
	}
	// One monster verified org + a monster anonymous ASN.
	for i := 0; i < 600; i++ {
		ip := fmt.Sprintf("10.200.%d.%d", i/200, i%200)
		ua := fmt.Sprintf("MonsterBot/%d.0 %s", i%150, longUA)
		f.lawn(ip, ua, 65999, "MONSTER-NET", time.Duration(i)*time.Hour, time.Minute, i%99, 100,
			fmt.Sprintf("/lawn/archive/%d/%s", 2000+i%25, strings.Repeat("AB", 30)))
		f.id(ip, ua, "Monster Crawler", logstore.StatusVerified)
		aip := fmt.Sprintf("%d.%d.%d.1", 11+i/250, i%250, i%7)
		f.lawn(aip, fmt.Sprintf("Anon/%d %s", i, longUA), 65998, "HUGE-EYEBALL-ISP", time.Duration(i)*time.Hour, time.Minute, 1, 1, "/lawn/q")
	}
	f.load(t, s)
	var days []dailyRow
	for d := 0; d < 400; d++ {
		day := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, d)
		days = append(days, dailyRow{day: day.Format("2006-01-02"), ip: "10.200.9.9", ua: "MonsterBot/old", asn: 65999,
			asnOrg: "MONSTER-NET", pages: 5, held: 60000, bytes: 10, depth: 3, sessions: 1, first: day.UnixMilli(), last: day.UnixMilli() + 1})
	}
	insertDaily(t, s, days...)
	if err := s.UpsertIdentity(context.Background(), logstore.Identity{IP: "10.200.9.9", UserAgent: "MonsterBot/old",
		ClaimedOrg: "Monster Crawler", Status: logstore.StatusVerified, CheckedAt: 1}); err != nil {
		t.Fatal(err)
	}

	opt := testOptions(t, s)
	opt.RobotsTxt = testRobots
	start := time.Now()
	r := build(t, opt)
	t.Logf("large build: %d pages in %s", len(r.Pages), time.Since(start))
	if len(r.Verified) != 301 || len(r.Liars) != 300 || len(r.Unverifiable) != 300 || len(r.ASNs) != 302 || len(r.ReadRules) != 900 {
		t.Errorf("sections: %d %d %d %d %d", len(r.Verified), len(r.Liars), len(r.Unverifiable), len(r.ASNs), len(r.ReadRules))
	}
	root := filepath.Join(opt.PublicDir, "shame")
	n := 0
	biggest := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		html := read(t, p)
		checkPage(t, p, html)
		biggest = max(biggest, len(html))
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d html pages, biggest %d bytes", n, biggest)
	if n != len(r.Pages)+2 { // + index.html and well-behaved/index.html
		t.Errorf("pages written %d want %d", n, len(r.Pages)+2)
	}
	idx := read(t, filepath.Join(root, "index.html"))
	if !strings.Contains(idx, "Showing the top") {
		t.Error("index should note truncation")
	}
	monster := read(t, filepath.Join(root, "org", "monster-crawler", "index.html"))
	if !strings.Contains(monster, "days.</p>") || !strings.Contains(monster, "shown; all are in") {
		t.Error("monster page should be capped")
	}
}

// The lead's homepage parses the top-level templates on their own; the shared
// partials must parse there too and provide "style" and "footer".
func TestPartialsParseWithHomepage(t *testing.T) {
	tpl, err := template.ParseFS(web.Templates(""), "*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"style", "footer"} {
		if tpl.Lookup(n) == nil {
			t.Errorf("%s not defined", n)
		}
	}
	var b strings.Builder
	if err := tpl.ExecuteTemplate(&b, "footer", "User-agent: *\nDisallow: /lawn/\n<x>"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Disallow: /lawn/\n&lt;x&gt;") || !strings.Contains(b.String(), "/#methodology") {
		t.Errorf("footer: %s", b.String())
	}
}
