package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/config"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/server"
)

type noDNS struct{}

func (noDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, errors.New("no dns in tests")
}
func (noDNS) LookupHost(context.Context, string) ([]string, error) {
	return nil, errors.New("no dns in tests")
}

const crawlersFixture = `
- org: Test AI Labs
  name: TestBot
  ua_patterns: ["TestBot"]
  verify: { method: ip_ranges, cidrs: ["203.0.113.0/24"] }
- org: Other Crawler Co
  name: OtherBot
  ua_patterns: ["OtherBot"]
  verify: { method: none }
`

func writeASNFixture(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	io.WriteString(zw, "203.0.113.0\t203.0.113.255\t64500\tZZ\tTESTNET-AS Example Hosting\n"+
		"198.51.100.0\t198.51.100.255\t64501\tZZ\tRESIDENTIAL-AS Example Broadband\n")
	zw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Secret = []byte("integration-test-secret-0123456789")
	cfg.DBPath = filepath.Join(dir, "lawn.db")
	cfg.PublicDir = filepath.Join(dir, "public")
	cfg.ASNDBPath = filepath.Join(dir, "asn.tsv.gz")
	cfg.CrawlersFile = filepath.Join(dir, "crawlers.yaml")
	cfg.CorpusDir = "../../corpus"
	cfg.Attrib.RangesCache = filepath.Join(dir, "ranges")
	cfg.Drip.ChunkBytes = 2048
	cfg.Drip.Interval = time.Millisecond
	cfg.Drip.MaxDuration = time.Second
	cfg.Log.FlushInterval = 10 * time.Millisecond
	cfg.Shame.RebuildInterval = time.Hour
	cfg.Shame.BlocklistMinViolations = 5
	if err := os.WriteFile(cfg.CrawlersFile, []byte(crawlersFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	writeASNFixture(t, cfg.ASNDBPath)
	return cfg
}

type crawler struct {
	base, ip, ua string
	c            *http.Client
}

func (c crawler) get(t *testing.T, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", c.base+path, nil)
	req.Header.Set("User-Agent", c.ua)
	// The test client connects from 127.0.0.1, the trusted proxy; the
	// header plays the role Caddy does in production.
	req.Header.Set("X-Forwarded-For", c.ip)
	resp, err := c.c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, string(b)
}

var linkRE = regexp.MustCompile(`href="(/lawn/[^"]+)"`)

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestIntegrationCrawlerWalk(t *testing.T) {
	cfg := testConfig(t)
	a, err := New(cfg, Options{Resolver: noDNS{}, Fetcher: func(context.Context, string) ([]byte, error) {
		return nil, errors.New("no network in tests")
	}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	pubLn, _ := net.Listen("tcp", "127.0.0.1:0")
	admLn, _ := net.Listen("tcp", "127.0.0.1:0")
	pub := server.NewPublicServer("", a.Server, cfg.Drip.MaxDuration)
	adm := server.NewAdminServer("", a.Metrics)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.serve(ctx, pub, adm, pubLn, admLn) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()

	bot := crawler{base: "http://" + pubLn.Addr().String(), ip: "203.0.113.7", ua: "Mozilla/5.0 (compatible; TestBot/1.0)", c: &http.Client{Timeout: 10 * time.Second}}

	// 1. Read the rules.
	code, robots := bot.get(t, "/robots.txt")
	if code != 200 || robots != server.RobotsTxt {
		t.Fatalf("robots: %d %q", code, robots)
	}
	// 2. Find bait in the sitemap and ignore the rules.
	_, sm := bot.get(t, "/sitemap.xml")
	m := regexp.MustCompile(`<loc>[^<]*?(/lawn/[^<]+)</loc>`).FindStringSubmatch(sm)
	if m == nil {
		t.Fatalf("no bait in sitemap: %s", sm)
	}
	// 3. Walk 50 maze pages, always following the first link.
	path := m[1]
	for i := 0; i < 50; i++ {
		code, body := bot.get(t, path)
		if code != 200 {
			t.Fatalf("page %d %s: %d", i, path, code)
		}
		if strings.Contains(body, "<script") {
			t.Fatal("maze page contains script")
		}
		links := linkRE.FindAllStringSubmatch(body, -1)
		if len(links) < 10 {
			t.Fatalf("page %d has %d links", i, len(links))
		}
		path = links[0][1]
	}
	// An anonymous residential client and an unverifiable crawler, too.
	res := crawler{base: bot.base, ip: "198.51.100.23", ua: "curl/8.0", c: bot.c}
	res.get(t, m[1])
	unv := crawler{base: bot.base, ip: "198.51.100.24", ua: "OtherBot/2.0", c: bot.c}
	unv.get(t, m[1])
	// A liar: claims TestBot from outside the published range.
	liar := crawler{base: bot.base, ip: "198.51.100.99", ua: "TestBot/1.0", c: bot.c}
	liar.get(t, m[1])

	db := a.Store.DB()
	count := func(q string, args ...any) int {
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	waitFor(t, "request rows", func() bool {
		return count(`SELECT COUNT(*) FROM requests WHERE is_violation=1`) == 53
	})
	waitFor(t, "identities", func() bool { return count(`SELECT COUNT(*) FROM identities`) == 4 })

	// Logs.
	if n := count(`SELECT COUNT(*) FROM requests WHERE ip='203.0.113.7' AND is_violation=1 AND dripped=1 AND asn=64500 AND ts_end >= ts_start`); n != 50 {
		t.Errorf("bot violations logged: %d", n)
	}
	if n := count(`SELECT MAX(depth) FROM requests WHERE ip='203.0.113.7'`); n != 49 {
		t.Errorf("max depth %d, want 49", n)
	}
	if n := count(`SELECT COUNT(*) FROM requests WHERE path='/robots.txt' AND is_violation=0 AND depth IS NULL`); n != 1 {
		t.Errorf("robots request rows: %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM robots_fetches WHERE ip='203.0.113.7'`); n != 1 {
		t.Errorf("robots_fetches: %d", n)
	}
	for ip, want := range map[string]string{"203.0.113.7": "verified", "198.51.100.23": "anonymous", "198.51.100.24": "unverifiable", "198.51.100.99": "spoofed"} {
		var st string
		if err := db.QueryRow(`SELECT status FROM identities WHERE ip=?`, ip).Scan(&st); err != nil || st != want {
			t.Errorf("identity %s: %q (%v), want %s", ip, st, err, want)
		}
	}

	// Leaderboard.
	if _, err := a.BuildShame(ctx); err != nil {
		t.Fatal(err)
	}
	idx, err := os.ReadFile(filepath.Join(cfg.PublicDir, "shame", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(idx)
	for _, want := range []string{"Test AI Labs", "Disallow: /lawn/", "/#methodology"} {
		if !strings.Contains(html, want) {
			t.Errorf("leaderboard missing %q", want)
		}
	}
	for _, never := range []string{"198.51.100.23", "198.51.100.24", "198.51.100.99", "<script"} {
		if strings.Contains(html, never) {
			t.Errorf("leaderboard must not contain %q", never)
		}
	}
	// The verified org page shows the crawler's individual IP (allowed only
	// for verified crawlers) and nothing else's.
	org, err := os.ReadFile(filepath.Join(cfg.PublicDir, "shame", "org", "test-ai-labs", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(org), "203.0.113.7") {
		t.Error("verified org page missing crawler IP")
	}
	pages, _ := filepath.Glob(filepath.Join(cfg.PublicDir, "shame", "org", "*", "index.html"))
	for _, p := range append(pages, filepath.Join(cfg.PublicDir, "shame", "index.html")) {
		b, _ := os.ReadFile(p)
		for _, ip := range []string{"198.51.100.23", "198.51.100.24", "198.51.100.99"} {
			if strings.Contains(string(b), ip) {
				t.Errorf("%s publishes non-verified IP %s", p, ip)
			}
		}
	}
	// read_the_rules section lists the bot. The section heading text is the
	// shame builder's; find the org after it.
	lower := strings.ToLower(html)
	i := strings.Index(lower, "read the rules")
	if i < 0 || !strings.Contains(html[i:], "Test AI Labs") {
		t.Errorf("read_the_rules section does not list the bot")
	}

	// Feed.
	fb, err := os.ReadFile(filepath.Join(cfg.PublicDir, "shame", "feed.json"))
	if err != nil {
		t.Fatal(err)
	}
	var feed []struct {
		Org, Status, ASNOrg string
		ASN                 int64
		CIDRs               []string
		HoursHeld           float64 `json:"hours_held"`
		Pages               int64
		MaxDepth            int    `json:"max_depth"`
		FirstSeen           string `json:"first_seen"`
		LastSeen            string `json:"last_seen"`
	}
	if err := json.Unmarshal(fb, &feed); err != nil {
		t.Fatalf("feed.json: %v\n%s", err, fb)
	}
	var sawVerified, sawSpoofed bool
	for _, e := range feed {
		for _, c := range e.CIDRs {
			if e.Status != "verified" && (strings.HasSuffix(c, "/32") || strings.HasSuffix(c, "/128")) {
				t.Errorf("non-verified entry publishes a host address: %+v", e)
			}
		}
		switch {
		case e.Status == "verified" && e.Org == "Test AI Labs":
			sawVerified = true
			if e.Pages != 50 || e.MaxDepth != 49 || e.ASN != 64500 || len(e.CIDRs) != 1 || e.CIDRs[0] != "203.0.113.7/32" {
				t.Errorf("verified feed entry: %+v", e)
			}
			if e.HoursHeld <= 0 || e.FirstSeen == "" || e.LastSeen == "" {
				t.Errorf("verified feed entry times: %+v", e)
			}
		case e.Status == "spoofed":
			sawSpoofed = true
			if len(e.CIDRs) != 1 || e.CIDRs[0] != "198.51.100.0/24" {
				t.Errorf("spoofed cidrs: %+v", e)
			}
		}
	}
	if !sawVerified || !sawSpoofed {
		t.Errorf("feed missing entries: %s", fb)
	}

	// Blocklist: verified /32 only; spoofer has 1 violation (< 5), residential never.
	bl, err := os.ReadFile(filepath.Join(cfg.PublicDir, "shame", "blocklist.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var cidrs []string
	for _, l := range strings.Split(string(bl), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			cidrs = append(cidrs, l)
		}
	}
	if len(cidrs) != 1 || cidrs[0] != "203.0.113.7/32" {
		t.Errorf("blocklist: %q", cidrs)
	}

	// Served through the app too.
	code, _ = bot.get(t, "/shame/feed.json")
	if code != 200 {
		t.Errorf("/shame/feed.json via server: %d", code)
	}
	// Metrics on the admin listener.
	resp, err := http.Get("http://" + admLn.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(mb), "lawn_violations_total 53") {
		t.Errorf("metrics:\n%s", mb)
	}
}
