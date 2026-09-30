package attrib

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// All addresses in these tests are from documentation ranges (RFC 5737,
// RFC 3849); they are fixtures, not vendor data.

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func prefixStrings(p []netip.Prefix) []string {
	out := make([]string, len(p))
	for i, x := range p {
		out[i] = x.String()
	}
	slices.Sort(out)
	return out
}

func TestParsePrefixesJSON(t *testing.T) {
	doc := `{
	  "creationTime": "2026-09-01T00:00:00",
	  "syncToken": "12345",
	  "prefixes": [
	    {"ipv6Prefix": "2001:db8:10::/64"},
	    {"ipv4Prefix": "192.0.2.0/27"},
	    {"ipv4Prefix": " 198.51.100.7/24 "}
	  ],
	  "nested": {"deeper": [["203.0.113.128/25", {"x": "2001:db8:ff::/48"}]], "n": 5, "ok": true, "nil": null},
	  "notes": ["hello", "10.0.0.1", "300.1.1.1/8"]
	}`
	got, err := ParsePrefixes([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/27", "198.51.100.0/24", "2001:db8:10::/64", "2001:db8:ff::/48", "203.0.113.128/25"}
	if g := prefixStrings(got); !slices.Equal(g, want) {
		t.Fatalf("got %v want %v", g, want)
	}
	// Top-level array.
	got, err = ParsePrefixes([]byte(`["192.0.2.0/24"]`))
	if err != nil || len(got) != 1 {
		t.Fatalf("array: %v %v", got, err)
	}
}

// A JSON list of bare addresses (no CIDR anywhere) is read as /32s and
// /128s; in a CIDR list, bare addresses stay ignored (see above).
func TestParsePrefixesJSONBareAddresses(t *testing.T) {
	doc := `{"creationTime": "2026-09-30", "ips": ["192.0.2.10", " 198.51.100.7 ", "2001:db8::5", "not-an-ip", "fe80::1%eth0"]}`
	got, err := ParsePrefixes([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.10/32", "198.51.100.7/32", "2001:db8::5/128"}
	if g := prefixStrings(got); !slices.Equal(g, want) {
		t.Fatalf("got %v want %v", g, want)
	}
	if _, err := ParsePrefixes([]byte(`{"version": "1.0", "count": 0}`)); err == nil {
		t.Error("a list with no addresses must still be an error")
	}
}

func TestParsePrefixesText(t *testing.T) {
	txt := "# vendor list\n\n192.0.2.0/24\n  2001:db8::/32  # trailing comment\n198.51.100.9\nnot-an-ip\r\n203.0.113.0/24\r\n"
	got, err := ParsePrefixes([]byte(txt))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/24", "198.51.100.9/32", "2001:db8::/32", "203.0.113.0/24"}
	if g := prefixStrings(got); !slices.Equal(g, want) {
		t.Fatalf("got %v want %v", g, want)
	}
}

func TestParsePrefixesErrors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":      "",
		"html":       "<html><body>Access denied</body></html>",
		"bad json":   `{"prefixes": [`,
		"json no ip": `{"prefixes": []}`,
		"comments":   "# nothing\n# here\n",
	} {
		if _, err := ParsePrefixes([]byte(in)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestPrefixSet(t *testing.T) {
	ps := newPrefixSet([]netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/25"),
		netip.MustParsePrefix("192.0.2.64/26"), // inside the /25: merged
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("198.51.100.7/32"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	})
	if len(ps) != 3 {
		// 192.0.2.0/25 and .128/25 are adjacent, not overlapping: kept
		// separate is fine too, so accept 3 or 4.
		if len(ps) != 4 {
			t.Fatalf("spans: %d", len(ps))
		}
	}
	for ip, want := range map[string]bool{
		"192.0.2.0": true, "192.0.2.255": true, "192.0.3.0": false, "192.0.1.255": false,
		"198.51.100.7": true, "198.51.100.8": false, "198.51.100.6": false,
		"::ffff:192.0.2.9": true,
		"2001:db8::1":      true, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff": true, "2001:db9::": false,
		"::c000:0201": false, // IPv4-compatible (not mapped) must not match 192.0.2.1
		"0.0.0.0":     false, "255.255.255.255": false, "::": false,
	} {
		if got := ps.contains(netip.MustParseAddr(ip)); got != want {
			t.Errorf("contains(%s)=%v want %v", ip, got, want)
		}
	}
	if newPrefixSet(nil).contains(netip.MustParseAddr("192.0.2.1")) {
		t.Error("empty set contains")
	}
	all4 := newPrefixSet([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if !all4.contains(netip.MustParseAddr("203.0.113.1")) || all4.contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("0.0.0.0/0 should cover all IPv4 and no IPv6")
	}
	all6 := newPrefixSet([]netip.Prefix{netip.MustParsePrefix("::/0")})
	if !all6.contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("::/0")
	}
	a := netip.MustParseAddr("2001:db8::1")
	if n := testing.AllocsPerRun(100, func() { ps.contains(a) }); n != 0 {
		t.Errorf("contains allocates %v", n)
	}
}

const testURL = "https://vendor.example/bot.json"

func urlCrawlers(t *testing.T, urls ...string) []Crawler {
	t.Helper()
	var cs []Crawler
	for _, u := range urls {
		cs = append(cs, Crawler{Org: "V", Name: u, Verify: VerifySpec{Method: VerifyIPRanges, URL: u}})
	}
	return cs
}

type fakeFetcher struct {
	mu    sync.Mutex
	body  map[string]string
	err   error
	calls atomic.Int64
}

func (f *fakeFetcher) fetch(ctx context.Context, url string) ([]byte, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.body[url]
	if !ok {
		return nil, errors.New("404")
	}
	return []byte(b), nil
}

func (f *fakeFetcher) set(url, body string, err error) {
	f.mu.Lock()
	f.body[url] = body
	f.err = err
	f.mu.Unlock()
}

func TestRangeStoreCacheAndRefresh(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "ranges")
	clk := newClock()
	ff := &fakeFetcher{body: map[string]string{testURL: `{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`}}
	rs := NewRangeStore(RangeOptions{Crawlers: urlCrawlers(t, testURL), CacheDir: dir, MaxAge: 24 * time.Hour, Fetcher: ff.fetch, Now: clk.Now})
	in := netip.MustParseAddr("192.0.2.5")
	out := netip.MustParseAddr("198.51.100.5")

	if _, known := rs.Contains(testURL, in); known {
		t.Fatal("known before any fetch")
	}
	if ff.calls.Load() != 0 {
		t.Fatal("NewRangeStore touched the network")
	}
	if err := rs.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, known := rs.Contains(testURL, in); !ok || !known {
		t.Fatal("not contained after refresh")
	}
	if ok, _ := rs.Contains(testURL, out); ok {
		t.Fatal("false positive")
	}
	fetchedAt := clk.Now()
	if files, _ := filepath.Glob(filepath.Join(dir, "ranges-*.txt")); len(files) != 1 {
		t.Fatalf("cache files: %v", files)
	}

	// Fresh: no refetch.
	clk.Add(23 * time.Hour)
	if err := rs.Refresh(ctx); err != nil || ff.calls.Load() != 1 {
		t.Fatalf("refetched fresh list: calls=%d err=%v", ff.calls.Load(), err)
	}

	// Stale + fetch failure: error returned, old copy kept.
	clk.Add(2 * time.Hour)
	ff.set(testURL, "", errors.New("boom"))
	if err := rs.Refresh(ctx); err == nil {
		t.Fatal("expected error")
	}
	if ok, known := rs.Contains(testURL, in); !ok || !known {
		t.Fatal("lost cached list on fetch failure")
	}

	// Garbage body: error, old copy kept.
	ff.set(testURL, "<html>rate limited</html>", nil)
	if err := rs.Refresh(ctx); err == nil {
		t.Fatal("expected parse error")
	}
	if ok, _ := rs.Contains(testURL, in); !ok {
		t.Fatal("garbage replaced list")
	}

	// A new process loads from the cache without network.
	dead := &fakeFetcher{err: errors.New("offline")}
	rs2 := NewRangeStore(RangeOptions{Crawlers: urlCrawlers(t, testURL), CacheDir: dir, MaxAge: 24 * time.Hour, Fetcher: dead.fetch, Now: clk.Now})
	if ok, known := rs2.Contains(testURL, in); !ok || !known {
		t.Fatal("cache not loaded at startup")
	}
	if ft, _ := rs2.Fetched(testURL); !ft.Equal(fetchedAt) {
		t.Fatalf("cached fetch time %v want %v", ft, fetchedAt)
	}
	if dead.calls.Load() != 0 {
		t.Fatal("startup fetched")
	}

	// Successful refresh replaces the list and the cache.
	ff.set(testURL, "198.51.100.0/24\n", nil)
	if err := rs.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := rs.Contains(testURL, out); !ok {
		t.Fatal("new list not active")
	}
	if ok, _ := rs.Contains(testURL, in); ok {
		t.Fatal("old list still active")
	}
	rs3 := NewRangeStore(RangeOptions{Crawlers: urlCrawlers(t, testURL), CacheDir: dir, Fetcher: dead.fetch, Now: clk.Now})
	if ok, _ := rs3.Contains(testURL, out); !ok {
		t.Fatal("cache not rewritten")
	}

	// RefreshAll ignores age.
	n := ff.calls.Load()
	if err := rs.RefreshAll(ctx); err != nil || ff.calls.Load() != n+1 {
		t.Fatalf("RefreshAll: calls %d->%d err=%v", n, ff.calls.Load(), err)
	}

	// SetCrawlers dropping the URL forgets it; re-adding reloads from cache.
	rs.SetCrawlers(nil)
	if _, known := rs.Contains(testURL, out); known {
		t.Fatal("dropped url still known")
	}
	rs.SetCrawlers(urlCrawlers(t, testURL))
	if ok, _ := rs.Contains(testURL, out); !ok {
		t.Fatal("re-added url not loaded from cache")
	}

	// No temp files left behind.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

func TestRangeStoreNoCacheDir(t *testing.T) {
	ff := &fakeFetcher{body: map[string]string{testURL: "192.0.2.0/24"}}
	rs := NewRangeStore(RangeOptions{Crawlers: urlCrawlers(t, testURL), Fetcher: ff.fetch})
	if err := rs.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := rs.Contains(testURL, netip.MustParseAddr("192.0.2.1")); !ok {
		t.Fatal("memory-only list")
	}
	var nilStore *RangeStore
	if _, known := nilStore.Contains(testURL, netip.MustParseAddr("192.0.2.1")); known {
		t.Fatal("nil store known")
	}
}

func TestRefreshLoop(t *testing.T) {
	ff := &fakeFetcher{body: map[string]string{testURL: "192.0.2.0/24", "https://other.example/x": "2001:db8::/32"}}
	rs := NewRangeStore(RangeOptions{Crawlers: urlCrawlers(t, testURL, "https://other.example/x", "https://missing.example/y"),
		CacheDir: t.TempDir(), Fetcher: ff.fetch})
	ctx, cancel := context.WithCancel(context.Background())
	var logged atomic.Int64
	done := make(chan struct{})
	go func() {
		rs.RefreshLoop(ctx, time.Hour, func(string, ...any) { logged.Add(1) })
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for logged.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no initial refresh")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshLoop did not stop")
	}
	if ok, _ := rs.Contains("https://other.example/x", netip.MustParseAddr("2001:db8::1")); !ok {
		t.Fatal("other list not loaded (one failing URL must not block the rest)")
	}
}

func TestHTTPFetcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok.json" {
			w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	f := HTTPFetcher(5 * time.Second)
	b, err := f(context.Background(), srv.URL+"/ok.json")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := ParsePrefixes(b); err != nil || len(p) != 1 {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := f(context.Background(), srv.URL+"/missing"); err == nil {
		t.Fatal("404 accepted")
	}
}
