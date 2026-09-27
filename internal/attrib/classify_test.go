package attrib

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// fakeResolver answers from maps. A value of errHang blocks until the
// context is done (simulating a DNS timeout).
type fakeResolver struct {
	ptr   map[string][]string
	host  map[string][]string
	errs  map[string]error // keyed by ip or host name
	calls atomic.Int64
}

var errHang = errors.New("hang")

func (f *fakeResolver) lookup(ctx context.Context, key string, m map[string][]string) ([]string, error) {
	f.calls.Add(1)
	if err, ok := f.errs[key]; ok {
		if err == errHang {
			<-ctx.Done()
			return nil, &net.DNSError{Err: "i/o timeout", Name: key, IsTimeout: true}
		}
		return nil, err
	}
	if v, ok := m[key]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: key, IsNotFound: true}
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return f.lookup(ctx, addr, f.ptr)
}

func (f *fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f.lookup(ctx, host, f.host)
}

const testCrawlersYAML = `
- org: Google
  name: Googlebot
  ua_patterns: ['\bGooglebot\b']
  verify: {method: rdns, domains: [googlebot.com]}
- org: Static Co
  name: StaticBot
  ua_patterns: ['StaticBot']
  verify: {method: ip_ranges, cidrs: ["203.0.113.0/24", "2001:db8:5::/48"]}
- org: URL Co
  name: URLBot
  ua_patterns: ['URLBot']
  verify: {method: ip_ranges, url: "https://vendor.example/urlbot.json"}
- org: None Co
  name: NoneBot
  ua_patterns: ['NoneBot']
  verify: none
`

func testCrawlers(t *testing.T) []Crawler {
	t.Helper()
	cs, err := ParseCrawlers([]byte(testCrawlersYAML))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func newTestResolver() *fakeResolver {
	return &fakeResolver{
		ptr: map[string][]string{
			"192.0.2.10":  {"crawl-192-0-2-10.googlebot.com."},
			"192.0.2.11":  {"geo-crawl-192-0-2-11.geo.GOOGLEBOT.com"},
			"192.0.2.20":  {"crawl-192-0-2-20.evilgooglebot.com."},
			"192.0.2.21":  {"googlebot.com.evil.example."},
			"192.0.2.30":  {"crawl-192-0-2-30.googlebot.com."}, // forward points elsewhere
			"192.0.2.31":  {"crawl-192-0-2-31.googlebot.com."}, // forward NXDOMAIN
			"192.0.2.32":  {"crawl-192-0-2-32.googlebot.com."}, // forward SERVFAIL
			"192.0.2.40":  {"attacker.example.", "crawl-192-0-2-40.googlebot.com."},
			"2001:db8::a": {"crawl-v6.googlebot.com."},
		},
		host: map[string][]string{
			"crawl-192-0-2-10.googlebot.com":         {"192.0.2.10"},
			"geo-crawl-192-0-2-11.geo.googlebot.com": {"192.0.2.11"},
			"crawl-192-0-2-20.evilgooglebot.com":     {"192.0.2.20"},
			"googlebot.com.evil.example":             {"192.0.2.21"},
			"crawl-192-0-2-30.googlebot.com":         {"198.51.100.30"},
			"crawl-192-0-2-40.googlebot.com":         {"2001:db8::40", "192.0.2.40"},
			"crawl-v6.googlebot.com":                 {"2001:db8::a"},
		},
		errs: map[string]error{
			"192.0.2.50":                     errHang,
			"192.0.2.51":                     &net.DNSError{Err: "server misbehaving", IsTemporary: true},
			"crawl-192-0-2-32.googlebot.com": &net.DNSError{Err: "server misbehaving", IsTemporary: true},
		},
	}
}

func TestClassifyStatuses(t *testing.T) {
	ctx := context.Background()
	clk := newClock()
	cs := testCrawlers(t)
	ff := &fakeFetcher{body: map[string]string{"https://vendor.example/urlbot.json": `{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}`}}
	rs := NewRangeStore(RangeOptions{Crawlers: cs, Fetcher: ff.fetch, Now: clk.Now})
	if err := rs.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	c := NewClassifier(Options{Crawlers: cs, Resolver: newTestResolver(), Ranges: rs, DNSTimeout: 50 * time.Millisecond, Now: clk.Now})
	gb := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	for _, tc := range []struct {
		name, ip, ua   string
		status, method string
		org            string
		indeterminate  bool
	}{
		{"anonymous", "192.0.2.99", "Mozilla/5.0 Firefox/130.0", logstore.StatusAnonymous, logstore.MethodNone, "", false},
		{"anonymous empty ua", "192.0.2.99", "", logstore.StatusAnonymous, logstore.MethodNone, "", false},
		{"unverifiable", "192.0.2.99", "NoneBot/1.0", logstore.StatusUnverifiable, logstore.MethodNone, "None Co", false},
		{"rdns verified", "192.0.2.10", gb, logstore.StatusVerified, logstore.MethodRDNS, "Google", false},
		{"rdns verified subdomain+case", "192.0.2.11", gb, logstore.StatusVerified, logstore.MethodRDNS, "Google", false},
		{"rdns verified v6", "2001:db8::a", gb, logstore.StatusVerified, logstore.MethodRDNS, "Google", false},
		{"rdns verified second PTR", "192.0.2.40", gb, logstore.StatusVerified, logstore.MethodRDNS, "Google", false},
		{"suffix boundary", "192.0.2.20", gb, logstore.StatusSpoofed, logstore.MethodRDNS, "Google", false},
		{"domain in middle", "192.0.2.21", gb, logstore.StatusSpoofed, logstore.MethodRDNS, "Google", false},
		{"forward mismatch", "192.0.2.30", gb, logstore.StatusSpoofed, logstore.MethodRDNS, "Google", false},
		{"forward nxdomain", "192.0.2.31", gb, logstore.StatusSpoofed, logstore.MethodRDNS, "Google", false},
		{"no PTR", "198.51.100.200", gb, logstore.StatusSpoofed, logstore.MethodRDNS, "Google", false},
		{"PTR timeout", "192.0.2.50", gb, logstore.StatusUnverifiable, logstore.MethodNone, "Google", true},
		{"PTR servfail", "192.0.2.51", gb, logstore.StatusUnverifiable, logstore.MethodNone, "Google", true},
		{"forward servfail", "192.0.2.32", gb, logstore.StatusUnverifiable, logstore.MethodNone, "Google", true},
		{"static range verified", "203.0.113.7", "StaticBot/2", logstore.StatusVerified, logstore.MethodIPRange, "Static Co", false},
		{"static range 4in6", "::ffff:203.0.113.7", "StaticBot/2", logstore.StatusVerified, logstore.MethodIPRange, "Static Co", false},
		{"static range v6", "2001:db8:5::1", "StaticBot/2", logstore.StatusVerified, logstore.MethodIPRange, "Static Co", false},
		{"static range spoofed", "192.0.2.7", "StaticBot/2", logstore.StatusSpoofed, logstore.MethodIPRange, "Static Co", false},
		{"url range verified", "198.51.100.8", "URLBot", logstore.StatusVerified, logstore.MethodIPRange, "URL Co", false},
		{"url range spoofed", "192.0.2.8", "URLBot", logstore.StatusSpoofed, logstore.MethodIPRange, "URL Co", false},
		{"bad ip", "not-an-ip", "StaticBot", logstore.StatusUnverifiable, logstore.MethodNone, "Static Co", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			id, err := c.ClassifyDetailed(ctx, tc.ip, tc.ua)
			if time.Since(start) > 2*time.Second {
				t.Error("DNS timeout not enforced")
			}
			if id.Status != tc.status || id.Method != tc.method || id.ClaimedOrg != tc.org {
				t.Errorf("got %+v", id)
			}
			if id.IP != tc.ip || id.UserAgent != tc.ua || id.CheckedAt != clk.Now().UnixMilli() {
				t.Errorf("identity fields: %+v", id)
			}
			if tc.indeterminate != errors.Is(err, ErrIndeterminate) {
				t.Errorf("err=%v", err)
			}
			if !tc.indeterminate && err != nil {
				t.Errorf("unexpected err %v", err)
			}
			if got := c.Classify(ctx, tc.ip, tc.ua); got.Status != tc.status {
				t.Errorf("Classify status %s", got.Status)
			}
		})
	}
}

func TestClassifyURLRangesUnavailable(t *testing.T) {
	cs := testCrawlers(t)
	// No RangeStore at all, and a store whose list never loaded: both
	// indeterminate, never spoofed.
	for _, rs := range []*RangeStore{nil, NewRangeStore(RangeOptions{Crawlers: cs, Fetcher: (&fakeFetcher{err: errors.New("x")}).fetch})} {
		c := NewClassifier(Options{Crawlers: cs, Resolver: newTestResolver(), Ranges: rs})
		id, err := c.ClassifyDetailed(context.Background(), "192.0.2.8", "URLBot")
		if !errors.Is(err, ErrIndeterminate) || id.Status != logstore.StatusUnverifiable {
			t.Fatalf("%+v %v", id, err)
		}
	}
}

func TestDomainMatch(t *testing.T) {
	d := []string{"googlebot.com", "search.msn.com"}
	for host, want := range map[string]bool{
		"googlebot.com": true, "a.googlebot.com": true, "a.b.googlebot.com": true,
		"evilgooglebot.com": false, "googlebot.com.evil": false, "xgooglebot.com": false,
		"msnbot-1.search.msn.com": true, "search.msn.com.example": false, "msn.com": false, "": false,
	} {
		if got := domainMatch(host, d); got != want {
			t.Errorf("domainMatch(%q)=%v", host, got)
		}
	}
}

// memStore is an in-memory IdentityStore.
type memStore struct {
	mu   sync.Mutex
	m    map[[2]string]logstore.Identity
	puts atomic.Int64
}

func newMemStore() *memStore { return &memStore{m: map[[2]string]logstore.Identity{}} }

func (s *memStore) GetIdentity(_ context.Context, ip, ua string) (logstore.Identity, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.m[[2]string{ip, ua}]
	return id, ok, nil
}

func (s *memStore) UpsertIdentity(_ context.Context, id logstore.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts.Add(1)
	s.m[[2]string{id.IP, id.UserAgent}] = id
	return nil
}

func (s *memStore) get(ip, ua string) (logstore.Identity, bool) {
	id, ok, _ := s.GetIdentity(context.Background(), ip, ua)
	return id, ok
}

func TestObserveNeverBlocks(t *testing.T) {
	c := NewClassifier(Options{Crawlers: testCrawlers(t), QueueSize: 2, Resolver: newTestResolver()})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 1000 {
			c.Observe(fmt.Sprintf("192.0.2.%d", i%250), fmt.Sprintf("ua-%d", i))
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Observe blocked")
	}
	st := c.Stats()
	if st.Queued != 2 || st.Dropped != 998 {
		t.Fatalf("stats %+v", st)
	}
	// A dropped pair is forgotten, so it can be queued once there is room.
	<-c.queue
	c.Observe("192.0.2.3", "ua-3")
	if c.Stats().Queued != 2 {
		t.Fatal("dropped pair was not retried")
	}
}

func TestObserveDedupAndExpiry(t *testing.T) {
	clk := newClock()
	c := NewClassifier(Options{QueueSize: 100, SeenTTL: time.Minute, Now: clk.Now, Resolver: newTestResolver()})
	c.Observe("192.0.2.1", "a")
	c.Observe("192.0.2.1", "a")
	c.Observe("192.0.2.1", "b")
	if q := c.Stats().Queued; q != 2 {
		t.Fatalf("queued %d want 2", q)
	}
	clk.Add(2 * time.Minute)
	c.Observe("192.0.2.1", "a")
	if q := c.Stats().Queued; q != 3 {
		t.Fatalf("expired pair not requeued: %d", q)
	}
}

func TestObserveBoundedAndNoAlloc(t *testing.T) {
	c := NewClassifier(Options{QueueSize: 1, SeenMax: 64, Resolver: newTestResolver()})
	ips := make([]string, 5000)
	for i := range ips {
		ips[i] = fmt.Sprintf("2001:db8::%x", i)
	}
	for _, ip := range ips {
		c.Observe(ip, "ua")
	}
	for i := range c.seen {
		if n := len(c.seen[i].m); n > 64/seenShards+1 {
			t.Fatalf("shard %d has %d entries", i, n)
		}
	}
	c.Observe("192.0.2.1", "seen")
	i := 0
	if n := testing.AllocsPerRun(1000, func() {
		c.Observe("192.0.2.1", "seen")  // dedupe path
		c.Observe(ips[i%len(ips)], "x") // enqueue/drop path
		i++
	}); n != 0 {
		t.Fatalf("Observe allocates %v per run", n)
	}
}

func TestRunTTLSkipAndStore(t *testing.T) {
	clk := newClock()
	cs := testCrawlers(t)
	res := newTestResolver()
	st := newMemStore()
	ttl := 7 * 24 * time.Hour
	gb := "Googlebot/2.1"
	fresh := logstore.Identity{IP: "192.0.2.10", UserAgent: gb, ClaimedOrg: "Google", Status: logstore.StatusSpoofed,
		Method: logstore.MethodRDNS, CheckedAt: clk.Now().Add(-time.Hour).UnixMilli()}
	stale := logstore.Identity{IP: "192.0.2.11", UserAgent: gb, ClaimedOrg: "Google", Status: logstore.StatusSpoofed,
		Method: logstore.MethodRDNS, CheckedAt: clk.Now().Add(-ttl - time.Hour).UnixMilli()}
	staleTimeout := logstore.Identity{IP: "192.0.2.51", UserAgent: gb, ClaimedOrg: "Google", Status: logstore.StatusVerified,
		Method: logstore.MethodRDNS, CheckedAt: clk.Now().Add(-ttl - time.Hour).UnixMilli()}
	for _, id := range []logstore.Identity{fresh, stale, staleTimeout} {
		st.UpsertIdentity(context.Background(), id)
	}
	st.puts.Store(0)

	c := NewClassifier(Options{Crawlers: cs, Resolver: res, Store: st, TTL: ttl, DNSTimeout: 20 * time.Millisecond,
		Workers: 3, QueueSize: 16, Now: clk.Now, RetryAfter: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()

	c.Observe(fresh.IP, gb)        // fresh: skipped, no DNS
	c.Observe(stale.IP, gb)        // stale: re-verified
	c.Observe(staleTimeout.IP, gb) // stale + DNS failure: old row kept
	c.Observe("192.0.2.50", gb)    // new + DNS timeout: unverifiable, retry soon
	c.Observe("192.0.2.99", "Mozilla/5.0")

	deadline := time.Now().Add(5 * time.Second)
	for c.Stats().Classified < 4 || st.puts.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("timeout: %+v puts=%d", c.Stats(), st.puts.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if got, _ := st.get(fresh.IP, gb); got != fresh {
		t.Errorf("fresh identity changed: %+v", got)
	}
	if got, _ := st.get(stale.IP, gb); got.Status != logstore.StatusVerified || got.CheckedAt != clk.Now().UnixMilli() {
		t.Errorf("stale not re-verified: %+v", got)
	}
	if got, _ := st.get(staleTimeout.IP, gb); got != staleTimeout {
		t.Errorf("indeterminate result overwrote existing row: %+v", got)
	}
	got, ok := st.get("192.0.2.50", gb)
	wantAt := clk.Now().Add(time.Hour - ttl).UnixMilli()
	if !ok || got.Status != logstore.StatusUnverifiable || got.CheckedAt != wantAt {
		t.Errorf("timeout row: %+v ok=%v want checked_at %d", got, ok, wantAt)
	}
	if got, _ := st.get("192.0.2.99", "Mozilla/5.0"); got.Status != logstore.StatusAnonymous {
		t.Errorf("anonymous: %+v", got)
	}
	if st.puts.Load() != 3 {
		t.Errorf("puts=%d want 3", st.puts.Load())
	}
	if c.Stats().Classified != 4 {
		t.Errorf("classified=%d want 4 (fresh one skipped)", c.Stats().Classified)
	}
}

func TestReverifyStale(t *testing.T) {
	ctx := context.Background()
	clk := newClock()
	s, err := logstore.Open(filepath.Join(t.TempDir(), "lawn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ttl := 7 * 24 * time.Hour
	gb := "Googlebot/2.1"
	now := clk.Now().UnixMilli()
	mk := func(ip, ua string, viol bool) logstore.Request {
		return logstore.Request{TsStart: now, IP: ip, UserAgent: ua, Method: "GET", Path: "/lawn/x", IsViolation: viol, Depth: 1}
	}
	if err := s.InsertRequests(ctx, []logstore.Request{
		mk("192.0.2.10", gb, true),         // A: violator, no identity -> classify
		mk("192.0.2.11", gb, true),         // B: stale identity -> reclassify
		mk("192.0.2.99", "Firefox", false), // C: non-violator, no identity -> classify (anonymous)
		mk("192.0.2.12", "NoneBot", true),  // E: fresh identity -> skip
	}); err != nil {
		t.Fatal(err)
	}
	old := clk.Now().Add(-ttl - time.Hour).UnixMilli()
	for _, id := range []logstore.Identity{
		{IP: "192.0.2.11", UserAgent: gb, Status: logstore.StatusSpoofed, Method: logstore.MethodRDNS, CheckedAt: old},
		{IP: "192.0.2.77", UserAgent: gb, Status: logstore.StatusSpoofed, Method: logstore.MethodRDNS, CheckedAt: old}, // D: no raw requests
		{IP: "192.0.2.12", UserAgent: "NoneBot", Status: logstore.StatusUnverifiable, Method: logstore.MethodNone, CheckedAt: now},
	} {
		if err := s.UpsertIdentity(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	c := NewClassifier(Options{Crawlers: testCrawlers(t), Resolver: newTestResolver(), Store: s, TTL: ttl, Now: clk.Now, Workers: 2})
	n, err := c.ReverifyStale(ctx, s.DB())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("n=%d want 3", n)
	}
	if id, ok, _ := s.GetIdentity(ctx, "192.0.2.10", gb); !ok || id.Status != logstore.StatusVerified {
		t.Errorf("A: %+v %v", id, ok)
	}
	if id, _, _ := s.GetIdentity(ctx, "192.0.2.11", gb); id.Status != logstore.StatusVerified || id.CheckedAt != now {
		t.Errorf("B: %+v", id)
	}
	if id, ok, _ := s.GetIdentity(ctx, "192.0.2.99", "Firefox"); !ok || id.Status != logstore.StatusAnonymous {
		t.Errorf("C: non-violators must be classified too: %+v %v", id, ok)
	}
	// Reverse DNS is recorded for every job's IP (the test resolver has no
	// PTR for 192.0.2.99, which is cached as "").
	if _, ok, _ := s.GetHost(ctx, "192.0.2.99"); !ok {
		t.Error("C: host row not recorded")
	}
	if id, _, _ := s.GetIdentity(ctx, "192.0.2.77", gb); id.CheckedAt != old {
		t.Errorf("D touched: %+v", id)
	}
	// Second pass: nothing left to do.
	if n, err := c.ReverifyStale(ctx, s.DB()); err != nil || n != 0 {
		t.Fatalf("second pass n=%d err=%v", n, err)
	}
}

func TestSetCrawlers(t *testing.T) {
	c := NewClassifier(Options{Resolver: newTestResolver()})
	if id := c.Classify(context.Background(), "192.0.2.1", "NoneBot"); id.Status != logstore.StatusAnonymous {
		t.Fatalf("%+v", id)
	}
	c.SetCrawlers(testCrawlers(t))
	if id := c.Classify(context.Background(), "192.0.2.1", "NoneBot"); id.Status != logstore.StatusUnverifiable {
		t.Fatalf("%+v", id)
	}
}

// hostMemStore adds the optional HostStore to memStore.
type hostMemStore struct {
	*memStore
	hmu   sync.Mutex
	hosts map[string]logstore.Host
}

func (s *hostMemStore) GetHost(_ context.Context, ip string) (logstore.Host, bool, error) {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	h, ok := s.hosts[ip]
	return h, ok, nil
}

func (s *hostMemStore) UpsertHost(_ context.Context, h logstore.Host) error {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	s.hosts[h.IP] = h
	return nil
}

func TestRecordHostPTR(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	res := &fakeResolver{
		ptr:  map[string][]string{"198.51.100.1": {"Crawl-7.NewBot.Example."}},
		errs: map[string]error{"198.51.100.3": errors.New("servfail")},
	}
	st := &hostMemStore{memStore: newMemStore(), hosts: map[string]logstore.Host{}}
	c := NewClassifier(Options{Crawlers: testCrawlers(t), Resolver: res, Store: st,
		TTL: 7 * 24 * time.Hour, DNSTimeout: time.Second, Now: func() time.Time { return now }})
	ctx := context.Background()

	c.handle(ctx, "198.51.100.1", "NewBot/0.1") // PTR present
	c.handle(ctx, "198.51.100.2", "curl/8")     // NXDOMAIN
	c.handle(ctx, "198.51.100.3", "x")          // resolver failure
	if h := st.hosts["198.51.100.1"]; h.PTR != "crawl-7.newbot.example" || h.CheckedAt != now.UnixMilli() {
		t.Errorf("ptr row: %+v", h)
	}
	if h, ok := st.hosts["198.51.100.2"]; !ok || h.PTR != "" {
		t.Errorf("no-PTR must be cached as empty: %+v ok=%v", h, ok)
	}
	if _, ok := st.hosts["198.51.100.3"]; ok {
		t.Error("DNS failure must not be cached")
	}
	// Anonymous identities are still classified alongside.
	if id, ok := st.get("198.51.100.2", "curl/8"); !ok || id.Status != logstore.StatusAnonymous {
		t.Errorf("identity: %+v ok=%v", id, ok)
	}
	// Fresh rows are not looked up again; stale ones are.
	before := c.Stats().PTRLookups
	c.handle(ctx, "198.51.100.1", "OtherUA/1")
	if c.Stats().PTRLookups != before {
		t.Error("fresh host row was looked up again")
	}
	now = now.Add(8 * 24 * time.Hour)
	c.handle(ctx, "198.51.100.1", "OtherUA/1")
	if c.Stats().PTRLookups != before+1 {
		t.Error("stale host row was not refreshed")
	}
}
