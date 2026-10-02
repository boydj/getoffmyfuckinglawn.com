package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/drip"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

type fakePages struct{}

func (fakePages) Render(buf *bytes.Buffer, path string) {
	buf.WriteString("<html><title>" + path + "</title><body><nav><a href=\"/lawn/next\">next</a></nav>\n" + strings.Repeat("x", 100) + "</body></html>")
}
func (fakePages) IDs(path string) (page, parent uint32, hasParent bool) {
	// Deterministic stand-ins: page = len(path); a "/lawn/next" link
	// claims parent 1.
	if path == "/lawn/next" {
		return uint32(len(path)), 1, true
	}
	return uint32(len(path)), 0, false
}
func (fakePages) EntryURLs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "/lawn/entry" + strconv.Itoa(i)
	}
	return out
}

type fakeDripper struct {
	mu      sync.Mutex
	drips   int
	fasts   int
	egress  *fakeEgress
	plans   []drip.Plan
	outcome drip.Outcome // what DripWith reports
}

func (d *fakeDripper) DripWith(_ context.Context, w http.ResponseWriter, body []byte, _ uint64, plan drip.Plan) (int64, drip.Outcome, error) {
	d.mu.Lock()
	d.drips++
	d.plans = append(d.plans, plan)
	o := d.outcome
	d.mu.Unlock()
	n, err := w.Write(body)
	d.egress.Add(int64(n))
	return int64(n), o, err
}
func (d *fakeDripper) Fast(w http.ResponseWriter, body []byte) (int64, error) {
	d.mu.Lock()
	d.fasts++
	d.mu.Unlock()
	n, err := w.Write(body)
	d.egress.Add(int64(n))
	return int64(n), err
}

type fakeLimiter struct {
	mu       sync.Mutex
	allow    bool
	active   int
	acquired []netip.Addr
	asns     []uint32
}

func (l *fakeLimiter) Acquire(ip netip.Addr, asn uint32) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.allow {
		return false
	}
	l.active++
	l.acquired = append(l.acquired, ip)
	l.asns = append(l.asns, asn)
	return true
}
func (l *fakeLimiter) Release(netip.Addr, uint32) { l.mu.Lock(); l.active--; l.mu.Unlock() }
func (l *fakeLimiter) Active() int                { l.mu.Lock(); defer l.mu.Unlock(); return l.active }

type fakeEgress struct {
	mu sync.Mutex
	n  int64
}

func (e *fakeEgress) Add(n int64)  { e.mu.Lock(); e.n += n; e.mu.Unlock() }
func (e *fakeEgress) Today() int64 { e.mu.Lock(); defer e.mu.Unlock(); return e.n }

type fakeLogger struct {
	mu     sync.Mutex
	reqs   []logstore.Request
	robots []logstore.RobotsFetch
	full   bool
}

func (l *fakeLogger) LogRequest(r logstore.Request) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.full {
		return false
	}
	l.reqs = append(l.reqs, r)
	return true
}
func (l *fakeLogger) LogRobots(r logstore.RobotsFetch) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.robots = append(l.robots, r)
	return true
}

type fakeObserver struct {
	mu    sync.Mutex
	pairs []string
}

func (o *fakeObserver) Observe(ip, ua string) {
	o.mu.Lock()
	o.pairs = append(o.pairs, ip+"|"+ua)
	o.mu.Unlock()
}

type fakeASN map[string]uint32

func (f fakeASN) Lookup(a netip.Addr) (uint32, string, bool) {
	n, ok := f[a.String()]
	if !ok {
		return 0, "", false
	}
	return n, "TEST-AS" + strconv.Itoa(int(n)), true
}

func (f fakeASN) LookupCC(a netip.Addr) (uint32, string, string, bool) {
	n, org, ok := f.Lookup(a)
	if !ok {
		return 0, "", "", false
	}
	return n, org, "NL", true
}

type rig struct {
	srv  *Server
	lim  *fakeLimiter
	egr  *fakeEgress
	drip *fakeDripper
	log  *fakeLogger
	obs  *fakeObserver
	pub  string
}

func newRig(t *testing.T, opts ...func(*Deps)) *rig {
	t.Helper()
	pub := t.TempDir()
	egr := &fakeEgress{}
	r := &rig{lim: &fakeLimiter{allow: true}, egr: egr, drip: &fakeDripper{egress: egr}, log: &fakeLogger{}, obs: &fakeObserver{}, pub: pub}
	clock := time.UnixMilli(1_700_000_000_000)
	d := Deps{
		Pages: fakePages{}, Dripper: r.drip, Limiter: r.lim, Egress: egr, Logger: r.log, Observer: r.obs,
		ASN:       fakeASN{"203.0.113.7": 64500},
		Trusted:   []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		PublicDir: pub, Home: []byte("<html>home</html>"), BaseURL: "https://example.test",
		Now: func() time.Time { clock = clock.Add(250 * time.Millisecond); return clock },
	}
	for _, o := range opts {
		o(&d)
	}
	r.srv = New(d)
	return r
}

func (r *rig) do(method, path, xff, ua string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:5555"
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	req.Header.Set("User-Agent", ua)
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, req)
	return w
}

func TestRoutes(t *testing.T) {
	r := newRig(t)
	cases := []struct {
		path, ctype string
		status      int
		contains    string
	}{
		{"/", "text/html", 200, "home"},
		{"/robots.txt", "text/plain", 200, "Disallow: /lawn/"},
		{"/sitemap.xml", "application/xml", 200, "https://example.test/lawn/entry0"},
		{"/healthz", "text/plain", 200, "ok"},
		{"/nope", "text/plain", 404, "get off my lawn"},
		{"/shame/", "", 404, ""},
		{"/lawn/abc", "text/html", 200, "<title>/lawn/abc</title>"},
	}
	for _, c := range cases {
		w := r.do("GET", c.path, "203.0.113.7", "TestBot/1.0")
		if w.Code != c.status {
			t.Errorf("%s: status %d want %d", c.path, w.Code, c.status)
		}
		if !strings.HasPrefix(w.Header().Get("Content-Type"), c.ctype) {
			t.Errorf("%s: content-type %q", c.path, w.Header().Get("Content-Type"))
		}
		if !strings.Contains(w.Body.String(), c.contains) {
			t.Errorf("%s: body %q", c.path, w.Body.String())
		}
	}
	if len(r.log.reqs) != len(cases) {
		t.Fatalf("every request must be logged: got %d want %d", len(r.log.reqs), len(cases))
	}
	for _, rec := range r.log.reqs {
		if rec.IP != "203.0.113.7" || rec.UserAgent != "TestBot/1.0" || rec.ASN != 64500 || rec.ASNOrg != "TEST-AS64500" || rec.Country != "NL" {
			t.Errorf("bad attribution: %+v", rec)
		}
		if rec.TsEnd < rec.TsStart {
			t.Errorf("ts_end before ts_start: %+v", rec)
		}
		want := strings.HasPrefix(rec.Path, "/lawn/")
		if rec.IsViolation != want {
			t.Errorf("%s: is_violation=%v", rec.Path, rec.IsViolation)
		}
		if !want && (rec.Depth != -1 || rec.PageID != 0 || rec.ParentID != 0) {
			t.Errorf("%s: depth and page ids must be NULL outside /lawn/", rec.Path)
		}
		if want && rec.PageID != uint32(len(rec.Path)) {
			t.Errorf("%s: page_id %d", rec.Path, rec.PageID)
		}
	}
	if len(r.log.robots) != 1 || r.log.robots[0].IP != "203.0.113.7" {
		t.Errorf("robots fetch not logged: %+v", r.log.robots)
	}
	// Every visit except /healthz is sent for classification.
	if len(r.obs.pairs) != len(cases)-1 || r.obs.pairs[0] != "203.0.113.7|TestBot/1.0" {
		t.Errorf("observer: %v", r.obs.pairs)
	}
	if r.drip.drips != 1 || r.lim.active != 0 || r.lim.asns[0] != 64500 {
		t.Errorf("drip=%d active=%d asns=%v", r.drip.drips, r.lim.active, r.lim.asns)
	}
}

func TestMazeOverLimitServesFast(t *testing.T) {
	r := newRig(t)
	r.lim.allow = false
	w := r.do("GET", "/lawn/x", "203.0.113.7", "ua")
	if w.Code != 200 || r.drip.fasts != 1 || r.drip.drips != 0 {
		t.Fatalf("code=%d fasts=%d drips=%d", w.Code, r.drip.fasts, r.drip.drips)
	}
	rec := r.log.reqs[0]
	if rec.Dripped || !rec.IsViolation || rec.BytesSent != int64(w.Body.Len()) || rec.Depth != 0 {
		t.Fatalf("rec %+v", rec)
	}
	if !strings.Contains(w.Body.String(), "full") || len(w.Body.String()) > 200 {
		t.Errorf("shed page should be small and static: %q", w.Body.String())
	}
	if w.Header().Get("Content-Length") == "" {
		t.Error("fast path should set Content-Length")
	}
}

func TestMethodNotAllowedAndHead(t *testing.T) {
	r := newRig(t)
	if w := r.do("POST", "/lawn/x", "", "ua"); w.Code != 405 {
		t.Fatalf("POST: %d", w.Code)
	}
	w := r.do("HEAD", "/lawn/x", "", "ua")
	if w.Code != 200 || w.Body.Len() != 0 || r.drip.drips != 0 {
		t.Fatalf("HEAD: %d len=%d", w.Code, w.Body.Len())
	}
	// HEAD on /lawn still counts as a violation.
	if !r.log.reqs[1].IsViolation {
		t.Fatal("HEAD /lawn should be a violation")
	}
	// Direct peer (no XFF) is the trusted proxy itself.
	if r.log.reqs[0].IP != "127.0.0.1" {
		t.Fatalf("ip %q", r.log.reqs[0].IP)
	}
}

func TestLogDropCounted(t *testing.T) {
	r := newRig(t)
	r.log.full = true
	r.do("GET", "/", "", "ua")
	if r.srv.Metrics.LogDropped.Load() != 1 {
		t.Fatal("drop not counted")
	}
}

func TestShameStatic(t *testing.T) {
	r := newRig(t)
	must(t, os.MkdirAll(filepath.Join(r.pub, "shame", "org", "acme"), 0o755))
	must(t, os.MkdirAll(filepath.Join(r.pub, ".shame-tmp", "x"), 0o755))
	must(t, os.MkdirAll(filepath.Join(r.pub, "shame", "noindex"), 0o755))
	must(t, os.WriteFile(filepath.Join(r.pub, "shame", "index.html"), []byte("<h1>board</h1>"), 0o644))
	must(t, os.WriteFile(filepath.Join(r.pub, "shame", "org", "acme", "index.html"), []byte("acme"), 0o644))
	must(t, os.WriteFile(filepath.Join(r.pub, "shame", "feed.json"), []byte("[]"), 0o644))
	must(t, os.WriteFile(filepath.Join(r.pub, "secret.txt"), []byte("no"), 0o644))

	for path, want := range map[string]int{
		"/shame/":                200,
		"/shame/org/acme/":       200,
		"/shame/feed.json":       200,
		"/shame":                 301,
		"/shame/noindex/":        404,
		"/shame/../secret.txt":   404,
		"/shame/.shame-tmp/x/":   404,
		"/shame/does-not-exist/": 404,
	} {
		w := r.do("GET", path, "", "ua")
		if w.Code != want {
			t.Errorf("%s: %d want %d", path, w.Code, want)
		}
	}
	w := r.do("GET", "/shame/", "", "ua")
	if !strings.Contains(w.Body.String(), "board") {
		t.Errorf("body %q", w.Body.String())
	}
	last := r.log.reqs[len(r.log.reqs)-1]
	if last.BytesSent != int64(len("<h1>board</h1>")) || last.IsViolation {
		t.Errorf("shame log %+v", last)
	}
}

// The published data files answer conditional requests with 304 (promised
// under "Using this data" on the homepage).
func TestShameConditionalGet(t *testing.T) {
	r := newRig(t)
	must(t, os.MkdirAll(filepath.Join(r.pub, "shame"), 0o755))
	must(t, os.WriteFile(filepath.Join(r.pub, "shame", "feed.json"), []byte("[]\n"), 0o644))
	get := func(ims string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/shame/feed.json", nil)
		req.Header.Set("User-Agent", "feed-reader/1")
		if ims != "" {
			req.Header.Set("If-Modified-Since", ims)
		}
		w := httptest.NewRecorder()
		r.srv.ServeHTTP(w, req)
		return w
	}
	w := get("")
	lm := w.Header().Get("Last-Modified")
	if w.Code != 200 || lm == "" || w.Header().Get("Cache-Control") != "public, max-age=60" {
		t.Fatalf("first fetch: %d last-modified=%q cache=%q", w.Code, lm, w.Header().Get("Cache-Control"))
	}
	if w := get(lm); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Errorf("conditional fetch: %d, %d bytes", w.Code, w.Body.Len())
	}
}

func TestMetricsExposition(t *testing.T) {
	r := newRig(t)
	r.do("GET", "/lawn/a", "", "ua")
	reg := NewMetricsRegistry(r.srv)
	reg.Register(Gauge{Name: "lawn_test_extra", Help: "x", Value: func() float64 { return 42 }})
	ts := httptest.NewServer(NewAdminServer("", reg, nil).Handler)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(b)
	for _, want := range []string{
		`lawn_requests_total{route="lawn"} 1`,
		"lawn_violations_total 1",
		"lawn_dripped_total 1",
		"lawn_active_drips 0",
		"lawn_test_extra 42",
		"# TYPE lawn_bytes_sent_total counter",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n%s", want, body)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestMazeEndReasonsAndHeaders(t *testing.T) {
	r := newRig(t)
	req := httptest.NewRequest("GET", "/lawn/a", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("User-Agent", "Bot/1")
	req.Header.Set("Referer", "https://example.test/sitemap.xml")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip, br")
	r.srv.ServeHTTP(httptest.NewRecorder(), req)
	rec := r.log.reqs[0]
	if rec.EndReason != "complete" || rec.Referer != "https://example.test/sitemap.xml" || rec.Accept != "text/html" ||
		rec.AcceptLanguage != "en-US" || rec.AcceptEncoding != "gzip, br" {
		t.Fatalf("rec %+v", rec)
	}
	// The lead is the page through </nav>.
	wantLead := strings.Index("<html><title>/lawn/a</title><body><nav><a href=\"/lawn/next\">next</a></nav>\n", "</nav>\n") + len("</nav>\n")
	if p := r.drip.plans[0]; p.Lead != wantLead {
		t.Fatalf("lead %d, want %d", p.Lead, wantLead)
	}

	r.lim.allow = false
	r.do("GET", "/lawn/b", "203.0.113.7", "Bot/1")
	r.lim.allow = true
	r.do("HEAD", "/lawn/c", "203.0.113.7", "Bot/1")
	r.do("GET", "/", "203.0.113.7", "Bot/1")
	for i, want := range []string{"complete", "shed", "head", ""} {
		if got := r.log.reqs[i].EndReason; got != want {
			t.Errorf("request %d (%s): end_reason %q, want %q", i, r.log.reqs[i].Path, got, want)
		}
	}
	if r.srv.Metrics.DripEnds[drip.Completed].Load() != 1 {
		t.Error("drip end metric not counted")
	}
}

func TestAdaptiveBudget(t *testing.T) {
	r := newRig(t)
	r.srv.d.Patience = drip.NewPatience(drip.PatienceOptions{Max: 10 * time.Minute, Factor: 0.8})
	r.drip.outcome = drip.ClientGone // the bot hangs up on every page
	r.srv.SetASN(fakeASN{"203.0.113.7": 64500, "203.0.113.99": 64500})

	r.do("GET", "/lawn/1", "203.0.113.7", "Bot/1")
	r.do("GET", "/lawn/2", "203.0.113.99", "Bot/1") // same ASN, rotated IP
	r.do("GET", "/lawn/3", "198.51.100.1", "Bot/1") // no ASN known: its own /24 bucket
	r.do("GET", "/lawn/4", "203.0.113.7", "OtherBot/2")

	want := []time.Duration{
		10 * time.Minute,       // unknown client: full budget
		250 * time.Millisecond, // learned: gave up after 250ms (fake clock), 0.8x floored at 250ms
		10 * time.Minute,       // different network bucket
		10 * time.Minute,       // different UA
	}
	for i, w := range want {
		if got := r.drip.plans[i].MaxDuration; got != w {
			t.Errorf("request %d budget %v, want %v", i+1, got, w)
		}
	}
	if r.log.reqs[0].EndReason != "client_gone" {
		t.Errorf("end reason %q", r.log.reqs[0].EndReason)
	}
}

func TestFingerprintCapture(t *testing.T) {
	r := newRig(t)
	send := func(remote string, extra map[string]string) logstore.Request {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = remote
		req.Header = http.Header{}
		req.Header.Set("User-Agent", "Bot/1")
		req.Header.Set("Accept", "*/*")
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		r.srv.ServeHTTP(httptest.NewRecorder(), req)
		return r.log.reqs[len(r.log.reqs)-1]
	}
	// Through Caddy (trusted peer): proxy headers are dropped from the
	// name list, and proto/TLS come from Caddy's headers.
	viaCaddy := send("127.0.0.1:1", map[string]string{
		"X-Forwarded-For":     "203.0.113.7",
		"X-Forwarded-Proto":   "https",
		"X-Forwarded-Host":    "example.test",
		"Via":                 "2.0 Caddy",
		"X-Lawn-Client-Proto": "HTTP/2.0",
		"X-Lawn-Client-Tls":   "tls1.3 TLS_AES_128_GCM_SHA256 h2",
		"X-Lawn-Client-Ja4":   "t13d1516h2_8daaf6152771_e5627efa2ab1",
		"Sec-Fetch-Mode":      "navigate",
	})
	if viaCaddy.HeaderNames != "Accept,Sec-Fetch-Mode,User-Agent" {
		t.Errorf("header_names via proxy: %q", viaCaddy.HeaderNames)
	}
	if viaCaddy.Proto != "HTTP/2.0" || viaCaddy.TLS != "tls1.3 TLS_AES_128_GCM_SHA256 h2" {
		t.Errorf("proto/tls via proxy: %q %q", viaCaddy.Proto, viaCaddy.TLS)
	}
	if viaCaddy.JA4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("ja4 via proxy: %q", viaCaddy.JA4)
	}
	// Direct, untrusted peer: its X-Lawn-* claims are ignored (and kept in
	// the header list, since the client really sent them).
	direct := send("198.51.100.9:1", map[string]string{"X-Lawn-Client-Tls": "forged", "X-Lawn-Client-Proto": "HTTP/9",
		"X-Lawn-Client-Ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"})
	if direct.TLS != "" || direct.Proto != "HTTP/1.1" || direct.JA4 != "" {
		t.Errorf("untrusted peer must not set proto/tls: %q %q", direct.Proto, direct.TLS)
	}
	if direct.HeaderNames != "Accept,User-Agent,X-Lawn-Client-Ja4,X-Lawn-Client-Proto,X-Lawn-Client-Tls" {
		t.Errorf("header_names direct: %q", direct.HeaderNames)
	}
}

func TestValidJA4(t *testing.T) {
	for s, ok := range map[string]bool{
		"t13d1516h2_8daaf6152771_e5627efa2ab1": true,
		"t13i181000_85036bcba153_d41ae481755e": true,
		"t13d1516h2_8daaf6152771_e5627efa2abg": false, // not hex
		"T13d1516h2_8daaf6152771_e5627efa2ab1": false,
		"t13d1516h2-8daaf6152771_e5627efa2ab1": false,
		"t13d1516h2_8daaf6152771_e5627efa2ab":  false,
		"forged":                               false,
		"":                                     false,
	} {
		if got := validJA4(s); (got != "") != ok {
			t.Errorf("validJA4(%q) = %q", s, got)
		}
	}
}

func TestHeaderNamesBounded(t *testing.T) {
	h := http.Header{}
	for i := range 200 {
		h.Set("X-Custom-Header-Number-"+strconv.Itoa(i), "v")
	}
	if n := headerNames(h, false); len(n) > 512 {
		t.Fatalf("header_names not truncated: %d bytes", len(n))
	}
}

func TestLogPathDropsQueryValues(t *testing.T) {
	cases := map[string]string{
		"/lawn/abc":                          "/lawn/abc",
		"/":                                  "/",
		"/robots.txt?x=1":                    "/robots.txt?x",
		"/lawn/a?token=SECRET&a=1&token=2&b": "/lawn/a?a&b&token",
		"/search?q=alice%40example.com":      "/search?q",
		"/p%20q?=v&k":                        "/p%20q?k",
	}
	for in, want := range cases {
		u, err := url.ParseRequestURI(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := logPath(u); got != want {
			t.Errorf("logPath(%q) = %q, want %q", in, got, want)
		}
	}
	u, _ := url.ParseRequestURI("/x?" + strings.Repeat("k=v&", 1) + "a1&a2&a3&a4&a5&a6&a7&a8&a9&b1&b2&b3&b4&b5&b6&b7&b8&b9")
	if got := logPath(u); !strings.HasSuffix(got, "…") || strings.Contains(got, "=v") {
		t.Errorf("many keys should be capped: %q", got)
	}
	// End to end: the logged row never contains the value.
	r := newRig(t)
	r.do("GET", "/lawn/zz?session=hunter2", "203.0.113.7", "ua")
	if p := r.log.reqs[0].Path; p != "/lawn/zz?session" || strings.Contains(p, "hunter2") {
		t.Errorf("logged path %q", p)
	}
}

func TestLogReferer(t *testing.T) {
	for in, want := range map[string]string{
		"":                                 "",
		"https://example.test/sitemap.xml": "https://example.test/sitemap.xml",
		"https://search.test/q?query=secret#frag": "https://search.test/q?query",
		"https://user:pw@host.test/":              "https://host.test/",
		"mailto:someone@example.test":             "(unparsable)",
		"/relative/path?x=1":                      "/relative/path?x",
	} {
		if got := logReferer(in); got != want {
			t.Errorf("logReferer(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeRate struct{ allow bool }

func (f fakeRate) Allow(netip.Addr) bool { return f.allow }

func TestMazeRateLimited(t *testing.T) {
	r := newRig(t)
	r.srv.d.Rate = fakeRate{allow: false}
	w := r.do("GET", "/lawn/x", "203.0.113.7", "ua")
	rec := r.log.reqs[0]
	if w.Code != 200 || rec.EndReason != "rate_limited" || rec.Dripped || !rec.IsViolation || r.drip.drips != 0 || r.lim.active != 0 {
		t.Fatalf("code=%d rec=%+v drips=%d", w.Code, rec, r.drip.drips)
	}
	if !strings.Contains(w.Body.String(), "full") || r.srv.Metrics.RateLimited.Load() != 1 {
		t.Error("rate-limited requests get the tiny page and are counted")
	}
	// Non-maze routes are never rate limited.
	if w := r.do("GET", "/", "203.0.113.7", "ua"); w.Code != 200 || r.log.reqs[1].EndReason != "" {
		t.Error("homepage must not be rate limited")
	}
}

func TestMazeLogsParentID(t *testing.T) {
	r := newRig(t)
	r.do("GET", "/lawn/entry0", "203.0.113.7", "ua")
	r.do("GET", "/lawn/next", "203.0.113.7", "ua")
	if len(r.log.reqs) != 2 {
		t.Fatalf("logged %d", len(r.log.reqs))
	}
	if w := r.do("GET", "/lawn/x", "203.0.113.7", "ua"); w.Header().Get("X-Robots-Tag") != "noindex" {
		t.Errorf("X-Robots-Tag %q: maze links must stay followable", w.Header().Get("X-Robots-Tag"))
	}
	if e := r.log.reqs[0]; e.PageID == 0 || e.ParentID != 0 {
		t.Errorf("entry: %+v", e)
	}
	if c := r.log.reqs[1]; c.PageID != uint32(len("/lawn/next")) || c.ParentID != 1 {
		t.Errorf("child: page=%d parent=%d", c.PageID, c.ParentID)
	}
}

func TestAdminMazePreview(t *testing.T) {
	r := newRig(t)
	ts := httptest.NewServer(NewAdminServer("", NewMetricsRegistry(r.srv), fakePages{}).Handler)
	defer ts.Close()
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("/lawn/abc"); code != 200 || !strings.Contains(body, "<title>/lawn/abc</title>") {
		t.Fatalf("preview: %d %q", code, body)
	}
	if code, _ := get("/lawn"); code != 200 {
		t.Fatalf("/lawn: %d", code)
	}
	if code, body := get("/"); code != 200 || !strings.Contains(body, `href="/lawn/entry0"`) || !strings.Contains(body, "never logged") {
		t.Fatalf("index: %d %q", code, body)
	}
	// Nothing was logged, dripped or classified.
	if len(r.log.reqs) != 0 || r.drip.drips != 0 || r.drip.fasts != 0 || len(r.obs.pairs) != 0 {
		t.Errorf("preview must not log or drip: reqs=%d drips=%d fasts=%d obs=%d",
			len(r.log.reqs), r.drip.drips, r.drip.fasts, len(r.obs.pairs))
	}
	// Without a renderer there is no preview.
	plain := httptest.NewServer(NewAdminServer("", NewMetricsRegistry(r.srv), nil).Handler)
	defer plain.Close()
	resp, err := http.Get(plain.URL + "/lawn/abc")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("no renderer: %d", resp.StatusCode)
	}
}

const testOnion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"

func TestOnionVisitors(t *testing.T) {
	r := newRig(t, func(d *Deps) { d.Onion = testOnion })
	circuit := "fc00:dead:beef:4dad::12:3456"

	w := r.do("GET", "/sitemap.xml", circuit, "OnionBot/1.0")
	if !strings.Contains(w.Body.String(), "<loc>http://"+testOnion+"/lawn/") || strings.Contains(w.Body.String(), "example.test") {
		t.Errorf("onion sitemap must link to the onion mirror:\n%s", w.Body.String())
	}
	if w := r.do("GET", "/", circuit, "OnionBot/1.0"); w.Header().Get("Onion-Location") != "" {
		t.Error("onion visitors must not be told about the onion mirror")
	}
	r.do("GET", "/lawn/abc", circuit, "OnionBot/1.0")
	for _, rec := range r.log.reqs {
		if rec.IP != circuit || rec.ASN != logstore.OnionASN || rec.ASNOrg != logstore.OnionOrg || rec.Country != "" {
			t.Errorf("onion request logged as %s AS%d %q %q", rec.IP, rec.ASN, rec.ASNOrg, rec.Country)
		}
	}
	if r.lim.asns[len(r.lim.asns)-1] != logstore.OnionASN {
		t.Errorf("limiter should see the onion pseudo-network: %v", r.lim.asns)
	}

	// Clearnet visitors: normal sitemap, and HTML pages advertise the mirror.
	w = r.do("GET", "/sitemap.xml", "203.0.113.7", "ua")
	if !strings.Contains(w.Body.String(), "<loc>https://example.test/lawn/") {
		t.Errorf("clearnet sitemap:\n%s", w.Body.String())
	}
	if got := r.do("GET", "/?x=1", "203.0.113.7", "ua").Header().Get("Onion-Location"); got != "http://"+testOnion+"/?x=1" {
		t.Errorf("Onion-Location on home: %q", got)
	}
	if got := r.do("GET", "/robots.txt", "203.0.113.7", "ua").Header().Get("Onion-Location"); got != "" {
		t.Errorf("Onion-Location only belongs on HTML pages: %q", got)
	}
	// Without an onion address nothing is advertised.
	if got := newRig(t).do("GET", "/", "203.0.113.7", "ua").Header().Get("Onion-Location"); got != "" {
		t.Errorf("no onion configured, got %q", got)
	}
}

func (r *rig) doProto(path, xff, proto string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", xff)
	if proto != "" {
		req.Header.Set("X-Forwarded-Proto", proto)
	}
	req.Header.Set("User-Agent", "PlainBot/1.0")
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, req)
	return w
}

func TestPlainHTTP(t *testing.T) {
	r := newRig(t)
	last := func() logstore.Request { return r.log.reqs[len(r.log.reqs)-1] }

	w := r.doProto("/shame/x?a=1", "203.0.113.7", "http")
	if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "https://example.test/shame/x?a=1" {
		t.Fatalf("plain http page: %d %q", w.Code, w.Header().Get("Location"))
	}
	if rec := last(); rec.Scheme != "http" || rec.Status != 301 || rec.Path != "/shame/x?a" {
		t.Errorf("redirect logged as %+v", rec)
	}
	// The rule and the maze are served as over HTTPS.
	if w := r.doProto("/robots.txt", "203.0.113.7", "http"); w.Code != 200 || !strings.Contains(w.Body.String(), "Disallow: /lawn/") {
		t.Errorf("robots over http: %d", w.Code)
	}
	if w := r.doProto("/lawn/abc", "203.0.113.7", "http"); w.Code != 200 || !last().IsViolation || last().Scheme != "http" {
		t.Errorf("maze over http: %d %+v", w.Code, last())
	}
	if len(r.log.robots) != 1 {
		t.Errorf("robots fetch over http not counted: %d", len(r.log.robots))
	}
	// HTTPS is untouched and logged as such.
	if w := r.doProto("/", "203.0.113.7", "https"); w.Code != 200 || last().Scheme != "https" {
		t.Errorf("https home: %d %q", w.Code, last().Scheme)
	}
	// The onion mirror is plain HTTP by design: never redirected.
	if w := r.doProto("/", "fc00:dead:beef:4dad::1", "http"); w.Code != 200 || last().Scheme != "http" {
		t.Errorf("onion home: %d", w.Code)
	}
	// A client-supplied X-Forwarded-Proto is ignored without the proxy.
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.1:4000"
	req.Header.Set("X-Forwarded-Proto", "http")
	w = httptest.NewRecorder()
	r.srv.ServeHTTP(w, req)
	if w.Code != 200 || last().Scheme != "http" {
		t.Errorf("direct request: %d %q", w.Code, last().Scheme)
	}
}
