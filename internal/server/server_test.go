package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	mu       sync.Mutex
	n        int64
	exceeded bool
}

func (e *fakeEgress) Exceeded() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.exceeded }
func (e *fakeEgress) Add(n int64)    { e.mu.Lock(); e.n += n; e.mu.Unlock() }
func (e *fakeEgress) Today() int64   { e.mu.Lock(); defer e.mu.Unlock(); return e.n }

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

type rig struct {
	srv  *Server
	lim  *fakeLimiter
	egr  *fakeEgress
	drip *fakeDripper
	log  *fakeLogger
	obs  *fakeObserver
	pub  string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	pub := t.TempDir()
	egr := &fakeEgress{}
	r := &rig{lim: &fakeLimiter{allow: true}, egr: egr, drip: &fakeDripper{egress: egr}, log: &fakeLogger{}, obs: &fakeObserver{}, pub: pub}
	clock := time.UnixMilli(1_700_000_000_000)
	r.srv = New(Deps{
		Pages: fakePages{}, Dripper: r.drip, Limiter: r.lim, Egress: egr, Logger: r.log, Observer: r.obs,
		ASN:       fakeASN{"203.0.113.7": 64500},
		Trusted:   []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		PublicDir: pub, Home: []byte("<html>home</html>"), BaseURL: "https://example.test",
		Now: func() time.Time { clock = clock.Add(250 * time.Millisecond); return clock },
	})
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
		if rec.IP != "203.0.113.7" || rec.UserAgent != "TestBot/1.0" || rec.ASN != 64500 || rec.ASNOrg != "TEST-AS64500" {
			t.Errorf("bad attribution: %+v", rec)
		}
		if rec.TsEnd < rec.TsStart {
			t.Errorf("ts_end before ts_start: %+v", rec)
		}
		want := strings.HasPrefix(rec.Path, "/lawn/")
		if rec.IsViolation != want {
			t.Errorf("%s: is_violation=%v", rec.Path, rec.IsViolation)
		}
		if !want && rec.Depth != -1 {
			t.Errorf("%s: depth must be NULL outside /lawn/", rec.Path)
		}
	}
	if len(r.log.robots) != 1 || r.log.robots[0].IP != "203.0.113.7" {
		t.Errorf("robots fetch not logged: %+v", r.log.robots)
	}
	if len(r.obs.pairs) != 1 || r.obs.pairs[0] != "203.0.113.7|TestBot/1.0" {
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

func TestMazeEgressCap(t *testing.T) {
	r := newRig(t)
	r.egr.exceeded = true
	w := r.do("GET", "/lawn/x", "203.0.113.7", "ua")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "closed") || r.drip.drips+r.drip.fasts != 0 {
		t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
	}
	if !r.log.reqs[0].IsViolation || r.log.reqs[0].Dripped {
		t.Fatal("capped request must still be logged as a violation")
	}
	if r.srv.Metrics.EgressCapped.Load() != 1 {
		t.Fatal("metric not incremented")
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

func TestMetricsExposition(t *testing.T) {
	r := newRig(t)
	r.do("GET", "/lawn/a", "", "ua")
	reg := NewMetricsRegistry(r.srv)
	reg.Register(Gauge{Name: "lawn_test_extra", Help: "x", Value: func() float64 { return 42 }})
	ts := httptest.NewServer(NewAdminServer("", reg).Handler)
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
	r.egr.exceeded = true
	r.do("GET", "/lawn/d", "203.0.113.7", "Bot/1")
	r.egr.exceeded = false
	r.do("GET", "/", "203.0.113.7", "Bot/1")
	for i, want := range []string{"complete", "shed", "head", "egress_cap", ""} {
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
