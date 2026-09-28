package smallweb

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/drip"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/maze"
)

type fakeLog struct {
	mu     sync.Mutex
	reqs   []logstore.Request
	robots int
}

func (f *fakeLog) LogRequest(r logstore.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r)
	return true
}
func (f *fakeLog) LogRobots(logstore.RobotsFetch) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.robots++
	return true
}
func (f *fakeLog) last(t *testing.T) logstore.Request {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if n := len(f.reqs); n > 0 {
			r := f.reqs[n-1]
			f.mu.Unlock()
			return r
		}
		f.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("nothing logged")
	return logstore.Request{}
}
func (f *fakeLog) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

type fakeLimiter struct {
	mu    sync.Mutex
	deny  bool
	asns  []uint32
	count int
}

func (l *fakeLimiter) Acquire(_ netip.Addr, asn uint32) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asns = append(l.asns, asn)
	if l.deny {
		return false
	}
	l.count++
	return true
}
func (l *fakeLimiter) setDeny(v bool) { l.mu.Lock(); l.deny = v; l.mu.Unlock() }
func (l *fakeLimiter) lastASN() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.asns[len(l.asns)-1]
}
func (f *fakeLog) robotCount() int                { f.mu.Lock(); defer f.mu.Unlock(); return f.robots }
func (l *fakeLimiter) Release(netip.Addr, uint32) { l.mu.Lock(); l.count--; l.mu.Unlock() }
func (l *fakeLimiter) Active() int                { l.mu.Lock(); defer l.mu.Unlock(); return l.count }

type rig struct {
	s        *Server
	log      *fakeLog
	lim      *fakeLimiter
	gopher   string
	gemini   string
	obs      []string
	obsMu    sync.Mutex
	certPath string
}

func (r *rig) Observe(ip, ua string) { r.obsMu.Lock(); r.obs = append(r.obs, ip); r.obsMu.Unlock() }

func newRig(t *testing.T, interval time.Duration) *rig {
	t.Helper()
	r := &rig{log: &fakeLog{}, lim: &fakeLimiter{}}
	gen := maze.NewGenerator([]byte("smallweb-test-secret-0123456789ab"), nil)
	dr := drip.NewDripper(drip.Options{ChunkBytes: 512, Interval: interval, MaxDuration: time.Minute}, drip.RealClock{}, drip.NewEgress(0, nil))
	r.s = New(Deps{
		Pages: gen, Dripper: dr, Limiter: r.lim, Logger: r.log, Observer: r,
		Lookup: func(netip.Addr) (uint32, string, string) { return 64500, "TEST-NET", "NL" },
		Host:   "lawn.example", GopherPort: 70, WebURL: "https://lawn.example",
	})
	gl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ml, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, err := LoadOrCreateCert(dir, "lawn.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.certPath = filepath.Join(dir, "cert.pem")
	go r.s.ServeGopher(gl)
	go r.s.ServeGemini(ml, cert)
	r.gopher, r.gemini = gl.Addr().String(), ml.Addr().String()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r.s.Shutdown(ctx)
	})
	return r
}

func (r *rig) askGopher(t *testing.T, req string) string {
	t.Helper()
	c, err := net.Dial("tcp", r.gopher)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, req)
	b, _ := io.ReadAll(c)
	return string(b)
}

func (r *rig) askGemini(t *testing.T, req string) (string, tls.ConnectionState) {
	t.Helper()
	c, err := tls.Dial("tcp", r.gemini, &tls.Config{InsecureSkipVerify: true, ServerName: "lawn.example"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, req)
	b, _ := io.ReadAll(c)
	return string(b), c.ConnectionState()
}

func TestGopher(t *testing.T) {
	r := newRig(t, 0)

	root := r.askGopher(t, "\r\n")
	if !strings.HasSuffix(root, "\r\n.\r\n") || !strings.Contains(root, "0robots.txt\t/robots.txt\tlawn.example\t70\r\n") ||
		strings.Count(root, "1Lawn\t/lawn/") != 6 || !strings.Contains(root, "hThe wall of shame (web)\tURL:https://lawn.example/shame/") {
		t.Fatalf("root menu:\n%s", root)
	}
	if rec := r.log.last(t); rec.Scheme != "gopher" || rec.Proto != "gopher" || rec.Path != "/" || rec.Status != 200 ||
		rec.Method != "GET" || rec.ASN != 64500 || rec.Country != "NL" || rec.IsViolation {
		t.Errorf("root logged as %+v", rec)
	}

	if got := r.askGopher(t, "robots.txt\r\n"); got != "User-agent: *\nDisallow: /lawn/\n" {
		t.Errorf("robots: %q", got)
	}
	if rec := r.log.last(t); rec.Path != "/robots.txt" || r.log.robotCount() != 1 {
		t.Errorf("robots logged as %+v (%d fetches)", rec, r.log.robotCount())
	}

	entry := strings.Split(strings.Split(root, "1Lawn\t")[1], "\t")[0]
	page := r.askGopher(t, entry+"\r\n")
	if !strings.HasSuffix(page, ".\r\n") || strings.Count(page, "\tlawn.example\t70\r\n") < 10 {
		t.Fatalf("maze menu:\n%s", page)
	}
	rec := r.log.last(t)
	if !rec.IsViolation || !rec.Dripped || rec.EndReason != "complete" || rec.Depth != 0 || rec.PageID == 0 ||
		rec.BytesSent != int64(len(page)) || rec.Path != entry {
		t.Errorf("maze logged as %+v", rec)
	}
	if r.lim.lastASN() != 64500 || r.lim.Active() != 0 {
		t.Errorf("limiter: %d active=%d", r.lim.lastASN(), r.lim.Active())
	}

	// A search query's value is never stored; gopher+ markers are not queries.
	r.askGopher(t, "/lawn/x\tsecret words\r\n")
	if p := r.log.last(t).Path; p != "/lawn/x?" {
		t.Errorf("search logged as %q", p)
	}
	r.askGopher(t, "/lawn/x\t$\r\n")
	if p := r.log.last(t).Path; p != "/lawn/x" {
		t.Errorf("gopher+ logged as %q", p)
	}

	if got := r.askGopher(t, "/nope\r\n"); !strings.HasPrefix(got, "3Not found") {
		t.Errorf("not found: %q", got)
	}
	if st := r.log.last(t).Status; st != 404 {
		t.Errorf("not found status %d", st)
	}

	// Over a limit: a short error, logged as shed.
	r.lim.setDeny(true)
	if got := r.askGopher(t, entry+"\r\n"); !strings.Contains(got, "The lawn is full") {
		t.Errorf("busy: %q", got)
	}
	if rec := r.log.last(t); rec.EndReason != "shed" || !rec.IsViolation || rec.Dripped {
		t.Errorf("shed logged as %+v", rec)
	}
	r.lim.setDeny(false)

	// A connection that sends nothing is a port scan, not a request.
	n := r.log.count()
	c, _ := net.Dial("tcp", r.gopher)
	c.Close()
	time.Sleep(50 * time.Millisecond)
	if r.log.count() != n {
		t.Error("empty connection was logged")
	}
	// Oversized requests are refused.
	if got := r.askGopher(t, strings.Repeat("a", 2000)+"\r\n"); !strings.HasPrefix(got, "3Bad request") {
		t.Errorf("long request: %q", got)
	}
	if st := r.log.last(t).Status; st != 400 {
		t.Errorf("long request status %d", st)
	}
	r.obsMu.Lock()
	defer r.obsMu.Unlock()
	if len(r.obs) == 0 || r.obs[0] != "127.0.0.1" {
		t.Errorf("clients not observed for classification: %v", r.obs)
	}
}

func TestGemini(t *testing.T) {
	r := newRig(t, 0)

	root, cs := r.askGemini(t, "gemini://lawn.example/\r\n")
	if !strings.HasPrefix(root, "20 text/gemini; lang=en\r\n# Get off my lawn.") || strings.Count(root, "\n=> /lawn/") != 6 ||
		!strings.Contains(root, "=> https://lawn.example/shame/ The wall of shame (web)") {
		t.Fatalf("root:\n%s", root)
	}
	rec := r.log.last(t)
	if rec.Scheme != "gemini" || rec.Path != "/" || rec.Status != 20 || cs.Version != tls.VersionTLS13 ||
		rec.TLS != "tls1.3 "+tls.CipherSuiteName(cs.CipherSuite) {
		t.Errorf("root logged as %+v", rec)
	}

	if got, _ := r.askGemini(t, "gemini://lawn.example/robots.txt\r\n"); got != "20 text/plain\r\nUser-agent: *\nDisallow: /lawn/\n" {
		t.Errorf("robots: %q", got)
	}
	entry := strings.Fields(strings.Split(root, "\n=> /lawn/")[1])[0]
	page, _ := r.askGemini(t, "gemini://lawn.example/lawn/"+entry+"\r\n")
	if !strings.HasPrefix(page, "20 text/gemini; lang=en\r\n# ") || strings.Count(page, "\n=> /lawn/") < 10 {
		t.Fatalf("maze page:\n%s", page)
	}
	if rec := r.log.last(t); !rec.IsViolation || rec.EndReason != "complete" || rec.Status != 20 || rec.Path != "/lawn/"+entry {
		t.Errorf("maze logged as %+v", rec)
	}
	// Queries are user input: only their presence is kept.
	r.askGemini(t, "gemini://lawn.example/lawn/x?my+secret\r\n")
	if p := r.log.last(t).Path; p != "/lawn/x?" {
		t.Errorf("query logged as %q", p)
	}
	for req, want := range map[string]string{
		"https://lawn.example/\r\n":           "53 ",
		"hello\r\n":                           "59 ",
		"gemini://lawn.example/nope\r\n":      "51 ",
		strings.Repeat("x", 1100) + "\r\n":    "59 ",
		"gemini://other.example/lawn/abc\r\n": "20 ", // any host is served, like the web catch-all
	} {
		if got, _ := r.askGemini(t, req); !strings.HasPrefix(got, want) {
			t.Errorf("%.40q: got %.40q, want %q", req, got, want)
		}
	}
	r.lim.setDeny(true)
	if got, _ := r.askGemini(t, "gemini://lawn.example/lawn/"+entry+"\r\n"); got != "44 60\r\n" {
		t.Errorf("busy: %q", got)
	}
	if rec := r.log.last(t); rec.Status != 44 || rec.EndReason != "shed" {
		t.Errorf("busy logged as %+v", rec)
	}
	// A plain-TCP probe of the TLS port is not a request.
	n := r.log.count()
	c, _ := net.Dial("tcp", r.gemini)
	io.WriteString(c, "GET / HTTP/1.0\r\n\r\n")
	io.ReadAll(c)
	c.Close()
	time.Sleep(50 * time.Millisecond)
	if r.log.count() != n {
		t.Error("failed handshake was logged")
	}
}

func TestDripAndShutdown(t *testing.T) {
	r := newRig(t, 50*time.Millisecond)
	c, err := net.Dial("tcp", r.gopher)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "/lawn/abc\r\n")
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	first, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(first, "i") {
		t.Fatalf("first line: %q %v", first, err)
	}
	// The lead (every link) arrives at once, before the text drips.
	lead := first
	for strings.Count(lead, "\t70\r\n") < 10 {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("lead: %v after %q", err, lead)
		}
		lead += l
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := r.s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if rec := r.log.last(t); rec.EndReason != "client_gone" || rec.BytesSent == 0 {
		t.Errorf("cut drip logged as %+v", rec)
	}
}

func TestCertPersisted(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateCert(dir, "lawn.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateCert(dir, "lawn.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Certificate[0]) != string(b.Certificate[0]) {
		t.Error("certificate changed between loads: Gemini clients would reject it")
	}
	if fi, err := os.Stat(filepath.Join(dir, "key.pem")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key.pem: %v %v", fi.Mode(), err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCert(dir, "lawn.example", time.Now()); err == nil {
		t.Error("a corrupt certificate must be an error, not silently replaced")
	}
}
