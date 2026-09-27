// Package server routes requests, resolves the real client IP, serves the
// maze through the drip, and hands every request to the async logger.
package server

import (
	"bytes"
	"context"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/drip"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/maze"
)

// RobotsTxt is the exact robots.txt served (SPEC.md section 4).
const RobotsTxt = "User-agent: *\nDisallow: /lawn/\n"

// PageRenderer renders deterministic maze pages.
type PageRenderer interface {
	Render(buf *bytes.Buffer, path string)
	EntryURLs(n int) []string
}

// Dripper writes a body slowly (DripWith) or at once (Fast).
type Dripper interface {
	DripWith(ctx context.Context, w http.ResponseWriter, body []byte, seed uint64, plan drip.Plan) (int64, drip.Outcome, error)
	Fast(w http.ResponseWriter, body []byte) (int64, error)
}

// Limiter caps concurrent drips.
type Limiter interface {
	Acquire(ip netip.Addr, asn uint32) bool
	Release(ip netip.Addr, asn uint32)
	Active() int
}

// Egress counts bytes sent today (metrics only; there is no cap).
type Egress interface {
	Add(n int64)
	Today() int64
}

// ASNLookup maps an address to its origin ASN. Must be safe for concurrent
// use and must not block.
type ASNLookup interface {
	Lookup(a netip.Addr) (asn uint32, org string, ok bool)
}

// Logger is the non-blocking request log sink.
type Logger interface {
	LogRequest(r logstore.Request) bool
	LogRobots(r logstore.RobotsFetch) bool
}

// Observer receives (ip, ua) pairs of violators for async classification.
type Observer interface {
	Observe(ip, ua string)
}

// Deps are the server's collaborators.
type Deps struct {
	Pages     PageRenderer
	Dripper   Dripper
	Limiter   Limiter
	Egress    Egress
	Logger    Logger
	Observer  Observer       // may be nil
	ASN       ASNLookup      // may be nil; replace later with SetASN
	Patience  *drip.Patience // adaptive per-client drip budget; nil = fixed max_duration
	Trusted   []netip.Prefix
	PublicDir string
	Home      []byte // pre-rendered homepage
	BaseURL   string
	Now       func() time.Time
}

type asnBox struct{ l ASNLookup }

// Server is the public HTTP handler.
type Server struct {
	d       Deps
	asn     atomic.Pointer[asnBox]
	sitemap []byte
	shame   http.Handler
	Metrics *Metrics
}

// New builds a Server.
func New(d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &Server{d: d, Metrics: &Metrics{}}
	s.SetASN(d.ASN)
	s.sitemap = buildSitemap(d.BaseURL, d.Pages.EntryURLs(8))
	s.shame = http.FileServer(shameFS{dir: d.PublicDir})
	return s
}

// SetASN atomically swaps the ASN table (SIGHUP reload).
func (s *Server) SetASN(l ASNLookup) { s.asn.Store(&asnBox{l}) }

func (s *Server) lookupASN(a netip.Addr) (uint32, string) {
	b := s.asn.Load()
	if b == nil || b.l == nil || !a.IsValid() {
		return 0, ""
	}
	asn, org, ok := b.l.Lookup(a)
	if !ok {
		return 0, ""
	}
	return asn, org
}

// shedPage is served for /lawn/* when a connection cap is hit.
var shedPage = []byte("<!doctype html><title>busy</title><p>The lawn is full. Try again later.</p>\n")

// ServeHTTP implements http.Handler. Every request is logged.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := s.d.Now()
	viaProxy := inPrefixes(parseHostAddr(r.RemoteAddr), s.d.Trusted)
	ip := ClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), s.d.Trusted)
	asn, asnOrg := s.lookupASN(ip)
	ua := r.UserAgent()
	path := r.URL.Path

	rec := logstore.Request{
		TsStart:   start.UnixMilli(),
		IP:        ip.String(),
		ASN:       asn,
		ASNOrg:    asnOrg,
		UserAgent: ua,
		Method:    r.Method,
		Path:      logPath(r.URL),
		Depth:     -1,
		// Fingerprinting aids, stored for analysis only (never published).
		Referer:        logReferer(r.Header.Get("Referer")),
		Accept:         truncate(r.Header.Get("Accept"), 256),
		AcceptLanguage: truncate(r.Header.Get("Accept-Language"), 128),
		AcceptEncoding: truncate(r.Header.Get("Accept-Encoding"), 128),
		HeaderNames:    headerNames(r.Header, viaProxy),
		Proto:          r.Proto,
	}
	if viaProxy {
		// Caddy sets these (overwriting any client value); see deploy/Caddyfile.
		if p := r.Header.Get("X-Lawn-Client-Proto"); p != "" {
			rec.Proto = truncate(p, 16)
		}
		rec.TLS = truncate(strings.TrimSpace(r.Header.Get("X-Lawn-Client-Tls")), 96)
	}
	var sent int64
	status := http.StatusOK
	route := routeOther

	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")

	switch {
	case r.Method != http.MethodGet && r.Method != http.MethodHead:
		h.Set("Allow", "GET, HEAD")
		status = http.StatusMethodNotAllowed
		sent = s.writeSmall(w, status, "text/plain; charset=utf-8", []byte("method not allowed\n"), r)
	case maze.IsMazePath(path):
		route = routeLawn
		rec.IsViolation = true
		rec.Depth = maze.Depth(path)
		sent, rec.Dripped, rec.EndReason = s.serveMaze(w, r, ip, asn, ua, start)
	case path == "/robots.txt":
		route = routeRobots
		sent = s.writeSmall(w, status, "text/plain; charset=utf-8", []byte(RobotsTxt), r)
		s.logRobots(logstore.RobotsFetch{IP: rec.IP, UserAgent: ua, Ts: rec.TsStart})
	case path == "/":
		route = routeHome
		sent = s.writeSmall(w, status, "text/html; charset=utf-8", s.d.Home, r)
	case path == "/sitemap.xml":
		route = routeSitemap
		sent = s.writeSmall(w, status, "application/xml; charset=utf-8", s.sitemap, r)
	case path == "/healthz":
		route = routeHealth
		sent = s.writeSmall(w, status, "text/plain; charset=utf-8", []byte("ok\n"), r)
	case path == "/shame":
		route = routeShame
		status = http.StatusMovedPermanently
		http.Redirect(w, r, "/shame/", status)
	case strings.HasPrefix(path, "/shame/"):
		route = routeShame
		cw := &countingWriter{ResponseWriter: w, status: http.StatusOK}
		h.Set("Cache-Control", "public, max-age=60")
		s.shame.ServeHTTP(cw, r)
		status, sent = cw.status, cw.n
	default:
		status = http.StatusNotFound
		sent = s.writeSmall(w, status, "text/plain; charset=utf-8", []byte("404: get off my lawn\n"), r)
	}

	rec.Status = status
	rec.BytesSent = sent
	rec.TsEnd = s.d.Now().UnixMilli()
	if rec.TsEnd <= rec.TsStart {
		rec.TsEnd = rec.TsStart
	}
	// Classify every visitor (not only violators), so well-behaved bots and
	// new ones can be reported. Non-blocking; deduplicated by the observer.
	if s.d.Observer != nil && ip.IsValid() && route != routeHealth {
		s.d.Observer.Observe(rec.IP, ua)
	}
	s.Metrics.observe(route, rec.IsViolation, rec.Dripped, sent)
	if !s.d.Logger.LogRequest(rec) {
		s.Metrics.LogDropped.Add(1)
	}
}

func (s *Server) logRobots(f logstore.RobotsFetch) {
	if !s.d.Logger.LogRobots(f) {
		s.Metrics.LogDropped.Add(1)
	}
}

// End reasons for maze requests that were not dripped. Dripped ones use
// drip.Outcome names (complete, cutoff, client_gone, write_error).
const (
	endShed = "shed" // over a connection cap: tiny page, no drip
	endHead = "head" // HEAD request: headers only
)

// serveMaze renders the page up front into a pooled buffer, then drips it
// unless a limit is hit. The link block goes out at once; the rest is
// trickled within the client's budget (adaptive, see drip.Patience).
// Returns bytes sent, whether it was dripped, and why it ended.
func (s *Server) serveMaze(w http.ResponseWriter, r *http.Request, ip netip.Addr, asn uint32, ua string, start time.Time) (int64, bool, string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Content-Type", "text/html; charset=utf-8")

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return 0, false, endHead
	}
	if !ip.IsValid() || !s.d.Limiter.Acquire(ip, asn) {
		// Load shedding: a tiny static page, no render, no drip (SPEC.md
		// 5.3 "fast, small"). Still a logged violation, never a 5xx.
		s.Metrics.LimitShed.Add(1)
		h.Set("Content-Length", strconv.Itoa(len(shedPage)))
		w.WriteHeader(http.StatusOK)
		n, _ := s.d.Dripper.Fast(w, shedPage)
		return n, false, endShed
	}
	defer s.d.Limiter.Release(ip, asn)

	buf := maze.GetBuffer()
	defer maze.PutBuffer(buf)
	s.d.Pages.Render(buf, r.URL.Path)
	body := buf.Bytes()
	// Headers go out immediately; the body is chunked and trickled.
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		s.Metrics.observeDrip(drip.WriteFailed)
		return 0, true, drip.WriteFailed.String()
	}
	key := drip.KeyFor(ip, asn, ua)
	plan := drip.Plan{Lead: maze.LeadLen(body), MaxDuration: s.d.Patience.Budget(key)}
	began := s.d.Now()
	n, outcome, _ := s.d.Dripper.DripWith(r.Context(), w, body, uint64(start.UnixNano()), plan)
	s.d.Patience.Observe(key, s.d.Now().Sub(began), outcome)
	s.Metrics.observeDrip(outcome)
	return n, true, outcome.String()
}

func (s *Server) writeSmall(w http.ResponseWriter, status int, ctype string, body []byte, r *http.Request) int64 {
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return 0
	}
	n, _ := w.Write(body)
	s.d.Egress.Add(int64(n))
	return int64(n)
}

// countingWriter records status and body bytes for file-server responses.
type countingWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (c *countingWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// shameFS serves PublicDir but only below shame/, with no directory
// listings and no dotfiles (the builder's temp dirs).
type shameFS struct{ dir string }

func (f shameFS) Open(name string) (http.File, error) {
	clean := filepath.ToSlash(filepath.Clean("/" + name))
	if !strings.HasPrefix(clean, "/shame/") && clean != "/shame" {
		return nil, fs.ErrNotExist
	}
	for _, seg := range strings.Split(clean, "/") {
		if strings.HasPrefix(seg, ".") {
			return nil, fs.ErrNotExist
		}
	}
	fh, err := http.Dir(f.dir).Open(clean)
	if err != nil {
		return nil, err
	}
	st, err := fh.Stat()
	if err != nil {
		fh.Close()
		return nil, err
	}
	if st.IsDir() {
		// Only serve directories that have an index.html.
		idx, err := http.Dir(f.dir).Open(strings.TrimSuffix(clean, "/") + "/index.html")
		if err != nil {
			fh.Close()
			return nil, os.ErrNotExist
		}
		idx.Close()
	}
	return fh, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// proxyAdded are headers our reverse proxy adds; they say nothing about
// the client, so they are left out of header_names.
var proxyAdded = map[string]bool{
	"X-Forwarded-For":     true,
	"X-Forwarded-Host":    true,
	"X-Forwarded-Proto":   true,
	"Via":                 true,
	"X-Lawn-Client-Proto": true,
	"X-Lawn-Client-Tls":   true,
}

// headerNames returns the names of the headers the client sent, sorted and
// comma-joined (Host is not in r.Header). Which headers a client sends, and
// which it omits, is a strong hint to what software it is.
func headerNames(h http.Header, viaProxy bool) string {
	var arr [32]string
	names := arr[:0]
	for k := range h {
		if viaProxy && proxyAdded[k] {
			continue
		}
		names = append(names, k)
	}
	slices.Sort(names)
	return truncate(strings.Join(names, ","), 512)
}

// logPath is what the log keeps of the request URL: the escaped path plus
// the query parameter NAMES, never their values ("/x?q=secret&a=1" ->
// "/x?a&q"). Values can carry tokens or personal data, and nothing here
// needs them; the names still show how a client builds URLs.
func logPath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery == "" {
		return truncate(p, 1024)
	}
	var arr [16]string
	keys := arr[:0]
	for part := range strings.SplitSeq(u.RawQuery, "&") {
		k, _, _ := strings.Cut(part, "=")
		if k == "" || slices.Contains(keys, k) {
			continue
		}
		if len(keys) == cap(arr) {
			keys = append(keys, "…")
			break
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return truncate(p+"?"+strings.Join(keys, "&"), 1024)
}

// logReferer keeps a Referer's scheme, host and path plus query parameter
// names (as logPath does), dropping values and fragments.
func logReferer(ref string) string {
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil || (u.Scheme != "" && u.Host == "" && u.Opaque != "") {
		return "(unparsable)"
	}
	origin := ""
	if u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	return truncate(origin+logPath(u), 512)
}
