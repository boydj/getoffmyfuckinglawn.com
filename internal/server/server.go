// Package server routes requests, resolves the real client IP, serves the
// maze through the drip, and hands every request to the async logger.
package server

import (
	"bytes"
	"context"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

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

// Dripper writes a body slowly (Drip) or at once (Fast).
type Dripper interface {
	Drip(ctx context.Context, w http.ResponseWriter, body []byte, seed uint64) (int64, error)
	Fast(w http.ResponseWriter, body []byte) (int64, error)
}

// Limiter caps concurrent drips.
type Limiter interface {
	Acquire(ip netip.Addr, asn uint32) bool
	Release(ip netip.Addr, asn uint32)
	Active() int
}

// Egress is the daily byte budget.
type Egress interface {
	Exceeded() bool
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
	Observer  Observer  // may be nil
	ASN       ASNLookup // may be nil; replace later with SetASN
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

// egressCapPage is served for /lawn/* once the daily egress cap is hit.
var egressCapPage = []byte("<!doctype html><title>closed</title><p>The lawn is closed for today.</p>\n")

// ServeHTTP implements http.Handler. Every request is logged.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := s.d.Now()
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
		Path:      truncate(r.URL.RequestURI(), 1024),
		Depth:     -1,
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
		sent, rec.Dripped = s.serveMaze(w, r, ip, asn, start)
		if s.d.Observer != nil && ip.IsValid() {
			s.d.Observer.Observe(rec.IP, ua)
		}
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

// serveMaze renders the page up front into a pooled buffer, then drips it
// unless a limit is hit. Returns bytes sent and whether it was dripped.
func (s *Server) serveMaze(w http.ResponseWriter, r *http.Request, ip netip.Addr, asn uint32, start time.Time) (int64, bool) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Content-Type", "text/html; charset=utf-8")

	if s.d.Egress.Exceeded() {
		s.Metrics.EgressCapped.Add(1)
		return s.writeSmall(w, http.StatusOK, "text/html; charset=utf-8", egressCapPage, r), false
	}

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return 0, false
	}
	if !ip.IsValid() || !s.d.Limiter.Acquire(ip, asn) {
		// Load shedding: a tiny static page, no render, no drip (SPEC.md
		// 5.3 "fast, small"). Still a logged violation, never a 5xx.
		s.Metrics.LimitShed.Add(1)
		h.Set("Content-Length", strconv.Itoa(len(shedPage)))
		w.WriteHeader(http.StatusOK)
		n, _ := s.d.Dripper.Fast(w, shedPage)
		return n, false
	}
	defer s.d.Limiter.Release(ip, asn)

	buf := maze.GetBuffer()
	defer maze.PutBuffer(buf)
	s.d.Pages.Render(buf, r.URL.Path)
	body := buf.Bytes()
	// Headers go out immediately; the body is chunked and trickled.
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return 0, true
	}
	n, _ := s.d.Dripper.Drip(r.Context(), w, body, uint64(start.UnixNano()))
	return n, true
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
