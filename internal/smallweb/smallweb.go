// Package smallweb serves the site over the small-web protocols: Gopher
// (RFC 1436, plain TCP) and Gemini (TLS). Both carry the same rule
// (robots.txt disallows /lawn/) and the same maze as the web site, rendered
// as a gopher menu or gemtext and dripped the same way, with the same
// limits. Every request is logged like an HTTP one, with scheme "gopher"
// or "gemini", so it appears in the same reports and on the same wall.
package smallweb

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/drip"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/maze"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/server"
)

// Pages renders maze pages in a small-web format.
type Pages interface {
	RenderAs(buf *bytes.Buffer, path string, f maze.Format, host string, port int) int
	EntryURLs(n int) []string
	IDs(path string) (page, parent uint32, hasParent bool)
}

// Deps are the collaborators, shared with the HTTP server.
type Deps struct {
	Pages    Pages
	Dripper  server.Dripper
	Limiter  server.Limiter
	Rate     server.RateLimiter // nil: no rate limit
	Patience *drip.Patience     // nil: fixed max_duration
	Logger   server.Logger
	Observer server.Observer // nil: no classification
	// Lookup returns the network and country of an address.
	Lookup func(netip.Addr) (asn uint32, org, cc string)
	// Host is the name gopher menus and the root pages point at; GopherPort
	// is the port in gopher menu lines.
	Host       string
	GopherPort int
	// WebURL is the web site (https://...), linked from the root pages.
	WebURL string
	// MaxDrip bounds how long one response may be held (drip.max_duration);
	// the write deadline allows a margin on top.
	MaxDrip time.Duration
	Now     func() time.Time
}

// Metrics counts small-web traffic for /metrics.
type Metrics struct {
	Gopher, Gemini atomic.Uint64 // requests
	Violations     atomic.Uint64
	Shed           atomic.Uint64 // over a limit: short "busy" answer
	BytesSent      atomic.Uint64
}

// Server serves Gopher and Gemini connections.
type Server struct {
	d       Deps
	Metrics Metrics

	gopherRoot, geminiRoot []byte // pre-rendered root pages

	ctx    context.Context // cancelled on Shutdown: cuts in-flight drips
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	lns    []net.Listener
}

// New returns a Server. Serve connections with ServeGopher/ServeGemini.
func New(d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.MaxDrip <= 0 {
		d.MaxDrip = 10 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{d: d, ctx: ctx, cancel: cancel}
	s.gopherRoot = s.gopherRootPage()
	s.geminiRoot = s.geminiRootPage()
	return s
}

var zeroTime time.Time

const (
	maxRequestLine = 1024 // Gemini's limit; plenty for a gopher selector
	readTimeout    = 10 * time.Second
	writeMargin    = 2 * time.Minute
)

// ErrClosed is returned by the Serve methods after Shutdown.
var ErrClosed = errors.New("smallweb: server closed")

// serve accepts connections on ln until Shutdown.
func (s *Server) serve(ln net.Listener, handle func(net.Conn)) error {
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		ln.Close()
		return ErrClosed
	}
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return ErrClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// Temporary (e.g. out of file descriptors): back off.
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			handle(c)
		}()
	}
}

// Shutdown stops accepting, cuts in-flight drips and waits for handlers
// (or ctx).
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.cancel()
	for _, ln := range s.lns {
		ln.Close()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// readRequest reads one CRLF- (or LF-) terminated request line of at most
// maxRequestLine bytes. It returns what it read even on error, so partial
// requests can be logged.
func readRequest(c net.Conn, now time.Time) (string, error) {
	c.SetReadDeadline(now.Add(readTimeout))
	r := bufio.NewReaderSize(c, 256)
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return string(line), err
		}
		if b == '\n' {
			return strings.TrimSuffix(string(line), "\r"), nil
		}
		if len(line) == maxRequestLine+1 { // +1 for a trailing \r
			return string(line), errTooLong
		}
		line = append(line, b)
	}
}

var errTooLong = errors.New("request line too long")

// base starts the log record for a connection.
func (s *Server) base(c net.Conn, start time.Time, scheme string) (logstore.Request, netip.Addr) {
	var ip netip.Addr
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		ip = ap.Addr().Unmap()
	}
	rec := logstore.Request{
		TsStart: start.UnixMilli(),
		IP:      ip.String(),
		Method:  "GET", // a fetch, as far as the reports are concerned
		Depth:   -1,
		Scheme:  scheme,
		Proto:   scheme,
	}
	if s.d.Lookup != nil && ip.IsValid() {
		rec.ASN, rec.ASNOrg, rec.Country = s.d.Lookup(ip)
	}
	return rec, ip
}

// finish completes and logs rec, and queues the client for classification.
func (s *Server) finish(rec logstore.Request, ip netip.Addr, sent int64) {
	rec.BytesSent = sent
	rec.TsEnd = max(s.d.Now().UnixMilli(), rec.TsStart)
	s.Metrics.BytesSent.Add(uint64(max(sent, 0)))
	if rec.IsViolation {
		s.Metrics.Violations.Add(1)
	}
	if s.d.Observer != nil && ip.IsValid() {
		s.d.Observer.Observe(rec.IP, rec.UserAgent)
	}
	s.d.Logger.LogRequest(rec)
}

// connWriter adapts a connection to the drip's http.ResponseWriter. Every
// Write goes straight to the socket (TLS: one record), so no Flush is
// needed.
type connWriter struct {
	c net.Conn
	h http.Header
}

func (w *connWriter) Header() http.Header {
	if w.h == nil {
		w.h = http.Header{}
	}
	return w.h
}
func (w *connWriter) Write(b []byte) (int, error) { return w.c.Write(b) }
func (w *connWriter) WriteHeader(int)             {}

// write sends a short, whole response.
func (s *Server) write(c net.Conn, body []byte) int64 {
	c.SetWriteDeadline(s.d.Now().Add(readTimeout))
	n, _ := s.d.Dripper.Fast(&connWriter{c: c}, body)
	return n
}

// serveMaze sends header+page for path in format f, dripped like the web
// maze. busy is the short answer for a client over a limit. It fills in
// the maze fields of rec and returns bytes sent.
func (s *Server) serveMaze(c net.Conn, rec *logstore.Request, ip netip.Addr, path string, f maze.Format, header string, busy []byte) int64 {
	rec.IsViolation = true
	rec.Depth = maze.Depth(path)
	var hasParent bool
	rec.PageID, rec.ParentID, hasParent = s.d.Pages.IDs(path)
	if !hasParent {
		rec.ParentID = 0
	}
	if !ip.IsValid() || (s.d.Rate != nil && !s.d.Rate.Allow(ip)) || !s.d.Limiter.Acquire(ip, rec.ASN) {
		s.Metrics.Shed.Add(1)
		rec.EndReason = "shed"
		return s.write(c, busy)
	}
	defer s.d.Limiter.Release(ip, rec.ASN)

	buf := maze.GetBuffer()
	defer maze.PutBuffer(buf)
	buf.WriteString(header)
	lead := len(header) + s.d.Pages.RenderAs(buf, path, f, s.d.Host, s.d.GopherPort)

	start := s.d.Now()
	key := drip.KeyFor(ip, rec.ASN, rec.UserAgent)
	plan := drip.Plan{Lead: lead}
	if s.d.Patience != nil {
		plan.MaxDuration = s.d.Patience.Budget(key)
	}
	c.SetWriteDeadline(start.Add(s.d.MaxDrip + writeMargin))
	n, outcome, _ := s.d.Dripper.DripWith(s.ctx, &connWriter{c: c}, buf.Bytes(), uint64(start.UnixNano()), plan)
	if outcome == drip.WriteFailed {
		// On a bare connection a failed write means the client hung up;
		// there is no request context to tell us sooner.
		outcome = drip.ClientGone
	}
	if s.d.Patience != nil {
		s.d.Patience.Observe(key, s.d.Now().Sub(start), outcome)
	}
	rec.Dripped = true
	rec.EndReason = outcome.String()
	return n
}

// cleanPath reduces a requested path to what the log keeps: the path
// itself, with "?" marking that a query was sent (a Gemini query or gopher
// search is user input, so its value is never stored).
func cleanPath(p string, hadQuery bool) string {
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	if len(p) > 1024 {
		p = p[:1024]
	}
	if hadQuery {
		p += "?"
	}
	return p
}
