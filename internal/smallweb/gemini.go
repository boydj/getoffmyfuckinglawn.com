package smallweb

import (
	"crypto/tls"
	"net"
	"net/url"
	"strings"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/maze"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/server"
)

// ServeGemini serves Gemini on ln (plain TCP; TLS is added here with cert)
// until Shutdown. The client sends one absolute URL line; the server
// answers with a status line and body, then closes.
//
//	/             the root page (the "homepage": it carries entry links)
//	/robots.txt   the rule, as for HTTP (Gemini's robots.txt convention)
//	/lawn/...     the maze, as gemtext, dripped
func (s *Server) ServeGemini(ln net.Listener, cert tls.Certificate) error {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // the Gemini spec requires 1.2+
		// Client certificates are optional in Gemini and unused here.
		ClientAuth: tls.RequestClientCert,
	}
	return s.serve(tls.NewListener(ln, cfg), s.handleGemini)
}

func (s *Server) handleGemini(c net.Conn) {
	start := s.d.Now()
	tc := c.(*tls.Conn)
	tc.SetDeadline(start.Add(readTimeout))
	if err := tc.Handshake(); err != nil {
		return // not a Gemini client (scanner, plain-TCP probe): not a request
	}
	tc.SetDeadline(zeroTime)
	line, err := readRequest(c, start)
	if err != nil && line == "" {
		return
	}
	s.Metrics.Gemini.Add(1)
	rec, ip := s.base(c, start, "gemini")
	cs := tc.ConnectionState()
	rec.TLS = strings.TrimSpace(tlsVersion(cs.Version) + " " + tls.CipherSuiteName(cs.CipherSuite))

	var sent int64
	u, perr := url.Parse(line)
	switch {
	case err != nil || perr != nil || u.Scheme != "gemini" || u.Host == "":
		// Not an absolute gemini:// URL. Other schemes are proxy requests,
		// which this capsule refuses (53).
		rec.Path = cleanPath("", false)
		if perr == nil && u.Scheme != "" && u.Scheme != "gemini" {
			rec.Status = 53
			sent = s.write(c, []byte("53 Proxy requests are refused\r\n"))
		} else {
			rec.Status = 59
			sent = s.write(c, []byte("59 Bad request\r\n"))
		}
	default:
		p := u.EscapedPath()
		rec.Path = cleanPath(p, u.RawQuery != "")
		switch {
		case p == "" || p == "/":
			rec.Status = 20
			sent = s.write(c, s.geminiRoot)
		case p == "/robots.txt":
			rec.Status = 20
			sent = s.write(c, append([]byte("20 text/plain\r\n"), server.RobotsTxt...))
			s.d.Logger.LogRobots(logstore.RobotsFetch{IP: rec.IP, UserAgent: rec.UserAgent, Ts: rec.TsStart})
		case maze.IsMazePath(p):
			rec.Status = 20
			sent = s.serveMaze(c, &rec, ip, p, maze.FormatGemini, "20 text/gemini; lang=en\r\n", geminiBusy)
			if rec.EndReason == "shed" {
				rec.Status = 44
			}
		default:
			rec.Status = 51
			sent = s.write(c, []byte("51 Not found. The only rule is in /robots.txt\r\n"))
		}
	}
	s.finish(rec, ip, sent)
}

// geminiBusy is Gemini's "slow down" (44) with a wait in seconds.
var geminiBusy = []byte("44 60\r\n")

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "tls1.3"
	case tls.VersionTLS12:
		return "tls1.2"
	}
	return "tls?"
}

// geminiRootPage is the root page: what this is, the rule, where the wall
// is, and (plainly labelled) entry links into the maze.
func (s *Server) geminiRootPage() []byte {
	var b strings.Builder
	b.WriteString("20 text/gemini; lang=en\r\n")
	b.WriteString("# Get off my lawn.\n\n")
	b.WriteString("This capsule has exactly one rule, and it is written down in /robots.txt: stay out of /lawn/. Crawlers that read the rule and walk in anyway get an endless maze of pointless pages, served a few bytes a second. Then they get their name on the wall.\n\n")
	b.WriteString("=> /robots.txt robots.txt\n")
	if s.d.WebURL != "" {
		b.WriteString("=> " + s.d.WebURL + "/shame/ The wall of shame (web)\n")
		b.WriteString("=> " + s.d.WebURL + "/ About this site (web)\n")
	}
	b.WriteString("\n## Crawlers only\n\nEverything below is disallowed by robots.txt.\n\n")
	for _, u := range s.d.Pages.EntryURLs(6) {
		b.WriteString("=> " + u + " Lawn\n")
	}
	return []byte(b.String())
}
