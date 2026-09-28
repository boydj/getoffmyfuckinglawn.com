package smallweb

import (
	"bytes"
	"net"
	"strconv"
	"strings"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/maze"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/server"
)

// ServeGopher serves Gopher (RFC 1436) on ln until Shutdown. The client
// sends one selector line; the server answers and closes.
//
//	"" or "/"       the root menu (the "homepage": it carries entry links)
//	"/robots.txt"   the rule, as for HTTP (selector "robots.txt" too)
//	"/lawn/..."     the maze, as gopher menus, dripped
func (s *Server) ServeGopher(ln net.Listener) error { return s.serve(ln, s.handleGopher) }

func (s *Server) handleGopher(c net.Conn) {
	start := s.d.Now()
	line, err := readRequest(c, start)
	if err != nil && line == "" {
		return // connected and said nothing (a port scan): not a request
	}
	s.Metrics.Gopher.Add(1)
	rec, ip := s.base(c, start, "gopher")
	// A gopher search sends "selector<TAB>query"; gopher+ appends
	// "<TAB>+" or "<TAB>$". Only the selector is kept.
	sel, extra, hasExtra := strings.Cut(line, "\t")
	rec.Path = cleanPath(sel, hasExtra && extra != "" && extra != "+" && extra != "$")
	var sent int64
	switch {
	case err != nil:
		rec.Status = 400
		sent = s.write(c, gopherError("Bad request."))
	case sel == "" || sel == "/":
		rec.Status = 200
		sent = s.write(c, s.gopherRoot)
	case sel == "/robots.txt" || sel == "robots.txt":
		rec.Status = 200
		rec.Path = "/robots.txt"
		sent = s.write(c, []byte(server.RobotsTxt))
		s.d.Logger.LogRobots(logstore.RobotsFetch{IP: rec.IP, UserAgent: rec.UserAgent, Ts: rec.TsStart})
	case maze.IsMazePath(rec.Path):
		rec.Status = 200
		sent = s.serveMaze(c, &rec, ip, rec.Path, maze.FormatGopher, "", gopherBusy)
	default:
		rec.Status = 404
		sent = s.write(c, gopherError("Not found. The only rule is in robots.txt."))
	}
	s.finish(rec, ip, sent)
}

var gopherBusy = gopherError("The lawn is full. Try again later.")

// gopherError is a one-item menu with an error (type 3) line.
func gopherError(msg string) []byte {
	return []byte("3" + msg + "\tfake\t(NULL)\t0\r\n.\r\n")
}

// gopherRootPage is the root menu: what this is, the rule, where the wall is,
// and (plainly labelled) entry links into the maze.
func (s *Server) gopherRootPage() []byte {
	var b bytes.Buffer
	info := func(t string) { b.WriteString("i" + t + "\tfake\t(NULL)\t0\r\n") }
	item := func(typ byte, name, sel string) {
		b.WriteByte(typ)
		b.WriteString(name + "\t" + sel + "\t" + s.d.Host + "\t" + strconv.Itoa(s.d.GopherPort) + "\r\n")
	}
	info("Get off my lawn.")
	info("")
	info("This server has exactly one rule, and it is written down in")
	info("robots.txt: stay out of /lawn/. Crawlers that read the rule and")
	info("walk in anyway get an endless maze of pointless menus, served a")
	info("few bytes a second. Then they get their name on the wall.")
	info("")
	item('0', "robots.txt", "/robots.txt")
	if s.d.WebURL != "" {
		item('h', "The wall of shame (web)", "URL:"+s.d.WebURL+"/shame/")
		item('h', "About this site (web)", "URL:"+s.d.WebURL+"/")
	}
	info("")
	info("Everything below is disallowed by robots.txt. Crawlers only.")
	for _, u := range s.d.Pages.EntryURLs(6) {
		item('1', "Lawn", u)
	}
	b.WriteString(".\r\n")
	return b.Bytes()
}
