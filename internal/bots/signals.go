package bots

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"math"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// Signals: why a client looks automated. Each is a fact about what the
// client sent or did; none alone proves automation. Weights add up to a
// group's score: 3 = no browser does this, 2 = rare for a person, 1 =
// supporting evidence only.
const (
	SigNamed        = "ua-names-bot-or-library"
	SigRobots       = "fetched-robots.txt"
	SigEntered      = "entered-/lawn/"
	SigNoAcceptLang = "no-accept-language"
	SigPTR          = "ptr-looks-like-crawler"
	SigNoH2         = "browser-ua-tls-offers-no-h2"    // JA4: ClientHello without h2 in ALPN
	SigTLSLibrary   = "browser-ua-tls-like-library:"   // + the library, e.g. "python-requests"
	SigHTTP1        = "browser-ua-over-https-http/1.1" // negotiated HTTP/1.1 although Caddy offers h2
	SigNoSecFetch   = "browser-ua-no-sec-fetch"        // modern browser without Sec-Fetch-* over HTTPS
	SigHead         = "browser-ua-head-requests"
	SigFast         = "fast-maze-walk"   // many maze pages in one minute
	SigRegular      = "metronome-timing" // evenly spaced requests
	SigOpensEarly   = "follows-links-before-page-ends"
	SigDeep         = "deep-in-maze"
	SigErrors       = "mostly-errors"
	SigNoFavicon    = "browser-ua-no-favicon"
	SigHosting      = "hosting-network"
	// + the first name JA4DB gives, e.g. "Python (Linux)". Private: rests
	// on FoxIO's database, not on our own observations.
	SigTLSJA4DB = "browser-ua-tls-ja4db-non-browser:"
)

var weights = map[string]int{
	SigNamed: 3, SigRobots: 2, SigEntered: 1, SigNoAcceptLang: 2, SigPTR: 2,
	SigNoH2: 3, SigTLSLibrary: 3, SigHTTP1: 2, SigNoSecFetch: 3, SigHead: 1,
	SigFast: 2, SigRegular: 2, SigOpensEarly: 3, SigDeep: 1, SigErrors: 1,
	SigNoFavicon: 1, SigHosting: 1, SigTLSJA4DB: 3,
}

// supportingOnly signals never list a client on their own: plenty of
// people browse from VPNs on hosting networks, and a cached favicon is
// not fetched again.
var supportingOnly = map[string]bool{SigHosting: true, SigNoFavicon: true}

// Thresholds. A person clicking through the maze waits for each dripping
// page; these are well beyond that.
const (
	fastPagesPerMinute = 30   // maze pages within any 60 s
	regularMinGaps     = 20   // gaps needed to judge timing
	regularMaxCV       = 0.25 // stddev/mean of the gaps
	deepDepth          = 10
	openEarlyMinFollow = 5
	errorsMinRequests  = 10
	noFaviconMinPages  = 10
)

// Weight is a signal's weight (prefix-matched for SigTLSLibrary).
func Weight(sig string) int {
	for _, p := range []string{SigTLSLibrary, SigTLSJA4DB} {
		if strings.HasPrefix(sig, p) {
			return weights[p]
		}
	}
	return weights[sig]
}

// Score adds up the weights of a set of signals.
func Score(sigs map[string]bool) int {
	n := 0
	for s := range sigs {
		n += Weight(s)
	}
	return n
}

// listable reports whether reasons are enough to list a client.
func listable(reasons []string) bool {
	for _, r := range reasons {
		if !supportingOnly[r] {
			return true
		}
	}
	return false
}

// scorer holds what signals needs beyond the client itself.
type scorer struct {
	ja4db   *JA4DB              // nil: not loaded
	hosting map[uint32]bool     // nil: list not loaded
	libJA4  map[string][]string // JA4 -> HTTP libraries seen with it
}

// newScorer indexes which TLS fingerprints HTTP libraries used in clients.
func newScorer(clients []*Client, hosting map[uint32]bool) *scorer {
	s := &scorer{hosting: hosting, libJA4: map[string][]string{}}
	for _, c := range clients {
		lib := Library(c.UA)
		if lib == "" {
			continue
		}
		for _, fp := range c.JA4s {
			if !slices.Contains(s.libJA4[fp], lib) {
				s.libJA4[fp] = append(s.libJA4[fp], lib)
			}
		}
	}
	for _, libs := range s.libJA4 {
		slices.Sort(libs)
	}
	return s
}

// signals lists why a client looks automated.
func (s *scorer) signals(c *Client, named bool) []string {
	var r []string
	add := func(sig string) { r = append(r, sig) }
	if named {
		add(SigNamed)
	}
	if c.Robots > 0 {
		add(SigRobots)
	}
	if c.Violations > 0 {
		add(SigEntered)
	}
	// Browsers always send Accept-Language.
	if c.Captured > 0 && c.NoAcceptLg == c.Captured {
		add(SigNoAcceptLang)
	}
	if c.PTR != "" && crawlerishPTR.MatchString(c.PTR) {
		add(SigPTR)
	}
	if s.hosting != nil && c.ASN > 0 && c.ASN <= math.MaxUint32 && s.hosting[uint32(c.ASN)] {
		add(SigHosting)
	}
	// How the client walks the maze.
	if c.MaxPerMinute >= fastPagesPerMinute {
		add(SigFast)
	}
	if c.Gaps >= regularMinGaps && c.GapCV < regularMaxCV {
		add(SigRegular)
	}
	if c.Follows >= openEarlyMinFollow && c.Open*2 >= c.Follows {
		add(SigOpensEarly)
	}
	if c.MaxDepth >= deepDepth {
		add(SigDeep)
	}
	if c.Requests >= errorsMinRequests && c.Errors*2 >= c.Requests {
		add(SigErrors)
	}

	// The rest compare what a browser user agent claims with what real
	// browsers send. Our own HTTPS site offers h2 and, for modern browsers,
	// receives Sec-Fetch-* headers on every request.
	b, ok := ParseBrowser(c.UA)
	if !ok {
		return r
	}
	var libs []string
	noH2 := false
	for _, fp := range c.JA4s {
		if len(fp) >= 10 && fp[8:10] != "h2" {
			noH2 = true
		}
		for _, l := range s.libJA4[fp] {
			if !slices.Contains(libs, l) {
				libs = append(libs, l)
			}
		}
	}
	if noH2 {
		add(SigNoH2)
	}
	slices.Sort(libs)
	for _, l := range libs {
		add(SigTLSLibrary + l)
	}
	// FoxIO's database knows this fingerprint only from non-browser
	// software. One signal per client, named after the first fingerprint
	// that qualifies.
	for _, fp := range c.JA4s {
		if names, ok := s.ja4db.NonBrowser(fp); ok && len(names) > 0 {
			add(SigTLSJA4DB + names[0])
			break
		}
	}
	if c.HTTPS > 0 && c.HTTPSH1 == c.HTTPS {
		add(SigHTTP1)
	}
	if b.SendsSecFetch() && c.HTTPSCaptured > 0 && c.HTTPSNoSecFetch == c.HTTPSCaptured {
		add(SigNoSecFetch)
	}
	if c.Heads > 0 {
		add(SigHead)
	}
	if c.HTTPSPages >= noFaviconMinPages && c.Favicon == 0 {
		add(SigNoFavicon)
	}
	return r
}

// Browser is the engine and version a user agent claims.
type Browser struct {
	Family       string // chrome, edge, firefox, safari
	Major, Minor int
}

var (
	reEdge    = regexp.MustCompile(`\bEdg/(\d+)`)
	reChrome  = regexp.MustCompile(`\bChrome/(\d+)`)
	reFirefox = regexp.MustCompile(`\bFirefox/(\d+)`)
	reSafari  = regexp.MustCompile(`\bVersion/(\d+)(?:\.(\d+))?.*\bSafari/`)
	// iOS browsers wrap WebKit and do not say which WebKit; skip them.
	reIOSWrapper = regexp.MustCompile(`\b(?:CriOS|FxiOS|EdgiOS|OPiOS)/`)
)

// ParseBrowser recognises the mainstream browsers a scraper is likely to
// impersonate. ok is false for anything else, including UAs that name a
// bot or library.
func ParseBrowser(ua string) (Browser, bool) {
	if !strings.HasPrefix(ua, "Mozilla/5.0 ") || reIOSWrapper.MatchString(ua) {
		return Browser{}, false
	}
	if _, named := Token(ua); named {
		return Browser{}, false
	}
	num := func(m []string, i int) int {
		if i >= len(m) || m[i] == "" {
			return 0
		}
		n, _ := strconv.Atoi(m[i])
		return n
	}
	switch {
	case reEdge.MatchString(ua):
		return Browser{"edge", num(reEdge.FindStringSubmatch(ua), 1), 0}, true
	case reChrome.MatchString(ua):
		return Browser{"chrome", num(reChrome.FindStringSubmatch(ua), 1), 0}, true
	case reFirefox.MatchString(ua):
		return Browser{"firefox", num(reFirefox.FindStringSubmatch(ua), 1), 0}, true
	case reSafari.MatchString(ua):
		m := reSafari.FindStringSubmatch(ua)
		return Browser{"safari", num(m, 1), num(m, 2)}, true
	}
	return Browser{}, false
}

// SendsSecFetch reports whether this browser version sends Sec-Fetch-*
// headers to HTTPS sites: Chrome 76, Edge 79, Firefox 90, Safari 16.4.
func (b Browser) SendsSecFetch() bool {
	switch b.Family {
	case "chrome":
		return b.Major >= 76
	case "edge":
		return b.Major >= 79
	case "firefox":
		return b.Major >= 90
	case "safari":
		return b.Major > 16 || b.Major == 16 && b.Minor >= 4
	}
	return false
}

// Library returns the HTTP library a UA names ("python-requests"), or ""
// for anything else. Headless browsers are not libraries: they share real
// browsers' TLS stacks.
func Library(ua string) string {
	m := libToken.FindStringSubmatch(strings.TrimSpace(ua))
	if m == nil {
		return ""
	}
	switch l := strings.ToLower(m[1]); l {
	case "headlesschrome", "phantomjs":
		return ""
	default:
		return l
	}
}

// LoadHostingASNs reads a list of hosting/datacenter ASNs, one "AS<n>" per
// line with optional "# comment" (X4BNet's format). A missing file returns
// nil, nil: the hosting signal is then left out.
func LoadHostingASNs(path string) (map[uint32]bool, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[uint32]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "# \t"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimPrefix(strings.ToUpper(line), "AS")
		if n, err := strconv.ParseUint(line, 10, 32); err == nil && n > 0 {
			m[uint32(n)] = true
		}
	}
	return m, sc.Err()
}

// timing accumulates one client's maze request times (unix ms, ascending).
type timing struct {
	ts []int64
}

// result returns the most maze pages within any 60 s, the number of gaps
// and their coefficient of variation.
func (t *timing) result() (perMinute, gaps int64, cv float64) {
	j := 0
	for i := range t.ts {
		for t.ts[i]-t.ts[j] >= 60_000 {
			j++
		}
		perMinute = max(perMinute, int64(i-j+1))
	}
	if len(t.ts) < 2 {
		return perMinute, 0, 0
	}
	n := float64(len(t.ts) - 1)
	var sum, sq float64
	for i := 1; i < len(t.ts); i++ {
		g := float64(t.ts[i] - t.ts[i-1])
		sum += g
		sq += g * g
	}
	mean := sum / n
	if mean == 0 {
		return perMinute, int64(n), 0
	}
	variance := math.Max(sq/n-mean*mean, 0)
	return perMinute, int64(n), math.Sqrt(variance) / mean
}

// PublicSignals are the signals the Wall of Shame may show: observations
// of what a client sent or how it walked the maze. Left out: the user
// agent naming a bot (its UA is shown anyway), robots.txt and /lawn/
// (the wall already reports both), and reverse DNS (a per-address lookup).
var PublicSignals = []string{
	SigTLSLibrary, SigNoH2, SigNoSecFetch, SigOpensEarly, SigHTTP1, SigNoAcceptLang,
	SigFast, SigRegular, SigHead, SigDeep, SigErrors, SigNoFavicon, SigHosting,
}

// IsPublic reports whether sig may be published (prefix-matched for
// SigTLSLibrary).
func IsPublic(sig string) bool {
	for _, p := range PublicSignals {
		if sig == p || p == SigTLSLibrary && strings.HasPrefix(sig, p) {
			return true
		}
	}
	return false
}

// ClientTraits is what the wall shows about one (ip, user agent).
type ClientTraits struct {
	Signals   []string // public signals only
	PerMinute int64    // most /lawn/ fetches within any 60 s
	JA4s      []string
}

// TraitOptions configures Traits.
type TraitOptions struct {
	DB      *sql.DB
	Hosting map[uint32]bool
	Exclude []netip.Prefix
}

// Traits computes the public signals of every (ip, user agent) in the raw
// request log (rolled-up history has no detail). Keys are {ip, ua}.
func Traits(ctx context.Context, opt TraitOptions) (map[[2]string]ClientTraits, error) {
	clients, err := scanClients(ctx, opt.DB, 0, false, logstore.NewIPSet(opt.Exclude))
	if err != nil {
		return nil, err
	}
	sc := newScorer(clients, opt.Hosting)
	out := make(map[[2]string]ClientTraits, len(clients))
	for _, c := range clients {
		_, named := Token(c.UA)
		var t ClientTraits
		for _, s := range sc.signals(c, named) {
			if IsPublic(s) {
				t.Signals = append(t.Signals, s)
			}
		}
		t.PerMinute, t.JA4s = c.MaxPerMinute, c.JA4s
		out[[2]string{c.IP, c.UA}] = t
	}
	return out, nil
}
