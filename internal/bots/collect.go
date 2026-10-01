package bots

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/attrib"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// Options configures Collect.
type Options struct {
	DB       *sql.DB
	Crawlers []attrib.Crawler // to tell known bots from unknown ones
	Since    time.Duration    // window; 0 = everything kept (raw + daily_visits)
	NewFor   time.Duration    // a group first seen within this long ago is "new" (default 7d)
	All      bool             // include clients with no bot signal (likely humans)
	Now      func() time.Time
	Exclude  []netip.Prefix  // operator networks (config exclude_cidrs): skipped
	Hosting  map[uint32]bool // hosting/datacenter ASNs (LoadHostingASNs); nil = not loaded
}

// Verdicts: what a group did with respect to robots.txt.
const (
	VerdictReadAndEntered = "read robots.txt, entered /lawn/"
	VerdictEntered        = "entered /lawn/"
	VerdictCompliant      = "compliant"
	VerdictNoRobots       = "never fetched robots.txt"
)

// Client is one (ip, user agent) in the window.
type Client struct {
	IP, UA               string
	ASN                  int64
	ASNOrg               string
	Requests, Robots     int64
	Bait, Violations     int64
	MaxDepth             int64
	First, Last          int64 // unix ms, within the window
	Status, ClaimedOrg   string
	PTR                  string
	Captured, NoAcceptLg int64 // rows with header data; of those, without Accept-Language
	HeaderNames          string
	Proto, TLS           string
	Country              string // "" = unknown or rolled-up only
	Schemes              string // comma-separated: https, http, gopher, gemini
	Frontier
	// Raw-row details for the browser-consistency and behaviour signals
	// (zero for rolled-up history).
	Heads, Errors, Favicon int64
	HTTPS, HTTPSH1         int64    // requests over HTTPS; of those, over HTTP/1.1
	HTTPSPages             int64    // page fetches (/, /lawn/, /shame/) over HTTPS
	HTTPSCaptured          int64    // HTTPS rows with header data
	HTTPSNoSecFetch        int64    // of those, without Sec-Fetch-Mode
	JA4s                   []string // distinct TLS fingerprints
	MaxPerMinute           int64    // most /lawn/ fetches within any 60 s
	Gaps                   int64    // gaps between /lawn/ fetches
	GapCV                  float64  // their coefficient of variation
}

// Frontier measures how a client walks the maze: of its /lawn/ fetches
// whose URL names a parent page (Children), how many followed a fetch of
// that parent by the same user agent (Follows), and how many of those
// started while the parent response was still dripping (Open). A high
// Open share means the tarpit's links are harvested before the page
// finishes, so holding a connection does not slow the crawl down.
type Frontier struct {
	Children, Follows, Open int64
}

// Bot is every client sharing one product token (or, for browser-looking
// UAs with bot signals, one network).
type Bot struct {
	Token       string
	Known       string // "Org (Name)" from crawlers.yaml, "" if unknown
	Contact     string
	Verdict     string
	New         bool
	FirstSeen   int64 // all-time, unix ms
	LastSeen    int64
	Requests    int64
	Robots      int64
	Bait        int64
	Violations  int64
	MaxDepth    int64
	Statuses    map[string]int
	IPs         map[string]bool
	ASNs        map[string]int64 // "AS<n> <org>" -> requests
	PTRDomains  map[string]int64
	Reasons     map[string]bool
	ReasonN     map[string]int // signal -> clients in the group that showed it
	SampleUA    string
	HeaderNames string
	Protos      map[string]int64
	TLS         map[string]int64
	Countries   map[string]int64 // country code -> requests
	Schemes     map[string]int   // scheme -> clients that used it
	JA4         map[string]int   // TLS fingerprint -> clients that used it
	Score       int              // sum of the signals' weights
	MaxPerMin   int64            // fastest client's most /lawn/ fetches in 60 s
	Frontier
	Clients []*Client
}

// Report is the result of Collect.
type Report struct {
	Generated time.Time
	Since     time.Duration
	Clients   int
	Hosting   bool   // the hosting-ASN list was loaded
	Bots      []*Bot // sorted: new first, then unknown, then by requests
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

// Collect reads the database and groups bot-like clients.
func Collect(ctx context.Context, opt Options) (*Report, error) {
	now := opt.now()
	if opt.NewFor <= 0 {
		opt.NewFor = 7 * 24 * time.Hour
	}
	var from int64
	if opt.Since > 0 {
		from = now.Add(-opt.Since).UnixMilli()
	}
	clients, err := scanClients(ctx, opt.DB, from, opt.Since == 0, logstore.NewIPSet(opt.Exclude))
	if err != nil {
		return nil, err
	}
	firstSeen, err := uaFirstSeen(ctx, opt.DB)
	if err != nil {
		return nil, err
	}

	rep := &Report{Generated: now, Since: opt.Since, Clients: len(clients), Hosting: opt.Hosting != nil}
	sc := newScorer(clients, opt.Hosting)
	groups := map[string]*Bot{}
	for _, c := range clients {
		token, named := Token(c.UA)
		if c.UA == "" {
			// Gopher and Gemini have no user agent. Their clients are grouped
			// by protocol and, like browsers, need a bot signal to be listed:
			// people use these protocols too.
			switch c.Schemes {
			case "gopher", "gemini":
				token, named = "("+c.Schemes+" client)", false
			}
		}
		reasons := sc.signals(c, named)
		if !listable(reasons) && !opt.All {
			continue
		}
		key := token
		if token == "" {
			// Browser-looking UA with bot signals: group by network, which
			// is how headless scrapers usually show up.
			key = "browser-like UA @ " + asnLabel(c.ASN, c.ASNOrg)
		}
		b := groups[key]
		if b == nil {
			b = &Bot{Token: key, Statuses: map[string]int{}, IPs: map[string]bool{}, ASNs: map[string]int64{},
				PTRDomains: map[string]int64{}, Reasons: map[string]bool{}, ReasonN: map[string]int{}, Protos: map[string]int64{}, TLS: map[string]int64{},
				Countries: map[string]int64{}, Schemes: map[string]int{}, JA4: map[string]int{},
				FirstSeen: c.First}
			groups[key] = b
		}
		b.add(c, reasons, opt.Crawlers)
		if fs, ok := firstSeen[c.UA]; ok && fs < b.FirstSeen {
			b.FirstSeen = fs
		}
	}
	newCutoff := now.Add(-opt.NewFor).UnixMilli()
	for _, b := range groups {
		b.finish(newCutoff)
		rep.Bots = append(rep.Bots, b)
	}
	sort.Slice(rep.Bots, func(i, j int) bool {
		a, b := rep.Bots[i], rep.Bots[j]
		if a.New != b.New {
			return a.New
		}
		if (a.Known == "") != (b.Known == "") {
			return a.Known == ""
		}
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return a.Token < b.Token
	})
	return rep, nil
}

func (b *Bot) add(c *Client, reasons []string, crawlers []attrib.Crawler) {
	b.Clients = append(b.Clients, c)
	b.Requests += c.Requests
	b.Robots += c.Robots
	b.Bait += c.Bait
	b.Violations += c.Violations
	b.MaxDepth = max(b.MaxDepth, c.MaxDepth)
	b.Children += c.Children
	b.Follows += c.Follows
	b.Open += c.Open
	b.FirstSeen = min(b.FirstSeen, c.First)
	b.LastSeen = max(b.LastSeen, c.Last)
	st := c.Status
	if st == "" {
		st = "unclassified"
	}
	b.Statuses[st]++
	b.IPs[c.IP] = true
	b.ASNs[asnLabel(c.ASN, c.ASNOrg)] += c.Requests
	if d := Domain(c.PTR); d != "" {
		b.PTRDomains[d] += c.Requests
	}
	for _, r := range reasons {
		b.Reasons[r] = true
		b.ReasonN[r]++
	}
	if c.Proto != "" {
		b.Protos[c.Proto] += c.Requests
	}
	if c.TLS != "" {
		b.TLS[c.TLS] += c.Requests
	}
	if c.Country != "" {
		b.Countries[c.Country] += c.Requests
	}
	for _, sc := range strings.Split(c.Schemes, ",") {
		if sc != "" {
			b.Schemes[sc]++
		}
	}
	for _, fp := range c.JA4s {
		b.JA4[fp]++
	}
	b.MaxPerMin = max(b.MaxPerMin, c.MaxPerMinute)
	if b.SampleUA == "" || (b.Contact == "" && Contact(c.UA) != "") {
		b.SampleUA = c.UA
		b.Contact = Contact(c.UA)
	}
	if b.HeaderNames == "" {
		b.HeaderNames = c.HeaderNames
	}
	if b.Known == "" {
		if cr := attrib.MatchUA(crawlers, c.UA); cr != nil {
			b.Known = cr.Org + " (" + cr.Name + ")"
		}
	}
}

func (b *Bot) finish(newCutoff int64) {
	switch {
	case b.Violations > 0 && b.Robots > 0:
		b.Verdict = VerdictReadAndEntered
	case b.Violations > 0:
		b.Verdict = VerdictEntered
	case b.Robots > 0:
		b.Verdict = VerdictCompliant
	default:
		b.Verdict = VerdictNoRobots
	}
	b.New = b.FirstSeen >= newCutoff
	b.Score = Score(b.Reasons)
}

func asnLabel(asn int64, org string) string {
	if asn < 0 || asn > 1<<32-1 {
		asn = 0
	}
	return logstore.NetworkLabel(uint32(asn), org, "unknown ASN")
}

// isHTTPS is the SQL test for a request that arrived over HTTPS. Rows
// logged before the scheme column (migration 6) have no scheme; back then
// only Caddy's HTTPS site reached the app, and it set the TLS column.
const isHTTPS = `(IFNULL(scheme, '') = 'https' OR (scheme IS NULL AND tls IS NOT NULL))`

// scanClients aggregates raw requests since from (unix ms) per (ip, ua),
// joined with identities and hosts. withDaily adds rolled-up visits.
// Clients whose IP is in skip (operator networks) are left out.
func scanClients(ctx context.Context, db *sql.DB, from int64, withDaily bool, skip *logstore.IPSet) ([]*Client, error) {
	q := `
SELECT r.ip, r.ua, r.asn, r.asn_org, r.requests, r.robots, r.bait, r.violations, r.max_depth, r.first, r.last,
       r.captured, r.no_al, r.header_names, r.proto, r.tls, r.country, r.schemes,
       r.heads, r.errors, r.favicon, r.https, r.https_h1, r.https_pages, r.https_captured, r.https_no_sf, r.ja4s,
       COALESCE(i.status, ''), COALESCE(i.claimed_org, ''), COALESCE(h.ptr, '')
FROM (
  SELECT ip, COALESCE(user_agent, '') AS ua, COALESCE(MAX(asn), 0) AS asn, COALESCE(MAX(asn_org), '') AS asn_org,
         COUNT(*) AS requests,
         SUM(method = 'GET' AND (path = '/robots.txt' OR path LIKE '/robots.txt?%')) AS robots,
         SUM(method = 'GET' AND (path IN ('/', '/sitemap.xml') OR path LIKE '/?%' OR path LIKE '/sitemap.xml?%')) AS bait,
         SUM(is_violation) AS violations,
         COALESCE(MAX(depth), 0) AS max_depth,
         MIN(ts_start) AS first, MAX(ts_start) AS last,
         SUM(header_names IS NOT NULL) AS captured,
         SUM(header_names IS NOT NULL AND accept_language IS NULL) AS no_al,
         COALESCE(MAX(header_names), '') AS header_names,
         COALESCE(MAX(proto), '') AS proto, COALESCE(MAX(tls), '') AS tls,
         COALESCE(MAX(country), '') AS country,
         COALESCE(GROUP_CONCAT(DISTINCT scheme), '') AS schemes,
         SUM(method = 'HEAD') AS heads,
         SUM(status >= 400) AS errors,
         SUM(path = '/favicon.ico' OR path LIKE '/favicon.ico?%') AS favicon,
         SUM(` + isHTTPS + `) AS https,
         SUM(` + isHTTPS + ` AND IFNULL(proto, '') = 'HTTP/1.1') AS https_h1,
         SUM(` + isHTTPS + ` AND method = 'GET' AND (path = '/' OR path LIKE '/?%' OR path LIKE '/lawn/%'
             OR path LIKE '/shame/%')) AS https_pages,
         SUM(` + isHTTPS + ` AND header_names IS NOT NULL) AS https_captured,
         SUM(` + isHTTPS + ` AND header_names IS NOT NULL
             AND instr(',' || header_names || ',', ',Sec-Fetch-Mode,') = 0) AS https_no_sf,
         COALESCE(GROUP_CONCAT(DISTINCT ja4), '') AS ja4s
  FROM requests WHERE ts_start >= ?
  GROUP BY ip, COALESCE(user_agent, '')
) r
LEFT JOIN identities i ON i.ip = r.ip AND i.user_agent = r.ua
LEFT JOIN hosts h ON h.ip = r.ip`
	rows, err := db.QueryContext(ctx, q, from)
	if err != nil {
		return nil, fmt.Errorf("bots: scan: %w", err)
	}
	byKey := map[[2]string]*Client{}
	var out []*Client
	for rows.Next() {
		c := &Client{}
		var ja4s string
		if err := rows.Scan(&c.IP, &c.UA, &c.ASN, &c.ASNOrg, &c.Requests, &c.Robots, &c.Bait, &c.Violations, &c.MaxDepth,
			&c.First, &c.Last, &c.Captured, &c.NoAcceptLg, &c.HeaderNames, &c.Proto, &c.TLS, &c.Country, &c.Schemes,
			&c.Heads, &c.Errors, &c.Favicon, &c.HTTPS, &c.HTTPSH1, &c.HTTPSPages, &c.HTTPSCaptured, &c.HTTPSNoSecFetch, &ja4s,
			&c.Status, &c.ClaimedOrg, &c.PTR); err != nil {
			rows.Close()
			return nil, fmt.Errorf("bots: scan: %w", err)
		}
		if ja4s != "" {
			c.JA4s = strings.Split(ja4s, ",")
			sort.Strings(c.JA4s)
		}
		if skip.Has(c.IP) {
			continue
		}
		byKey[[2]string{c.IP, c.UA}] = c
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("bots: scan: %w", err)
	}
	if err := scanFrontier(ctx, db, from, byKey); err != nil {
		return nil, err
	}
	if err := scanTiming(ctx, db, from, byKey); err != nil {
		return nil, err
	}
	if !withDaily {
		return out, nil
	}
	rows, err = db.QueryContext(ctx, `
SELECT d.ip, d.user_agent, COALESCE(MAX(d.asn), 0), COALESCE(MAX(d.asn_org), ''), SUM(d.requests), SUM(d.robots),
       SUM(d.bait_views), SUM(d.violations), MIN(d.first_ts), MAX(d.last_ts),
       COALESCE(i.status, ''), COALESCE(i.claimed_org, ''), COALESCE(h.ptr, '')
FROM daily_visits d
LEFT JOIN identities i ON i.ip = d.ip AND i.user_agent = d.user_agent
LEFT JOIN hosts h ON h.ip = d.ip
GROUP BY d.ip, d.user_agent`)
	if err != nil {
		return nil, fmt.Errorf("bots: daily: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		d := &Client{}
		if err := rows.Scan(&d.IP, &d.UA, &d.ASN, &d.ASNOrg, &d.Requests, &d.Robots, &d.Bait, &d.Violations,
			&d.First, &d.Last, &d.Status, &d.ClaimedOrg, &d.PTR); err != nil {
			return nil, fmt.Errorf("bots: daily: %w", err)
		}
		if skip.Has(d.IP) {
			continue
		}
		if c := byKey[[2]string{d.IP, d.UA}]; c != nil {
			c.Requests += d.Requests
			c.Robots += d.Robots
			c.Bait += d.Bait
			c.Violations += d.Violations
			c.First = min(c.First, d.First)
			c.Last = max(c.Last, d.Last)
			continue
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// scanFrontier fills Frontier for clients in byKey from raw requests since
// from. Parents are matched by user agent across IPs, since distributed
// crawlers often fetch a page from one address and its links from others.
// A parent that has aged out of requests leaves its children unmatched.
func scanFrontier(ctx context.Context, db *sql.DB, from int64, byKey map[[2]string]*Client) error {
	rows, err := db.QueryContext(ctx, `
SELECT ip, ua, COUNT(*), SUM(follows), SUM(open) FROM (
  SELECT c.ip, COALESCE(c.user_agent, '') AS ua,
         EXISTS(SELECT 1 FROM requests p WHERE p.page_id = c.parent_id AND p.user_agent IS c.user_agent
                AND p.ts_start <= c.ts_start) AS follows,
         EXISTS(SELECT 1 FROM requests p WHERE p.page_id = c.parent_id AND p.user_agent IS c.user_agent
                AND p.ts_start <= c.ts_start AND c.ts_start < p.ts_end) AS open
  FROM requests c WHERE c.parent_id IS NOT NULL AND c.ts_start >= ?
)
GROUP BY ip, ua`, from)
	if err != nil {
		return fmt.Errorf("bots: frontier: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip, ua string
		var f Frontier
		if err := rows.Scan(&ip, &ua, &f.Children, &f.Follows, &f.Open); err != nil {
			return fmt.Errorf("bots: frontier: %w", err)
		}
		if c := byKey[[2]string{ip, ua}]; c != nil {
			c.Frontier = f
		}
	}
	return rows.Err()
}

// scanTiming fills each client's maze timing from its /lawn/ fetches since
// from, streamed in (ip, ua, time) order.
func scanTiming(ctx context.Context, db *sql.DB, from int64, byKey map[[2]string]*Client) error {
	rows, err := db.QueryContext(ctx, `
SELECT ip, COALESCE(user_agent, ''), ts_start FROM requests
WHERE is_violation = 1 AND ts_start >= ?
ORDER BY ip, COALESCE(user_agent, ''), ts_start`, from)
	if err != nil {
		return fmt.Errorf("bots: timing: %w", err)
	}
	defer rows.Close()
	var cur [2]string
	var t timing
	flush := func() {
		if c := byKey[cur]; c != nil && len(t.ts) > 0 {
			c.MaxPerMinute, c.Gaps, c.GapCV = t.result()
		}
		t.ts = t.ts[:0]
	}
	for rows.Next() {
		var k [2]string
		var ts int64
		if err := rows.Scan(&k[0], &k[1], &ts); err != nil {
			return fmt.Errorf("bots: timing: %w", err)
		}
		if k != cur {
			flush()
			cur = k
		}
		t.ts = append(t.ts, ts)
	}
	flush()
	return rows.Err()
}

// uaFirstSeen returns the earliest time each user agent was ever seen,
// across raw requests and rolled-up visits.
func uaFirstSeen(ctx context.Context, db *sql.DB) (map[string]int64, error) {
	rows, err := db.QueryContext(ctx, `
SELECT ua, MIN(ts) FROM (
  SELECT COALESCE(user_agent, '') AS ua, MIN(ts_start) AS ts FROM requests GROUP BY 1
  UNION ALL
  SELECT user_agent, MIN(first_ts) FROM daily_visits GROUP BY 1
) GROUP BY ua`)
	if err != nil {
		return nil, fmt.Errorf("bots: first seen: %w", err)
	}
	defer rows.Close()
	m := map[string]int64{}
	for rows.Next() {
		var ua string
		var ts int64
		if err := rows.Scan(&ua, &ts); err != nil {
			return nil, err
		}
		m[ua] = ts
	}
	return m, rows.Err()
}

// top returns up to n keys of m by descending value.
func top[V int | int64](m map[string]V, n int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinOr(s []string, empty string) string {
	if len(s) == 0 {
		return empty
	}
	return strings.Join(s, ", ")
}
