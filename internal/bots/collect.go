package bots

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/attrib"
)

// Options configures Collect.
type Options struct {
	DB       *sql.DB
	Crawlers []attrib.Crawler // to tell known bots from unknown ones
	Since    time.Duration    // window; 0 = everything kept (raw + daily_visits)
	NewFor   time.Duration    // a group first seen within this long ago is "new" (default 7d)
	All      bool             // include clients with no bot signal (likely humans)
	Now      func() time.Time
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
	SampleUA    string
	HeaderNames string
	Protos      map[string]int64
	TLS         map[string]int64
	Clients     []*Client
}

// Report is the result of Collect.
type Report struct {
	Generated time.Time
	Since     time.Duration
	Clients   int
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
	clients, err := scanClients(ctx, opt.DB, from, opt.Since == 0)
	if err != nil {
		return nil, err
	}
	firstSeen, err := uaFirstSeen(ctx, opt.DB)
	if err != nil {
		return nil, err
	}

	rep := &Report{Generated: now, Since: opt.Since, Clients: len(clients)}
	groups := map[string]*Bot{}
	for _, c := range clients {
		token, named := Token(c.UA)
		reasons := signals(c, named)
		if len(reasons) == 0 && !opt.All {
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
				PTRDomains: map[string]int64{}, Reasons: map[string]bool{}, Protos: map[string]int64{}, TLS: map[string]int64{},
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

// signals lists why a client looks automated. Browsers always send
// Accept-Language, so its absence (on rows where headers were captured) is
// a strong hint; so is fetching robots.txt at all.
func signals(c *Client, named bool) []string {
	var r []string
	if named {
		r = append(r, "ua-names-bot-or-library")
	}
	if c.Robots > 0 {
		r = append(r, "fetched-robots.txt")
	}
	if c.Violations > 0 {
		r = append(r, "entered-/lawn/")
	}
	if c.Captured > 0 && c.NoAcceptLg == c.Captured {
		r = append(r, "no-accept-language")
	}
	if c.PTR != "" && crawlerishPTR.MatchString(c.PTR) {
		r = append(r, "ptr-looks-like-crawler")
	}
	return r
}

func (b *Bot) add(c *Client, reasons []string, crawlers []attrib.Crawler) {
	b.Clients = append(b.Clients, c)
	b.Requests += c.Requests
	b.Robots += c.Robots
	b.Bait += c.Bait
	b.Violations += c.Violations
	b.MaxDepth = max(b.MaxDepth, c.MaxDepth)
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
	}
	if c.Proto != "" {
		b.Protos[c.Proto] += c.Requests
	}
	if c.TLS != "" {
		b.TLS[c.TLS] += c.Requests
	}
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
}

func asnLabel(asn int64, org string) string {
	switch {
	case asn == 0:
		return "unknown ASN"
	case org == "":
		return fmt.Sprintf("AS%d", asn)
	default:
		return fmt.Sprintf("AS%d %s", asn, org)
	}
}

// scanClients aggregates raw requests since from (unix ms) per (ip, ua),
// joined with identities and hosts. withDaily adds rolled-up visits.
func scanClients(ctx context.Context, db *sql.DB, from int64, withDaily bool) ([]*Client, error) {
	q := `
SELECT r.ip, r.ua, r.asn, r.asn_org, r.requests, r.robots, r.bait, r.violations, r.max_depth, r.first, r.last,
       r.captured, r.no_al, r.header_names, r.proto, r.tls,
       COALESCE(i.status, ''), COALESCE(i.claimed_org, ''), COALESCE(h.ptr, '')
FROM (
  SELECT ip, COALESCE(user_agent, '') AS ua, COALESCE(MAX(asn), 0) AS asn, COALESCE(MAX(asn_org), '') AS asn_org,
         COUNT(*) AS requests,
         SUM(path = '/robots.txt' OR path LIKE '/robots.txt?%') AS robots,
         SUM(path IN ('/', '/sitemap.xml')) AS bait,
         SUM(is_violation) AS violations,
         COALESCE(MAX(depth), 0) AS max_depth,
         MIN(ts_start) AS first, MAX(ts_start) AS last,
         SUM(header_names IS NOT NULL) AS captured,
         SUM(header_names IS NOT NULL AND accept_language IS NULL) AS no_al,
         COALESCE(MAX(header_names), '') AS header_names,
         COALESCE(MAX(proto), '') AS proto, COALESCE(MAX(tls), '') AS tls
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
		if err := rows.Scan(&c.IP, &c.UA, &c.ASN, &c.ASNOrg, &c.Requests, &c.Robots, &c.Bait, &c.Violations, &c.MaxDepth,
			&c.First, &c.Last, &c.Captured, &c.NoAcceptLg, &c.HeaderNames, &c.Proto, &c.TLS,
			&c.Status, &c.ClaimedOrg, &c.PTR); err != nil {
			rows.Close()
			return nil, fmt.Errorf("bots: scan: %w", err)
		}
		byKey[[2]string{c.IP, c.UA}] = c
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("bots: scan: %w", err)
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
