// Package shame aggregates the request log into the Wall of Shame: the static
// leaderboard, per-org pages, feed.json and blocklist.txt (SPEC.md section 8).
package shame

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// Options configures a Collect or Build run.
type Options struct {
	DB           *sql.DB
	Templates    fs.FS  // web.Templates(""): root holds partials.html and shame/*.html
	PublicDir    string // output goes to PublicDir/shame/ (atomic swap)
	RobotsTxt    string // exact robots.txt in effect, shown in every footer
	BaseURL      string // e.g. https://getoffmyfuckinglawn.com; used in blocklist.txt
	SessionGap   time.Duration
	BlocklistMin int // shame.blocklist_min_violations
	Now          func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o Options) gap() time.Duration {
	if o.SessionGap <= 0 {
		return 10 * time.Minute
	}
	return o.SessionGap
}

// Trailing windows, in display order.
const (
	W24h = iota
	W7d
	W30d
	WAll
	NumWindows
)

// WindowNames are the labels of the trailing windows, indexed by W*.
var WindowNames = [NumWindows]string{"24h", "7d", "30d", "all"}

var windowDur = [NumWindows]time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour, 0}

// WindowIndex maps "24h", "7d", "30d" or "all" to its W* index.
func WindowIndex(name string) (int, bool) {
	for i, n := range WindowNames {
		if n == name {
			return i, true
		}
	}
	return 0, false
}

// Metrics are the section 8 per-row numbers for one window.
type Metrics struct {
	HeldMs    int64 // sum of ts_end - ts_start over violations
	Pages     int64 // violation requests
	Bytes     int64 // bytes sent on violations
	MaxDepth  int
	Sessions  int64 // sessions with >= 1 violation
	ReadRules int64 // of those, sessions flagged read_the_rules
	FirstSeen int64 // unix ms of first violation, 0 = none
	LastSeen  int64 // unix ms of last violation end, 0 = none
}

// Hours is HeldMs in hours.
func (m Metrics) Hours() float64 { return float64(m.HeldMs) / 3.6e6 }

func (m *Metrics) add(o Metrics) {
	m.HeldMs += o.HeldMs
	m.Pages += o.Pages
	m.Bytes += o.Bytes
	m.Sessions += o.Sessions
	m.ReadRules += o.ReadRules
	m.MaxDepth = max(m.MaxDepth, o.MaxDepth)
	if o.FirstSeen > 0 && (m.FirstSeen == 0 || o.FirstSeen < m.FirstSeen) {
		m.FirstSeen = o.FirstSeen
	}
	m.LastSeen = max(m.LastSeen, o.LastSeen)
}

// Day is one row of a per-org daily time series (UTC days).
type Day struct {
	Date     string // YYYY-MM-DD
	Pages    int64
	HeldMs   int64
	Bytes    int64
	Sessions int64
}

// UACount is a user agent and its violation count.
type UACount struct {
	UA    string
	Pages int64
}

// ASNRef is an autonomous system seen in a group.
type ASNRef struct {
	ASN   uint32
	Org   string
	Label string
}

// Group kinds. The first four are identity statuses; KindASN is the
// all-statuses aggregate used by the Top ASNs section.
const (
	KindASN = "asn"
)

// Group is one leaderboard entity: a verified org, a (claimed org, ASN) liar
// pair, an unverifiable claimed org, an anonymous ASN, an ASN aggregate, or a
// feed atom (status, org, ASN).
type Group struct {
	Kind       string   // identity status, or KindASN
	Slug       string   // org page is shame/org/<Slug>/; for anonymous groups it is their ASN page
	OwnPage    bool     // Slug names this group's own page
	Name       string   // claimed org, or ASN label for anonymous/ASN groups
	Sub        string   // secondary label (network for liars)
	Statuses   []string // identity statuses present, in canonical order
	ClaimedOrg string   // "" for anonymous/ASN groups
	ASN        uint32   // for spoofed/anonymous/ASN groups and feed atoms
	ASNOrg     string
	ASNs       []ASNRef // every ASN seen
	W          [NumWindows]Metrics
	CIDRs      []string // sorted; obeys DisplayCIDR per member status
	TopUAs     []UACount
	Paths      []string // recent sample /lawn/ paths, newest first
	Daily      []Day    // ascending by date
	Members    []*Group // KindASN only: per-(status, org) atoms in this ASN

	agg *agg
}

// All returns the all-time metrics.
func (g *Group) All() Metrics { return g.W[WAll] }

// FeedEntry is one element of feed.json. There is one entry per
// (status, claimed org, ASN); anonymous entries use the ASN org as org.
type FeedEntry struct {
	Org       string   `json:"org"`
	Status    string   `json:"status"`
	ASN       *uint32  `json:"asn"`
	ASNOrg    string   `json:"asn_org"`
	CIDRs     []string `json:"cidrs"`
	HoursHeld float64  `json:"hours_held"`
	Pages     int64    `json:"pages"`
	MaxDepth  int      `json:"max_depth"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
}

// Report is everything the builder renders, and what `lawn stats` prints.
type Report struct {
	Generated    time.Time
	Totals       [NumWindows]Metrics // global counters; Totals[WAll].MaxDepth is the deepest crawl ever
	Verified     []*Group            // section 1
	Liars        []*Group            // section 2 (spoofed, by claimed org + ASN)
	Unverifiable []*Group            // claimed, unverifiable (by claimed org)
	ASNs         []*Group            // section 3 (every violator, by ASN)
	ReadRules    []*Group            // section 4 (offenders with >= 1 read_the_rules session)
	Groups       []*Group            // every offender group (verified, liars, unverifiable, anonymous-by-ASN)
	Pages        []*Group            // groups that get a shame/org/<slug>/ page
	Feed         []FeedEntry
	Blocklist    []string
	BlocklistMin int
	Warnings     []string

	// WellBehaved lists clients that fetched robots.txt and never requested
	// anything under /lawn/, grouped like the wall (see wellbehaved.go),
	// most recently seen first. WellBehavedFeed is well-behaved.json.
	WellBehaved     []*WellBehavedGroup
	WellBehavedFeed []WellBehavedEntry
}

// ---- aggregation internals ----

const maxPaths = 5

type pathSample struct {
	ts   int64
	path string
}

type dayAgg struct{ pages, heldMs, bytes, sessions int64 }

type agg struct {
	w      [NumWindows]Metrics
	cidrs  map[string]struct{}
	uas    map[string]int64
	paths  []pathSample
	daily  map[int64]*dayAgg // days since epoch
	asns   map[uint32]string
	status map[string]struct{}
}

func newAgg() *agg {
	return &agg{
		cidrs:  map[string]struct{}{},
		uas:    map[string]int64{},
		daily:  map[int64]*dayAgg{},
		asns:   map[uint32]string{},
		status: map[string]struct{}{},
	}
}

func (a *agg) day(d int64) *dayAgg {
	x := a.daily[d]
	if x == nil {
		x = &dayAgg{}
		a.daily[d] = x
	}
	return x
}

func (a *agg) addPaths(ps []pathSample) {
	a.paths = append(a.paths, ps...)
	slices.SortFunc(a.paths, func(x, y pathSample) int {
		if c := cmp.Compare(y.ts, x.ts); c != 0 {
			return c
		}
		return cmp.Compare(x.path, y.path)
	})
	a.paths = slices.CompactFunc(a.paths, func(x, y pathSample) bool { return x.path == y.path })
	if len(a.paths) > maxPaths {
		a.paths = a.paths[:maxPaths]
	}
}

func (a *agg) merge(o *agg) {
	for i := range a.w {
		a.w[i].add(o.w[i])
	}
	for k := range o.cidrs {
		a.cidrs[k] = struct{}{}
	}
	for k, v := range o.uas {
		a.uas[k] += v
	}
	for k, v := range o.daily {
		d := a.day(k)
		d.pages += v.pages
		d.heldMs += v.heldMs
		d.bytes += v.bytes
		d.sessions += v.sessions
	}
	for k, v := range o.asns {
		if v != "" || a.asns[k] == "" {
			a.asns[k] = v
		}
	}
	for k := range o.status {
		a.status[k] = struct{}{}
	}
	a.addPaths(o.paths)
}

type atomKey struct {
	status string
	org    string
	asn    uint32
}

type atom struct {
	key    atomKey
	asnOrg string
	agg    *agg
}

type collector struct {
	gapMs  int64
	cut    [NumWindows]int64
	atoms  map[atomKey]*atom
	polite map[atomKey]*politeAtom
}

func (c *collector) atom(k atomKey, asnOrg string) *atom {
	a := c.atoms[k]
	if a == nil {
		a = &atom{key: k, agg: newAgg()}
		a.agg.status[k.status] = struct{}{}
		c.atoms[k] = a
	}
	if asnOrg != "" {
		a.asnOrg = asnOrg
	}
	a.agg.asns[k.asn] = a.asnOrg
	return a
}

// normalize maps a raw identities row to a display status and org. Missing,
// unknown, or org-less classifications become anonymous: never confirmed.
func normalize(status, org string) (string, string) {
	switch status {
	case logstore.StatusVerified, logstore.StatusSpoofed, logstore.StatusUnverifiable:
		if org != "" {
			return status, org
		}
	}
	return logstore.StatusAnonymous, ""
}

const msPerDay = 86_400_000

// pair holds the streamed rows of one (ip, user_agent).
type pair struct {
	ip, ua      []byte
	status, org string
	asn         uint32
	asnOrg      []byte
	events      []logstore.Event
	viol        bool // a raw /lawn/ request
	rolledViol  bool // a /lawn/ request in daily_visits or daily_aggregates
	vis         [NumWindows]Visits
	ring        [maxPaths][]byte
	ringTs      [maxPaths]int64
	ringN       int
}

func (p *pair) reset(ip, ua, status, org []byte) {
	p.ip = append(p.ip[:0], ip...)
	p.ua = append(p.ua[:0], ua...)
	p.status, p.org = normalize(string(status), string(org))
	p.asn = 0
	p.asnOrg = p.asnOrg[:0]
	p.events = p.events[:0]
	p.viol = false
	p.rolledViol = false
	p.vis = [NumWindows]Visits{}
	p.ringN = 0
}

func (p *pair) pushPath(ts int64, path []byte) {
	i := p.ringN % maxPaths
	p.ring[i] = append(p.ring[i][:0], path...)
	p.ringTs[i] = ts
	p.ringN++
}

// Row sources in rawQuery.
const (
	srcRequest    = 0 // one raw request
	srcDailyVisit = 1 // a daily_visits rollup (every visitor, older than retention)
	srcDailyAgg   = 2 // a daily_aggregates rollup with violations
)

// Raw-row kind bits computed in SQL, so non-violation paths never leave
// SQLite: a /robots.txt path (any method, for session read_rules), a GET of
// it (a counted robots.txt fetch), and a GET of a page carrying hidden
// /lawn/ links (the bait: / and /sitemap.xml, with or without a query).
const (
	kindRobotsPath = 1
	kindRobotsGet  = 2
	kindBaitGet    = 4
)

// rawQuery streams every request plus the rolled-up visit and violation
// history, one (ip, user_agent) at a time: raw rows first in time order,
// then rollups. Paths are only returned for violations (sample paths). As a
// flat compound, SQLite merges the branches and walks requests through
// idx_req_ip_ts, sorting only within each IP rather than the whole table.
const rawQuery = `SELECT r.ip, COALESCE(r.user_agent, ''), 0, r.ts_start, COALESCE(r.ts_end, 0), r.is_violation,
    COALESCE(r.depth, 0), COALESCE(r.bytes_sent, 0), COALESCE(r.asn, 0), COALESCE(r.asn_org, ''),
    CASE WHEN r.is_violation = 1 THEN r.path ELSE '' END,
    CASE
      WHEN r.is_violation = 1 THEN 0
      WHEN r.path = '/robots.txt' OR substr(r.path, 1, 12) = '/robots.txt?' THEN 1 + 2 * (r.method = 'GET')
      WHEN r.method = 'GET' AND (r.path IN ('/', '/sitemap.xml') OR substr(r.path, 1, 2) = '/?'
        OR substr(r.path, 1, 13) = '/sitemap.xml?') THEN 4
      ELSE 0 END,
    1, 0, 0, COALESCE(i.status, ''), COALESCE(i.claimed_org, ''), r.id
  FROM requests r LEFT JOIN identities i ON i.ip = r.ip AND i.user_agent = COALESCE(r.user_agent, '')
UNION ALL
SELECT d.ip, d.user_agent, 1, d.first_ts, d.last_ts, d.violations, 0, 0, COALESCE(d.asn, 0), COALESCE(d.asn_org, ''),
    '', 0, d.requests, d.robots, d.bait_views, COALESCE(i.status, ''), COALESCE(i.claimed_org, ''), 0
  FROM daily_visits d LEFT JOIN identities i ON i.ip = d.ip AND i.user_agent = d.user_agent
UNION ALL
SELECT a.ip, a.user_agent, 2, a.first_ts, a.last_ts, a.pages, 0, 0, 0, '', '', 0, 0, 0, 0,
    COALESCE(i.status, ''), COALESCE(i.claimed_org, ''), 0
  FROM daily_aggregates a LEFT JOIN identities i ON i.ip = a.ip AND i.user_agent = a.user_agent WHERE a.pages > 0
ORDER BY 1, 2, 3, 4, 18`

// visit counts one raw request into the trailing windows it falls in.
func (p *pair) visit(cut *[NumWindows]int64, ts, tsEnd int64, kind int64) {
	last := max(ts, tsEnd)
	for w := range NumWindows {
		if w != WAll && ts < cut[w] {
			continue
		}
		v := &p.vis[w]
		v.Requests++
		if kind&kindRobotsGet != 0 {
			v.Robots++
		}
		if kind&kindBaitGet != 0 {
			v.Bait++
		}
		v.see(ts, last)
	}
}

func (c *collector) scanRaw(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, rawQuery)
	if err != nil {
		return fmt.Errorf("shame: query requests: %w", err)
	}
	defer rows.Close()
	var (
		ip, ua, asnOrg, path, status, org sql.RawBytes
		src, ts, tsEnd, viol, depth       int64
		nbytes, asn, kind                 int64
		reqs, robots, bait, rowID         int64
		p                                 pair
		started                           bool
	)
	for rows.Next() {
		if err := rows.Scan(&ip, &ua, &src, &ts, &tsEnd, &viol, &depth, &nbytes, &asn, &asnOrg,
			&path, &kind, &reqs, &robots, &bait, &status, &org, &rowID); err != nil {
			return fmt.Errorf("shame: scan requests: %w", err)
		}
		if !started || !bytes.Equal(ip, p.ip) || !bytes.Equal(ua, p.ua) {
			if started {
				c.flushPair(&p)
			}
			p.reset(ip, ua, status, org)
			started = true
		}
		validASN := asn > 0 && asn <= 1<<32-1
		switch src {
		case srcRequest:
			if validASN {
				p.asn = uint32(asn)
				p.asnOrg = append(p.asnOrg[:0], asnOrg...)
			}
			p.visit(&c.cut, ts, tsEnd, kind)
			v := viol == 1
			if v {
				p.viol = true
				if samplePathOK(path) {
					p.pushPath(ts, path)
				}
			} else if kind&kindRobotsPath == 0 {
				continue // neither a violation nor robots.txt: no session event
			}
			p.events = append(p.events, logstore.Event{
				TsStart: ts, TsEnd: tsEnd, IsViolation: v, IsRobots: !v,
				Depth: int(depth), Bytes: nbytes,
			})
		case srcDailyVisit:
			// Rollups sort after raw rows: raw (newer) ASN data wins.
			if validASN && p.asn == 0 {
				p.asn = uint32(asn)
				p.asnOrg = append(p.asnOrg[:0], asnOrg...)
			}
			if viol > 0 {
				p.rolledViol = true
			}
			v := &p.vis[WAll]
			v.Requests += max(reqs, 0)
			v.Robots += max(robots, 0)
			v.Bait += max(bait, 0)
			v.see(ts, max(ts, tsEnd))
		default: // srcDailyAgg
			p.rolledViol = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("shame: read requests: %w", err)
	}
	if started {
		c.flushPair(&p)
	}
	return nil
}

// sessionMetrics sums sessions (which already only count violations).
func sessionMetrics(ss []logstore.Session) Metrics {
	var m Metrics
	for i := range ss {
		s := &ss[i]
		if s.Pages == 0 {
			continue
		}
		m.Sessions++
		if s.ReadRules {
			m.ReadRules++
		}
		m.Pages += int64(s.Pages)
		m.HeldMs += s.HeldMs
		m.Bytes += s.Bytes
		m.MaxDepth = max(m.MaxDepth, s.MaxDepth)
	}
	return m
}

func (c *collector) flushPair(p *pair) {
	if !p.viol {
		if !p.rolledViol && p.vis[WAll].Robots > 0 {
			c.flushPolite(p)
		}
		return
	}
	a := c.atom(atomKey{status: p.status, org: p.org, asn: p.asn}, string(p.asnOrg))
	ev := p.events
	all := logstore.DeriveSessions(ev, c.gapMs)
	var lastSeen int64
	for i := range ev {
		if ev[i].IsViolation {
			lastSeen = max(lastSeen, ev[i].TsStart, ev[i].TsEnd)
		}
	}
	for w := range NumWindows {
		start := 0
		ss := all
		if w != WAll {
			cut := c.cut[w]
			start = sort.Search(len(ev), func(i int) bool { return ev[i].TsStart >= cut })
			if start > 0 {
				ss = logstore.DeriveSessions(ev[start:], c.gapMs)
			}
		}
		m := sessionMetrics(ss)
		if m.Pages == 0 {
			continue
		}
		for i := start; i < len(ev); i++ {
			if ev[i].IsViolation {
				m.FirstSeen = ev[i].TsStart
				break
			}
		}
		m.LastSeen = lastSeen
		a.agg.w[w].add(m)
	}
	// Daily series: pages/held/bytes by request day, sessions by the day of
	// their first violation (matches daily_aggregates semantics).
	for i := range ev {
		if e := &ev[i]; e.IsViolation {
			d := a.agg.day(e.TsStart / msPerDay)
			d.pages++
			d.heldMs += logstore.HeldMs(e.TsStart, e.TsEnd)
			d.bytes += e.Bytes
		}
	}
	for i := range all {
		if all[i].Pages > 0 {
			a.agg.day(all[i].FirstLawn/msPerDay).sessions++
		}
	}
	if cidr := DisplayCIDR(string(p.ip), p.status); cidr != "" {
		a.agg.cidrs[cidr] = struct{}{}
	}
	a.agg.uas[string(p.ua)] += int64(countViolations(ev))
	n := min(p.ringN, maxPaths)
	ps := make([]pathSample, 0, n)
	for i := range n {
		ps = append(ps, pathSample{ts: p.ringTs[i], path: string(p.ring[i])})
	}
	a.agg.addPaths(ps)
}

func countViolations(ev []logstore.Event) int {
	n := 0
	for i := range ev {
		if ev[i].IsViolation {
			n++
		}
	}
	return n
}

const dailyQuery = `SELECT d.day, d.ip, d.user_agent, COALESCE(d.asn, 0), COALESCE(d.asn_org, ''),
  d.pages, d.held_ms, d.bytes_sent, COALESCE(d.max_depth, 0), d.sessions, d.read_rules,
  d.first_ts, d.last_ts, COALESCE(i.status, ''), COALESCE(i.claimed_org, '')
FROM daily_aggregates d
LEFT JOIN identities i ON i.ip = d.ip AND i.user_agent = d.user_agent`

// scanDaily folds rolled-up rows (older than retention) into all-time only.
func (c *collector) scanDaily(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, dailyQuery)
	if err != nil {
		return fmt.Errorf("shame: query daily_aggregates: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			day, ip, ua, asnOrg, status, org             string
			asn, pages, held, nbytes, sessions, readRule int64
			depth                                        int
			first, last                                  int64
		)
		if err := rows.Scan(&day, &ip, &ua, &asn, &asnOrg, &pages, &held, &nbytes, &depth,
			&sessions, &readRule, &first, &last, &status, &org); err != nil {
			return fmt.Errorf("shame: scan daily_aggregates: %w", err)
		}
		if pages <= 0 {
			continue
		}
		status, org = normalize(status, org)
		var a32 uint32
		if asn > 0 && asn <= 1<<32-1 {
			a32 = uint32(asn)
		}
		a := c.atom(atomKey{status: status, org: org, asn: a32}, asnOrg)
		a.agg.w[WAll].add(Metrics{HeldMs: held, Pages: pages, Bytes: nbytes, MaxDepth: depth,
			Sessions: sessions, ReadRules: readRule, FirstSeen: first, LastSeen: last})
		di := first / msPerDay
		if t, err := time.Parse("2006-01-02", day); err == nil {
			di = t.Unix() / 86400
		}
		d := a.agg.day(di)
		d.pages += pages
		d.heldMs += held
		d.bytes += nbytes
		d.sessions += sessions
		if cidr := DisplayCIDR(ip, status); cidr != "" {
			a.agg.cidrs[cidr] = struct{}{}
		}
		a.agg.uas[ua] += pages
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("shame: read daily_aggregates: %w", err)
	}
	return nil
}

// Collect runs the aggregation queries and returns the report. It streams
// raw rows ordered by (ip, user_agent, ts_start) and derives sessions one
// pair at a time, so memory scales with the number of groups, not rows.
// The same pass merges each pair's rolled-up history (daily_visits,
// daily_aggregates) to decide whether it is well-behaved.
func Collect(ctx context.Context, opt Options) (*Report, error) {
	if opt.DB == nil {
		return nil, errors.New("shame: nil DB")
	}
	now := opt.now().UTC()
	c := &collector{gapMs: opt.gap().Milliseconds(), atoms: map[atomKey]*atom{}, polite: map[atomKey]*politeAtom{}}
	for w, d := range windowDur {
		if d > 0 {
			c.cut[w] = now.Add(-d).UnixMilli()
		}
	}
	if err := c.scanRaw(ctx, opt.DB); err != nil {
		return nil, err
	}
	if err := c.scanDaily(ctx, opt.DB); err != nil {
		return nil, err
	}
	return c.report(now, opt.BlocklistMin), nil
}

// ---- report assembly ----

var statusOrder = []string{logstore.StatusVerified, logstore.StatusSpoofed, logstore.StatusUnverifiable, logstore.StatusAnonymous}

func (g *Group) finalize() {
	a := g.agg
	g.W = a.w
	g.Statuses = g.Statuses[:0]
	for _, s := range statusOrder {
		if _, ok := a.status[s]; ok {
			g.Statuses = append(g.Statuses, s)
		}
	}
	g.CIDRs = make([]string, 0, len(a.cidrs))
	for k := range a.cidrs {
		g.CIDRs = append(g.CIDRs, k)
	}
	slices.SortFunc(g.CIDRs, comparePrefix)
	g.TopUAs = make([]UACount, 0, len(a.uas))
	for k, v := range a.uas {
		g.TopUAs = append(g.TopUAs, UACount{UA: k, Pages: v})
	}
	slices.SortFunc(g.TopUAs, func(x, y UACount) int {
		if c := cmp.Compare(y.Pages, x.Pages); c != 0 {
			return c
		}
		return cmp.Compare(x.UA, y.UA)
	})
	if len(g.TopUAs) > 50 {
		g.TopUAs = g.TopUAs[:50]
	}
	g.Paths = g.Paths[:0]
	for _, p := range a.paths {
		g.Paths = append(g.Paths, p.path)
	}
	days := make([]int64, 0, len(a.daily))
	for k := range a.daily {
		days = append(days, k)
	}
	slices.Sort(days)
	g.Daily = make([]Day, 0, len(days))
	for _, k := range days {
		d := a.daily[k]
		g.Daily = append(g.Daily, Day{Date: time.Unix(k*86400, 0).UTC().Format("2006-01-02"),
			Pages: d.pages, HeldMs: d.heldMs, Bytes: d.bytes, Sessions: d.sessions})
	}
	g.ASNs = g.ASNs[:0]
	for k, v := range a.asns {
		g.ASNs = append(g.ASNs, ASNRef{ASN: k, Org: v, Label: ASNLabel(k, v)})
	}
	slices.SortFunc(g.ASNs, func(x, y ASNRef) int { return cmp.Compare(x.ASN, y.ASN) })
}

// byHeld sorts by all-time time held, then pages, then name.
func byHeld(gs []*Group) {
	slices.SortFunc(gs, func(x, y *Group) int {
		if c := cmp.Compare(y.W[WAll].HeldMs, x.W[WAll].HeldMs); c != 0 {
			return c
		}
		if c := cmp.Compare(y.W[WAll].Pages, x.W[WAll].Pages); c != 0 {
			return c
		}
		if c := cmp.Compare(x.Name, y.Name); c != 0 {
			return c
		}
		if c := cmp.Compare(x.Kind, y.Kind); c != 0 {
			return c
		}
		return cmp.Compare(x.ASN, y.ASN)
	})
}

type groupKey struct {
	kind string
	org  string
	asn  uint32
}

func (c *collector) report(now time.Time, blocklistMin int) *Report {
	r := &Report{Generated: now, BlocklistMin: blocklistMin}

	keys := make([]atomKey, 0, len(c.atoms))
	for k := range c.atoms {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y atomKey) int {
		if c := cmp.Compare(x.status, y.status); c != 0 {
			return c
		}
		if c := cmp.Compare(x.org, y.org); c != 0 {
			return c
		}
		return cmp.Compare(x.asn, y.asn)
	})

	primary := map[groupKey]*Group{}
	asnGroups := map[uint32]*Group{}
	var primaryOrder []groupKey
	var asnOrder []uint32
	atomGroups := make([]*Group, 0, len(keys))
	for _, k := range keys {
		a := c.atoms[k]
		ag := &Group{Kind: k.status, Name: k.org, ClaimedOrg: k.org, ASN: k.asn, ASNOrg: a.asnOrg, agg: a.agg}
		if k.status == logstore.StatusAnonymous {
			ag.Name = ASNLabel(k.asn, a.asnOrg)
		}
		atomGroups = append(atomGroups, ag)

		pk := groupKey{kind: k.status, org: k.org}
		if k.status == logstore.StatusSpoofed || k.status == logstore.StatusAnonymous {
			pk.asn = k.asn
		}
		pg := primary[pk]
		if pg == nil {
			pg = &Group{Kind: k.status, Name: k.org, ClaimedOrg: k.org, agg: newAgg()}
			if pk.asn != 0 || k.status == logstore.StatusSpoofed || k.status == logstore.StatusAnonymous {
				pg.ASN, pg.ASNOrg = k.asn, a.asnOrg
			}
			switch k.status {
			case logstore.StatusSpoofed:
				pg.Sub = "from " + ASNLabel(k.asn, a.asnOrg)
			case logstore.StatusAnonymous:
				pg.Name = ASNLabel(k.asn, a.asnOrg)
			}
			primary[pk] = pg
			primaryOrder = append(primaryOrder, pk)
		}
		pg.agg.merge(a.agg)

		xg := asnGroups[k.asn]
		if xg == nil {
			xg = &Group{Kind: KindASN, Name: ASNLabel(k.asn, a.asnOrg), ASN: k.asn, ASNOrg: a.asnOrg, agg: newAgg()}
			asnGroups[k.asn] = xg
			asnOrder = append(asnOrder, k.asn)
		}
		xg.agg.merge(a.agg)
		xg.Members = append(xg.Members, ag)
	}

	for _, g := range atomGroups {
		g.finalize()
	}
	used := map[string]bool{}
	claim := func(s string) string {
		out := s
		for i := 2; used[out]; i++ {
			out = fmt.Sprintf("%s-%d", s, i)
		}
		used[out] = true
		return out
	}
	// Slugs are assigned in a fixed order so they are stable across builds.
	slices.Sort(asnOrder)
	for _, asn := range asnOrder {
		g := asnGroups[asn]
		g.finalize()
		g.Slug, g.OwnPage = claim(asnSlug(asn, g.ASNOrg)), true
		byHeld(g.Members)
		r.ASNs = append(r.ASNs, g)
		r.Pages = append(r.Pages, g)
	}
	for _, pk := range primaryOrder {
		g := primary[pk]
		g.finalize()
		switch g.Kind {
		case logstore.StatusVerified:
			g.Slug, g.OwnPage = claim(Slugify(g.Name)), true
			r.Verified = append(r.Verified, g)
		case logstore.StatusSpoofed:
			g.Slug, g.OwnPage = claim("spoofed-"+Slugify(g.Name)+"-"+asnSlug(g.ASN, g.ASNOrg)), true
			r.Liars = append(r.Liars, g)
		case logstore.StatusUnverifiable:
			g.Slug, g.OwnPage = claim(Slugify(g.Name)+"-unverifiable"), true
			r.Unverifiable = append(r.Unverifiable, g)
		default:
			g.Slug = asnGroups[g.ASN].Slug
		}
		if g.OwnPage {
			r.Pages = append(r.Pages, g)
		}
		r.Groups = append(r.Groups, g)
		if g.W[WAll].ReadRules > 0 {
			r.ReadRules = append(r.ReadRules, g)
		}
	}
	// Atoms link to their primary group's page.
	for _, ag := range atomGroups {
		pk := groupKey{kind: ag.Kind, org: ag.ClaimedOrg}
		if ag.Kind == logstore.StatusSpoofed || ag.Kind == logstore.StatusAnonymous {
			pk.asn = ag.ASN
		}
		ag.Slug = primary[pk].Slug
	}
	for _, gs := range [][]*Group{r.Verified, r.Liars, r.Unverifiable, r.ASNs, r.Groups, r.Pages} {
		byHeld(gs)
	}
	byReadRules(r.ReadRules)

	for _, g := range atomGroups {
		for w := range NumWindows {
			r.Totals[w].add(g.W[w])
		}
	}
	r.Feed = buildFeed(atomGroups)
	r.Blocklist = buildBlocklist(atomGroups, blocklistMin)
	c.wellBehaved(r)
	return r
}

// byReadRules orders the read-the-rules section by flagged sessions, then
// by time held.
func byReadRules(gs []*Group) {
	slices.SortFunc(gs, func(x, y *Group) int {
		if c := cmp.Compare(y.W[WAll].ReadRules, x.W[WAll].ReadRules); c != 0 {
			return c
		}
		if c := cmp.Compare(y.W[WAll].HeldMs, x.W[WAll].HeldMs); c != 0 {
			return c
		}
		if c := cmp.Compare(x.Name, y.Name); c != 0 {
			return c
		}
		return cmp.Compare(x.ASN, y.ASN)
	})
}

func buildFeed(atoms []*Group) []FeedEntry {
	gs := slices.Clone(atoms)
	byHeld(gs)
	out := make([]FeedEntry, 0, len(gs))
	for _, g := range gs {
		m := g.W[WAll]
		e := FeedEntry{
			Org:       g.ClaimedOrg,
			Status:    g.Kind,
			ASNOrg:    g.ASNOrg,
			CIDRs:     make([]string, 0, len(g.CIDRs)),
			HoursHeld: float64(m.HeldMs/36) / 1e5, // hours, 5 decimals
			Pages:     m.Pages,
			MaxDepth:  m.MaxDepth,
			FirstSeen: rfc3339(m.FirstSeen),
			LastSeen:  rfc3339(m.LastSeen),
		}
		if g.ASN != 0 {
			asn := g.ASN
			e.ASN = &asn
		}
		if g.Kind == logstore.StatusAnonymous {
			e.Org = ASNLabel(g.ASN, g.ASNOrg)
		}
		for _, cidr := range g.CIDRs {
			if publishable(cidr, g.Kind) {
				e.CIDRs = append(e.CIDRs, cidr)
			}
		}
		out = append(out, e)
	}
	return out
}

// buildBlocklist: individual IPs of verified offenders, plus the /24 or /48
// networks of spoofed (claimed org, ASN) groups with >= min violations.
func buildBlocklist(atoms []*Group, minViolations int) []string {
	set := map[string]struct{}{}
	for _, g := range atoms {
		switch g.Kind {
		case logstore.StatusVerified:
		case logstore.StatusSpoofed:
			if g.W[WAll].Pages < int64(max(minViolations, 1)) {
				continue
			}
		default:
			continue
		}
		for _, cidr := range g.CIDRs {
			if publishable(cidr, g.Kind) {
				set[cidr] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.SortFunc(out, comparePrefix)
	return out
}
