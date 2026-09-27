package shame

import (
	"cmp"
	"slices"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// Well-behaved crawlers: clients (ip, user_agent) that fetched /robots.txt
// at least once and have no /lawn/ request anywhere in our records (raw
// requests, daily_visits.violations, daily_aggregates). A client that ever
// requested /lawn/ belongs to the wall of shame instead, and one that never
// fetched robots.txt is not listed because we can't say it followed it.
// Grouping and IP display follow the wall (SPEC.md section 8).

// Visits are the per-window request counts of well-behaved clients.
type Visits struct {
	Requests  int64 // every request, any path
	Robots    int64 // GET /robots.txt
	Bait      int64 // GET of a page carrying hidden /lawn/ links (/ or /sitemap.xml)
	FirstSeen int64 // unix ms, 0 = none
	LastSeen  int64 // unix ms, 0 = none
}

// SawBait reports whether a page carrying hidden /lawn/ links was fetched.
func (v Visits) SawBait() bool { return v.Bait > 0 }

func (v *Visits) see(first, last int64) {
	if first > 0 && (v.FirstSeen == 0 || first < v.FirstSeen) {
		v.FirstSeen = first
	}
	v.LastSeen = max(v.LastSeen, last)
}

func (v *Visits) add(o Visits) {
	v.Requests += o.Requests
	v.Robots += o.Robots
	v.Bait += o.Bait
	v.see(o.FirstSeen, o.LastSeen)
}

// UAVisits is a user agent and its all-time request count.
type UAVisits struct {
	UA       string
	Requests int64
}

// WellBehavedGroup is one row of the well-behaved page. Every member has the
// same identity status. Verified and unverifiable clients are grouped by
// claimed org; spoofed ones by (claimed org, ASN) but named after the ASN, so
// the claimed org is never credited; anonymous ones by ASN.
type WellBehavedGroup struct {
	Kind       string // identity status (verified, spoofed, unverifiable, anonymous)
	Name       string // claimed org (verified, unverifiable) or ASN label (spoofed, anonymous)
	Sub        string // spoofed: the failed claim, stated factually
	ClaimedOrg string // "" for anonymous
	ASN        uint32 // spoofed and anonymous groups
	ASNOrg     string
	ASNs       []ASNRef // every ASN seen, by number
	Clients    int      // distinct (ip, user agent) pairs
	W          [NumWindows]Visits
	CIDRs      []string   // sorted; obeys DisplayCIDR
	UAs        []UAVisits // by requests, then UA; at most 50
}

// All returns the all-time counts.
func (g *WellBehavedGroup) All() Visits { return g.W[WAll] }

// WellBehavedEntry is one element of well-behaved.json. There is one entry
// per (status, claimed org, ASN), like feed.json. Org is the claimed org for
// verified and unverifiable clients and the ASN label for spoofed and
// anonymous ones (a spoofed claim is never credited to the org it names; the
// claim is in ClaimedOrg next to status "spoofed").
type WellBehavedEntry struct {
	Org        string   `json:"org"`
	ClaimedOrg string   `json:"claimed_org"`
	Status     string   `json:"status"`
	ASN        *uint32  `json:"asn"`
	ASNOrg     string   `json:"asn_org"`
	CIDRs      []string `json:"cidrs"`
	Robots     int64    `json:"robots_fetches"`
	Requests   int64    `json:"requests"`
	SawBait    bool     `json:"saw_bait"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   string   `json:"last_seen"`
}

// WellBehavedClients is the number of (ip, user agent) pairs listed.
func (r *Report) WellBehavedClients() int {
	n := 0
	for _, g := range r.WellBehaved {
		n += g.Clients
	}
	return n
}

type politeAgg struct {
	w       [NumWindows]Visits
	clients int
	cidrs   map[string]struct{}
	uas     map[string]int64
	asns    map[uint32]string
}

func newPoliteAgg() *politeAgg {
	return &politeAgg{cidrs: map[string]struct{}{}, uas: map[string]int64{}, asns: map[uint32]string{}}
}

func (a *politeAgg) merge(o *politeAgg) {
	for i := range a.w {
		a.w[i].add(o.w[i])
	}
	a.clients += o.clients
	for k := range o.cidrs {
		a.cidrs[k] = struct{}{}
	}
	for k, v := range o.uas {
		a.uas[k] += v
	}
	for k, v := range o.asns {
		if v != "" || a.asns[k] == "" {
			a.asns[k] = v
		}
	}
}

type politeAtom struct {
	key    atomKey
	asnOrg string
	agg    *politeAgg
}

// flushPolite adds an eligible pair (robots.txt fetched, no /lawn/ ever) to
// its (status, org, ASN) atom.
func (c *collector) flushPolite(p *pair) {
	k := atomKey{status: p.status, org: p.org, asn: p.asn}
	a := c.polite[k]
	if a == nil {
		a = &politeAtom{key: k, agg: newPoliteAgg()}
		c.polite[k] = a
	}
	if len(p.asnOrg) > 0 {
		a.asnOrg = string(p.asnOrg)
	}
	a.agg.asns[k.asn] = a.asnOrg
	for w := range NumWindows {
		a.agg.w[w].add(p.vis[w])
	}
	a.agg.clients++
	if cidr := DisplayCIDR(string(p.ip), p.status); cidr != "" && publishable(cidr, p.status) {
		a.agg.cidrs[cidr] = struct{}{}
	}
	a.agg.uas[string(p.ua)] += p.vis[WAll].Requests
}

func statusRank(s string) int {
	if i := slices.Index(statusOrder, s); i >= 0 {
		return i
	}
	return len(statusOrder)
}

// byRecent orders well-behaved groups by all-time last seen (newest first),
// then all-time requests, status, name and ASN.
func byRecent(gs []*WellBehavedGroup) {
	slices.SortFunc(gs, func(x, y *WellBehavedGroup) int {
		if c := cmp.Compare(y.W[WAll].LastSeen, x.W[WAll].LastSeen); c != 0 {
			return c
		}
		if c := cmp.Compare(y.W[WAll].Requests, x.W[WAll].Requests); c != 0 {
			return c
		}
		if c := cmp.Compare(statusRank(x.Kind), statusRank(y.Kind)); c != 0 {
			return c
		}
		if c := cmp.Compare(x.Name, y.Name); c != 0 {
			return c
		}
		if c := cmp.Compare(x.ClaimedOrg, y.ClaimedOrg); c != 0 {
			return c
		}
		return cmp.Compare(x.ASN, y.ASN)
	})
}

func (g *WellBehavedGroup) finalize(a *politeAgg) {
	g.W = a.w
	g.Clients = a.clients
	g.CIDRs = make([]string, 0, len(a.cidrs))
	for k := range a.cidrs {
		g.CIDRs = append(g.CIDRs, k)
	}
	slices.SortFunc(g.CIDRs, comparePrefix)
	g.UAs = make([]UAVisits, 0, len(a.uas))
	for k, v := range a.uas {
		g.UAs = append(g.UAs, UAVisits{UA: k, Requests: v})
	}
	slices.SortFunc(g.UAs, func(x, y UAVisits) int {
		if c := cmp.Compare(y.Requests, x.Requests); c != 0 {
			return c
		}
		return cmp.Compare(x.UA, y.UA)
	})
	if len(g.UAs) > 50 {
		g.UAs = g.UAs[:50]
	}
	g.ASNs = make([]ASNRef, 0, len(a.asns))
	for k, v := range a.asns {
		g.ASNs = append(g.ASNs, ASNRef{ASN: k, Org: v, Label: ASNLabel(k, v)})
	}
	slices.SortFunc(g.ASNs, func(x, y ASNRef) int { return cmp.Compare(x.ASN, y.ASN) })
}

// spoofedClaim describes a spoofed group's claim without crediting the org.
func spoofedClaim(org string) string {
	return "User agent claimed " + org + "; failed " + org + "'s published verification"
}

// wellBehaved groups the eligible atoms into r.WellBehaved and builds
// r.WellBehavedFeed.
func (c *collector) wellBehaved(r *Report) {
	type gk struct {
		status, org string
		asn         uint32
	}
	groups := map[gk]*WellBehavedGroup{}
	aggs := map[gk]*politeAgg{}
	atoms := make([]*WellBehavedGroup, 0, len(c.polite))
	r.WellBehavedFeed = make([]WellBehavedEntry, 0, len(c.polite))
	for _, a := range c.polite {
		k := a.key
		ag := &WellBehavedGroup{Kind: k.status, Name: k.org, ClaimedOrg: k.org, ASN: k.asn, ASNOrg: a.asnOrg}
		key := gk{status: k.status, org: k.org}
		switch k.status {
		case logstore.StatusSpoofed, logstore.StatusAnonymous:
			key.asn = k.asn
			ag.Name = ASNLabel(k.asn, a.asnOrg)
			if k.status == logstore.StatusSpoofed {
				ag.Sub = spoofedClaim(k.org)
			}
		}
		ag.finalize(a.agg)
		atoms = append(atoms, ag)

		g := groups[key]
		if g == nil {
			g = &WellBehavedGroup{Kind: ag.Kind, Name: ag.Name, Sub: ag.Sub, ClaimedOrg: k.org}
			if key.asn != 0 || k.status == logstore.StatusSpoofed || k.status == logstore.StatusAnonymous {
				g.ASN, g.ASNOrg = k.asn, a.asnOrg
			}
			groups[key] = g
			aggs[key] = newPoliteAgg()
		}
		aggs[key].merge(a.agg)
	}
	r.WellBehaved = make([]*WellBehavedGroup, 0, len(groups))
	for k, g := range groups {
		g.finalize(aggs[k])
		r.WellBehaved = append(r.WellBehaved, g)
	}
	byRecent(r.WellBehaved)
	byRecent(atoms)
	for _, g := range atoms {
		m := g.W[WAll]
		e := WellBehavedEntry{
			Org:        g.Name,
			ClaimedOrg: g.ClaimedOrg,
			Status:     g.Kind,
			ASNOrg:     g.ASNOrg,
			CIDRs:      make([]string, 0, len(g.CIDRs)),
			Robots:     m.Robots,
			Requests:   m.Requests,
			SawBait:    m.SawBait(),
			FirstSeen:  rfc3339(m.FirstSeen),
			LastSeen:   rfc3339(m.LastSeen),
		}
		if g.ASN != 0 {
			asn := g.ASN
			e.ASN = &asn
		}
		for _, cidr := range g.CIDRs {
			if publishable(cidr, g.Kind) {
				e.CIDRs = append(e.CIDRs, cidr)
			}
		}
		r.WellBehavedFeed = append(r.WellBehavedFeed, e)
	}
}
