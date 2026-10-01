package shame

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

type wbRow struct {
	G         *WellBehavedGroup
	Network   string // verified/unverifiable: first ASN seen
	NetMore   int
	UAs       []UAVisits
	UAMore    int
	UALen     int
	CIDRs     []string
	CIDRMore  int
	Traits    []TraitCount // strongest first, capped
	TraitMore int
}

type wbSection struct {
	ID, Title, Lede string
	Rows            []wbRow
	Total           int
}

type wbView struct {
	Generated string
	Groups    int
	Clients   int
	Robots    int64
	Requests  int64
	Sections  []wbSection
	RobotsTxt string
}

// wbCaps are the row / per-row limits tried in turn until the page fits.
type wbCaps struct{ rows, uas, uaLen, cidrs, traits int }

var wbCapLevels = []wbCaps{
	{50, 3, 120, 6, 3},
	{40, 2, 100, 4, 3},
	{30, 2, 80, 3, 2},
	{20, 1, 80, 2, 2},
	{15, 1, 60, 2, 1},
	{10, 1, 60, 1, 1},
	{5, 1, 60, 1, 1},
	{3, 1, 40, 1, 1},
	{1, 1, 40, 1, 1},
}

// wbSections are the page sections, one per identity status, in the same
// order as the wall: confirmed first, never mixed with unconfirmed rows.
var wbSections = []struct{ status, id, title, lede string }{
	{logstore.StatusVerified, "verified", "Verified crawlers",
		"User agent matched a known crawler and the source address passed that vendor's published verification (reverse DNS or published IP ranges). Only these rows show individual IPs."},
	{logstore.StatusUnverifiable, "unverifiable", "Claimed, unverifiable",
		"User agent names a known crawler whose vendor publishes no verification method we could find. The claim is not confirmed."},
	{logstore.StatusSpoofed, "spoofed", "Spoofed crawler user agents",
		"User agent claimed a known crawler, but the source address failed that crawler's published verification. Listed under the network the requests came from; nothing here is attributed to the crawler named."},
	{logstore.StatusAnonymous, "anonymous", "Other clients, by network",
		"No known crawler user agent. Attributed only to the network (ASN) the requests came from."},
}

func wbRowFor(g *WellBehavedGroup, c wbCaps) wbRow {
	row := wbRow{G: g, UALen: c.uaLen}
	if g.Kind == logstore.StatusVerified || g.Kind == logstore.StatusUnverifiable {
		if len(g.ASNs) > 0 {
			row.Network = g.ASNs[0].Label
			row.NetMore = len(g.ASNs) - 1
		}
	}
	row.UAs = g.UAs[:min(c.uas, len(g.UAs))]
	row.UAMore = len(g.UAs) - len(row.UAs)
	row.CIDRs = g.CIDRs[:min(c.cidrs, len(g.CIDRs))]
	row.CIDRMore = len(g.CIDRs) - len(row.CIDRs)
	row.Traits = g.Traits[:min(c.traits, len(g.Traits))]
	row.TraitMore = len(g.Traits) - len(row.Traits)
	return row
}

func renderWellBehaved(t *template.Template, r *Report, robots string) ([]byte, error) {
	byStatus := map[string][]*WellBehavedGroup{}
	for _, g := range r.WellBehaved {
		k := statusClass(g.Kind)
		byStatus[k] = append(byStatus[k], g)
	}
	v := wbView{Generated: genTime(r.Generated), Groups: len(r.WellBehaved), RobotsTxt: robots}
	for _, g := range r.WellBehaved {
		v.Clients += g.Clients
		v.Robots += g.W[WAll].Robots
		v.Requests += g.W[WAll].Requests
	}
	var buf bytes.Buffer
	for _, c := range wbCapLevels {
		v.Sections = v.Sections[:0]
		for _, s := range wbSections {
			gs := byStatus[s.status]
			sec := wbSection{ID: s.id, Title: s.title, Lede: s.lede, Total: len(gs)}
			for _, g := range gs[:min(c.rows, len(gs))] {
				sec.Rows = append(sec.Rows, wbRowFor(g, c))
			}
			v.Sections = append(v.Sections, sec)
		}
		buf.Reset()
		if err := t.ExecuteTemplate(&buf, "shame-well-behaved", v); err != nil {
			return nil, fmt.Errorf("shame: render well-behaved: %w", err)
		}
		if buf.Len() < MaxPageBytes {
			break
		}
	}
	return buf.Bytes(), nil
}
