package shame

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// WriteStats prints the top offender groups for one trailing window
// ("24h", "7d", "30d" or "all") as plain text, for `lawn stats --since`.
// limit <= 0 prints every group. Rows carry the same status labels and
// display-rule networks as the site. A second table lists the well-behaved
// groups (read robots.txt, never entered /lawn/) active in the window.
func WriteStats(w io.Writer, r *Report, window string, limit int) error {
	wi, ok := WindowIndex(window)
	if !ok {
		return fmt.Errorf("shame: unknown window %q (want 24h, 7d, 30d or all)", window)
	}
	var gs []*Group
	for _, g := range r.Groups {
		if g.W[wi].Pages > 0 {
			gs = append(gs, g)
		}
	}
	slices.SortStableFunc(gs, func(x, y *Group) int {
		if c := cmp.Compare(y.W[wi].HeldMs, x.W[wi].HeldMs); c != 0 {
			return c
		}
		return cmp.Compare(y.W[wi].Pages, x.W[wi].Pages)
	})
	total := len(gs)
	if limit > 0 && len(gs) > limit {
		gs = gs[:limit]
	}
	t := r.Totals[wi]
	fmt.Fprintf(w, "Top offenders, window %s (generated %s)\n", window, genTime(r.Generated))
	fmt.Fprintf(w, "Totals: %s bot-hours, %d disallowed pages, %d sessions, max depth %d\n\n",
		fmtHours(t.HeldMs), t.Pages, t.Sessions, t.MaxDepth)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tSTATUS\tNAME\tNETWORK\tHOURS\tPAGES\tDEPTH\tBYTES\tSESSIONS\tREAD-RULES\tFIRST SEEN\tLAST SEEN")
	for i, g := range gs {
		m := g.W[wi]
		network := ""
		if g.Kind != KindASN && (g.ASN != 0 || g.ASNOrg != "") {
			network = ASNLabel(g.ASN, g.ASNOrg)
		}
		if network == g.Name {
			network = ""
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%d\t%d\t%s\t%s\n", i+1, StatusLabel(g.Kind),
			truncate(g.Name, 40), truncate(network, 40), fmtHours(m.HeldMs), m.Pages, m.MaxDepth,
			fmtBytes(m.Bytes), m.Sessions, m.ReadRules, fmtTime(m.FirstSeen), fmtTime(m.LastSeen))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if total > len(gs) {
		fmt.Fprintf(w, "\n(%d more not shown)\n", total-len(gs))
	}
	if total == 0 {
		fmt.Fprintln(w, "No violations in this window.")
	}
	return writeWellBehavedStats(w, r, wi, limit)
}

// writeWellBehavedStats prints the well-behaved groups with requests in
// window wi, most recently seen (in that window) first.
func writeWellBehavedStats(w io.Writer, r *Report, wi, limit int) error {
	var gs []*WellBehavedGroup
	for _, g := range r.WellBehaved {
		if g.W[wi].Requests > 0 {
			gs = append(gs, g)
		}
	}
	slices.SortStableFunc(gs, func(x, y *WellBehavedGroup) int {
		if c := cmp.Compare(y.W[wi].LastSeen, x.W[wi].LastSeen); c != 0 {
			return c
		}
		return cmp.Compare(y.W[wi].Requests, x.W[wi].Requests)
	})
	total := len(gs)
	if limit > 0 && len(gs) > limit {
		gs = gs[:limit]
	}
	fmt.Fprintf(w, "\nWell-behaved (read robots.txt, never entered /lawn/): %d groups, %d clients all time; %d groups active in window %s\n",
		len(r.WellBehaved), r.WellBehavedClients(), total, WindowNames[wi])
	if total == 0 {
		_, err := fmt.Fprintln(w, "None in this window.")
		return err
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tSTATUS\tNAME\tDETAIL\tCLIENTS\tROBOTS.TXT\tREQUESTS\tSAW BAIT\tFIRST SEEN\tLAST SEEN")
	for i, g := range gs {
		m := g.W[wi]
		detail := g.Sub
		if detail == "" && g.Kind != logstore.StatusAnonymous && len(g.ASNs) > 0 {
			detail = g.ASNs[0].Label
			if len(g.ASNs) > 1 {
				detail += fmt.Sprintf(" +%d", len(g.ASNs)-1)
			}
		}
		bait := "no"
		if m.SawBait() {
			bait = "yes"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\n", i+1, StatusLabel(g.Kind),
			truncate(g.Name, 40), truncate(detail, 60), g.Clients, m.Robots, m.Requests, bait,
			fmtTime(m.FirstSeen), fmtTime(m.LastSeen))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if total > len(gs) {
		_, err := fmt.Fprintf(w, "\n(%d more not shown)\n", total-len(gs))
		return err
	}
	return nil
}
