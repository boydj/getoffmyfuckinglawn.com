package shame

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"
)

// WriteStats prints the top offender groups for one trailing window
// ("24h", "7d", "30d" or "all") as plain text, for `lawn stats --since`.
// limit <= 0 prints every group. Rows carry the same status labels and
// display-rule networks as the site.
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
		_, err := fmt.Fprintf(w, "\n(%d more not shown)\n", total-len(gs))
		return err
	}
	if total == 0 {
		_, err := fmt.Fprintln(w, "No violations in this window.")
		return err
	}
	return nil
}
