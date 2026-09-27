package bots

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"
)

// WriteOptions filters the printed report.
type WriteOptions struct {
	UnknownOnly bool // only bots not in crawlers.yaml
	NewOnly     bool // only bots first seen within Options.NewFor
	Limit       int  // max bots in the table (<= 0: all)
	Details     int  // print a detail block for up to this many unknown/new bots
}

// Write prints the report as plain text.
func Write(w io.Writer, r *Report, o WriteOptions) {
	window := "all data kept"
	if r.Since > 0 {
		window = "last " + humanDur(r.Since)
	}
	var shown []*Bot
	unknown, fresh := 0, 0
	for _, b := range r.Bots {
		if b.Known == "" {
			unknown++
		}
		if b.New {
			fresh++
		}
		if (o.UnknownOnly && b.Known != "") || (o.NewOnly && !b.New) {
			continue
		}
		shown = append(shown, b)
	}
	fmt.Fprintf(w, "Bots, %s (generated %s)\n", window, r.Generated.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(w, "%d clients seen; %d bot groups: %d not in crawlers.yaml, %d first seen recently.\n\n",
		r.Clients, len(r.Bots), unknown, fresh)
	if len(shown) == 0 {
		fmt.Fprintln(w, "Nothing to show.")
		return
	}
	total := len(shown)
	if o.Limit > 0 && len(shown) > o.Limit {
		shown = shown[:o.Limit]
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "BOT\tKNOWN AS\tVERDICT\tREQ\tROBOTS\tBAIT\tLAWN\tDEPTH\tIPS\tTOP NETWORK\tPTR DOMAIN\tFIRST SEEN\tLAST SEEN\tFLAGS")
	for _, b := range shown {
		known := b.Known
		if known == "" {
			known = "-"
		}
		var flags []string
		if b.New {
			flags = append(flags, "NEW")
		}
		if b.Known == "" {
			flags = append(flags, "UNKNOWN")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
			clip(b.Token, 40), clip(known, 30), b.Verdict, b.Requests, b.Robots, b.Bait, b.Violations, b.MaxDepth,
			len(b.IPs), clip(joinOr(top(b.ASNs, 1), "-"), 40), joinOr(top(b.PTRDomains, 1), "-"),
			ts(b.FirstSeen), ts(b.LastSeen), strings.Join(flags, " "))
	}
	tw.Flush()
	if total > len(shown) {
		fmt.Fprintf(w, "(%d more; raise --limit)\n", total-len(shown))
	}

	n := 0
	for _, b := range shown {
		if n >= o.Details || (b.Known != "" && !b.New) {
			continue
		}
		n++
		writeDetails(w, b)
	}
}

func writeDetails(w io.Writer, b *Bot) {
	fmt.Fprintf(w, "\n--- %s", b.Token)
	if b.New {
		fmt.Fprint(w, " [NEW]")
	}
	if b.Known == "" {
		fmt.Fprint(w, " [not in crawlers.yaml]")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  sample UA:    %s\n", clip(b.SampleUA, 300))
	fmt.Fprintf(w, "  contact:      %s\n", orDash(b.Contact))
	fmt.Fprintf(w, "  why a bot:    %s\n", joinOr(sortedKeys(b.Reasons), "-"))
	fmt.Fprintf(w, "  identity:     %s\n", statusSummary(b.Statuses))
	fmt.Fprintf(w, "  networks:     %s\n", joinOr(top(b.ASNs, 3), "-"))
	fmt.Fprintf(w, "  PTR domains:  %s\n", joinOr(top(b.PTRDomains, 3), "none"))
	fmt.Fprintf(w, "  headers sent: %s\n", orDash(b.HeaderNames))
	fmt.Fprintf(w, "  protocol:     %s\n", joinOr(top(b.Protos, 2), "-"))
	fmt.Fprintf(w, "  TLS:          %s\n", joinOr(top(b.TLS, 2), "-"))
	fmt.Fprintf(w, "  activity:     %d requests from %d IPs; %d robots.txt, %d bait pages, %d /lawn/ (max depth %d)\n",
		b.Requests, len(b.IPs), b.Robots, b.Bait, b.Violations, b.MaxDepth)
	if b.Known == "" && !strings.HasPrefix(b.Token, "browser-like") && !strings.HasPrefix(b.Token, "(") {
		fmt.Fprintln(w, "  crawlers.yaml stub (verify the vendor's docs before adding):")
		fmt.Fprintf(w, "    - org: TODO  # %s\n", orDash(b.Contact))
		fmt.Fprintf(w, "      name: %s\n", b.Token)
		fmt.Fprintf(w, "      ua_patterns: ['\\b%s\\b']\n", regexp.QuoteMeta(b.Token))
		fmt.Fprintln(w, "      verify: {method: none}  # TODO: official verification method, if any")
	}
}

func statusSummary(m map[string]int) string {
	var parts []string
	for _, k := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%s x%d", k, m[k]))
	}
	return joinOr(parts, "-")
}

func ts(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func humanDur(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	s := strings.TrimSuffix(d.String(), "0s") // "1h30m0s" -> "1h30m"
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// ParseSince accepts "all", Go durations ("36h") and whole days ("7d").
func ParseSince(s string) (time.Duration, error) {
	if s == "all" || s == "" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err == nil && n > 0 && fmt.Sprintf("%dd", n) == s {
			return time.Duration(n) * 24 * time.Hour, nil
		}
		return 0, fmt.Errorf("bad --since %q", s)
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("bad --since %q (use e.g. 24h, 7d, all)", s)
	}
	return d, nil
}
