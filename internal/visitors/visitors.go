// Package visitors is the private per-request log view behind
// `lawn visitors`: who came, from where, for what, and how it ended.
// Output is for the operator only; nothing here is published.
package visitors

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// Options selects and orders the visits to list.
type Options struct {
	DB        *sql.DB
	Since     time.Duration // window; 0 = everything still in requests
	Now       func() time.Time
	IP        string // single address or CIDR
	ASN       string // "AS64500" or "64500"
	UA        string // case-insensitive substring
	Path      string // path prefix, e.g. /lawn/ or /.env
	Scheme    string // https, http, gopher or gemini
	LawnOnly  bool   // only /lawn/ requests
	Operators bool   // include the operator's own networks (marked *)
	Exclude   []netip.Prefix
	Limit     int // max rows (<= 0: 100)
}

// Visit is one logged request.
type Visit struct {
	Start, End        int64 // unix ms; End 0 = unknown
	IP, Country       string
	ASN               int64
	ASNOrg, UserAgent string
	Method, Path      string
	Status            int64
	Depth             int64 // -1 outside /lawn/
	Ended, Referer    string
	Bytes             int64
	Scheme, Proto     string
	Operator          bool
}

// Result is what List found.
type Result struct {
	Visits   []Visit
	Hidden   int  // operator visits left out
	More     bool // the limit cut the list short
	Timeline bool // oldest first (single client)
}

// List reads matching visits: newest first, or oldest first when IP names
// one address (a client's timeline).
func List(ctx context.Context, o Options) (*Result, error) {
	if o.DB == nil {
		return nil, errors.New("visitors: nil DB")
	}
	if o.Limit <= 0 {
		o.Limit = 100
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	var (
		where []string
		args  []any
		inNet netip.Prefix
		res   = &Result{}
	)
	if o.Since > 0 {
		where = append(where, "ts_start >= ?")
		args = append(args, now().Add(-o.Since).UnixMilli())
	}
	if o.IP != "" {
		if a, err := netip.ParseAddr(o.IP); err == nil {
			where = append(where, "ip = ?")
			args = append(args, a.Unmap().String())
			res.Timeline = true
		} else if p, err := netip.ParsePrefix(o.IP); err == nil {
			inNet = p.Masked()
		} else {
			return nil, fmt.Errorf("visitors: --ip %q is not an address or CIDR", o.IP)
		}
	}
	if o.ASN != "" {
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(o.ASN), "AS"), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("visitors: --asn %q is not an AS number", o.ASN)
		}
		where = append(where, "asn = ?")
		args = append(args, n)
	}
	if o.UA != "" {
		where = append(where, `user_agent LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(o.UA)+"%")
	}
	if o.Path != "" {
		where = append(where, `path LIKE ? ESCAPE '\'`)
		args = append(args, likeEscape(o.Path)+"%")
	}
	if o.LawnOnly {
		where = append(where, "is_violation = 1")
	}
	if o.Scheme != "" {
		where = append(where, "scheme = ?")
		args = append(args, strings.ToLower(o.Scheme))
	}
	q := `SELECT ts_start, COALESCE(ts_end, 0), ip, COALESCE(country, ''), COALESCE(asn, 0), COALESCE(asn_org, ''),
  COALESCE(user_agent, ''), COALESCE(method, ''), path, COALESCE(status, 0), COALESCE(depth, -1),
  COALESCE(end_reason, ''), COALESCE(referer, ''), COALESCE(bytes_sent, 0),
  COALESCE(scheme, ''), COALESCE(proto, '')
FROM requests`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	if res.Timeline {
		q += " ORDER BY ts_start, id"
	} else {
		q += " ORDER BY ts_start DESC, id DESC"
	}
	rows, err := o.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("visitors: %w", err)
	}
	defer rows.Close()
	skip := logstore.NewIPSet(o.Exclude)
	for rows.Next() {
		var v Visit
		if err := rows.Scan(&v.Start, &v.End, &v.IP, &v.Country, &v.ASN, &v.ASNOrg, &v.UserAgent, &v.Method,
			&v.Path, &v.Status, &v.Depth, &v.Ended, &v.Referer, &v.Bytes, &v.Scheme, &v.Proto); err != nil {
			return nil, fmt.Errorf("visitors: %w", err)
		}
		if inNet.IsValid() {
			a, err := netip.ParseAddr(v.IP)
			if err != nil || !inNet.Contains(a.Unmap()) {
				continue
			}
		}
		if skip.Has(v.IP) {
			if !o.Operators {
				res.Hidden++
				continue
			}
			v.Operator = true
		}
		if len(res.Visits) == o.Limit {
			res.More = true
			if o.Operators || skip == nil {
				break // nothing left to count
			}
			continue // keep counting hidden rows
		}
		res.Visits = append(res.Visits, v)
	}
	return res, rows.Err()
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// Write prints r as a table.
func Write(w io.Writer, r *Result) {
	if len(r.Visits) == 0 {
		fmt.Fprintln(w, "No matching visits.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "TIME (UTC)\tIP\tCC\tNETWORK\tVIA\tREQUEST\tSTATUS\tDEPTH\tENDED\tSECS\tBYTES\tREFERER\tUSER AGENT")
		for _, v := range r.Visits {
			ip := v.IP
			if v.Operator {
				ip = "*" + ip
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
				time.UnixMilli(v.Start).UTC().Format("01-02 15:04:05"), ip, orDash(v.Country),
				clip(network(v.ASN, v.ASNOrg), 28), via(v), clip(v.Method+" "+v.Path, 60), status(v.Status),
				depth(v.Depth), orDash(v.Ended), secs(v.Start, v.End), v.Bytes,
				clip(orDash(v.Referer), 50), clip(orDash(v.UserAgent), 90))
		}
		tw.Flush()
	}
	order := "newest first"
	if r.Timeline {
		order = "oldest first"
	}
	fmt.Fprintf(w, "\n%d visits, %s.", len(r.Visits), order)
	if r.More {
		fmt.Fprint(w, " More match; raise --limit or narrow the filters.")
	}
	if r.Hidden > 0 {
		fmt.Fprintf(w, " %d from your own networks (exclude_cidrs) hidden; --operators shows them.", r.Hidden)
	}
	fmt.Fprintln(w)
}

// via is how a visit arrived: "https h2", "https h3", "http 1.1", "onion",
// "gopher", "gemini"; "-" for rows logged before schemes were recorded.
func via(v Visit) string {
	if v.ASN == int64(logstore.OnionASN) {
		return "onion"
	}
	switch v.Scheme {
	case "gopher", "gemini":
		return v.Scheme
	case "":
		if v.Proto == "" {
			return "-"
		}
		return strings.TrimPrefix(v.Proto, "HTTP/")
	}
	ver := strings.TrimPrefix(v.Proto, "HTTP/")
	switch ver {
	case "2.0":
		ver = "h2"
	case "3.0":
		ver = "h3"
	}
	return strings.TrimSpace(v.Scheme + " " + ver)
}

func network(asn int64, org string) string {
	if asn < 0 || asn > 1<<32-1 {
		asn = 0
	}
	return logstore.NetworkLabel(uint32(asn), org, "-")
}

func status(s int64) string {
	if s == 0 {
		return "-"
	}
	return strconv.FormatInt(s, 10)
}

func depth(d int64) string {
	if d < 0 {
		return "-"
	}
	return strconv.FormatInt(d, 10)
}

func secs(start, end int64) string {
	if end <= 0 || end < start {
		return "-"
	}
	return strconv.FormatFloat(float64(end-start)/1000, 'f', 1, 64)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
