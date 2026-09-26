package shame

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// MaxPageBytes is the hard ceiling for every rendered HTML page (SPEC.md
// section 8: "total page weight under 50 KB"). Pages have no other assets.
const MaxPageBytes = 50_000

// buildMu serializes in-process builds (ticker vs. an overlapping run).
var buildMu sync.Mutex

// Build collects the report, renders every page and feed into a temp dir
// inside PublicDir, and atomically swaps it into PublicDir/shame.
func Build(ctx context.Context, opt Options) (*Report, error) {
	if opt.Templates == nil {
		return nil, errors.New("shame: nil Templates")
	}
	if opt.PublicDir == "" {
		return nil, errors.New("shame: empty PublicDir")
	}
	tpl, err := parseTemplates(opt)
	if err != nil {
		return nil, err
	}
	r, err := Collect(ctx, opt)
	if err != nil {
		return nil, err
	}
	buildMu.Lock()
	defer buildMu.Unlock()
	if err := os.MkdirAll(opt.PublicDir, 0o755); err != nil {
		return nil, fmt.Errorf("shame: %w", err)
	}
	cleanStale(opt.PublicDir, time.Hour)
	tmp, err := os.MkdirTemp(opt.PublicDir, tmpPrefix)
	if err != nil {
		return nil, fmt.Errorf("shame: temp dir: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o755); err != nil {
		return nil, fmt.Errorf("shame: %w", err)
	}
	if err := writeAll(ctx, tpl, r, opt, tmp); err != nil {
		return nil, err
	}
	if err := swapDir(opt.PublicDir, tmp); err != nil {
		return nil, err
	}
	ok = true
	return r, nil
}

const (
	tmpPrefix = ".shame-tmp-"
	oldPrefix = ".shame-old-"
)

// cleanStale removes temp/old dirs left behind by a crashed build.
func cleanStale(publicDir string, age time.Duration) {
	ents, err := os.ReadDir(publicDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() || !(strings.HasPrefix(n, tmpPrefix) || strings.HasPrefix(n, oldPrefix)) {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > age {
			os.RemoveAll(filepath.Join(publicDir, n))
		}
	}
}

// swapDir moves tmp into publicDir/shame: the old tree is renamed aside,
// the new one renamed in, then the old one removed. Both renames are atomic;
// the window where shame/ is absent is two syscalls wide. On failure the old
// tree is restored.
func swapDir(publicDir, tmp string) error {
	final := filepath.Join(publicDir, "shame")
	old := ""
	if _, err := os.Lstat(final); err == nil {
		old = filepath.Join(publicDir, oldPrefix+strings.TrimPrefix(filepath.Base(tmp), tmpPrefix))
		if err := os.Rename(final, old); err != nil {
			return fmt.Errorf("shame: move old tree aside: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("shame: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		if old != "" {
			_ = os.Rename(old, final)
		}
		return fmt.Errorf("shame: swap in new tree: %w", err)
	}
	if old != "" {
		if err := os.RemoveAll(old); err != nil {
			return fmt.Errorf("shame: remove old tree: %w", err)
		}
	}
	return nil
}

func parseTemplates(opt Options) (*template.Template, error) {
	gap := opt.gap()
	funcs := template.FuncMap{
		"hours":       fmtHours,
		"bytes":       fmtBytes,
		"when":        fmtTime,
		"trunc":       truncate,
		"statusLabel": StatusLabel,
		"statusClass": statusClass,
		"sub":         func(a, b int) int { return a - b },
		"gap":         func() string { return gap.String() },
	}
	t, err := template.New("shame").Funcs(funcs).ParseFS(opt.Templates, "partials.html", "shame/*.html")
	if err != nil {
		return nil, fmt.Errorf("shame: templates: %w", err)
	}
	for _, name := range []string{"style", "footer", "shame-index", "shame-org"} {
		if t.Lookup(name) == nil {
			return nil, fmt.Errorf("shame: template %q not defined", name)
		}
	}
	return t, nil
}

// ---- views ----

type winView struct {
	Name string
	M    Metrics
}

type rowView struct {
	Prefix string
	G      *Group
}

type tableView struct {
	Heading string
	Rows    []rowView
	Total   int
	Feed    string
}

type indexView struct {
	Generated    string
	All          Metrics
	Windows      []winView
	Verified     tableView
	Liars        tableView
	Unverifiable tableView
	ASNs         tableView
	ReadRules    tableView
	RobotsTxt    string
}

type sparkView struct {
	W, H   int
	Days   int
	Peak   int64
	Points string
}

type orgView struct {
	Title       string
	Generated   string
	G           *Group
	Note        string
	Windows     []winView
	ASNs        []ASNRef
	ASNTotal    int
	Members     []*Group
	MemberTotal int
	Spark       *sparkView
	Daily       []Day
	DailyTotal  int
	UAs         []UACount
	UATotal     int
	UALen       int
	CIDRs       []string
	CIDRTotal   int
	CIDRNote    string
	Paths       []string
	RobotsTxt   string
}

func windows(ms [NumWindows]Metrics) []winView {
	out := make([]winView, NumWindows)
	for i := range out {
		out[i] = winView{Name: WindowNames[i], M: ms[i]}
	}
	return out
}

func table(heading string, gs []*Group, n int, prefix string) tableView {
	tv := tableView{Heading: heading, Total: len(gs), Feed: "feed.json"}
	for _, g := range gs[:min(n, len(gs))] {
		tv.Rows = append(tv.Rows, rowView{Prefix: prefix, G: g})
	}
	return tv
}

func genTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// indexCaps are per-section row limits tried in turn until the page fits.
var indexCaps = []int{50, 40, 30, 20, 15, 10, 5, 3, 1}

func renderIndex(t *template.Template, r *Report, robots string) ([]byte, error) {
	var buf bytes.Buffer
	for _, n := range indexCaps {
		v := indexView{
			Generated:    genTime(r.Generated),
			All:          r.Totals[WAll],
			Windows:      windows(r.Totals),
			Verified:     table("Org", r.Verified, n, "org/"),
			Liars:        table("Claimed org", r.Liars, n, "org/"),
			Unverifiable: table("Claimed org", r.Unverifiable, n, "org/"),
			ASNs:         table("Network", r.ASNs, n, "org/"),
			ReadRules:    table("Name", r.ReadRules, n, "org/"),
			RobotsTxt:    robots,
		}
		buf.Reset()
		if err := t.ExecuteTemplate(&buf, "shame-index", v); err != nil {
			return nil, fmt.Errorf("shame: render index: %w", err)
		}
		if buf.Len() < MaxPageBytes {
			break
		}
	}
	return buf.Bytes(), nil
}

type orgCaps struct{ asns, members, days, uas, uaLen, cidrs, paths int }

var orgCapLevels = []orgCaps{
	{20, 50, 90, 20, 200, 200, 5},
	{10, 30, 60, 10, 160, 100, 5},
	{5, 15, 30, 5, 120, 50, 3},
	{3, 10, 14, 3, 100, 20, 2},
	{1, 5, 7, 1, 80, 10, 1},
}

func orgNote(g *Group) string {
	switch g.Kind {
	case logstore.StatusVerified:
		return "User agent matched " + g.Name + "'s crawler and the source addresses passed " + g.Name + "'s published verification. These requests fetched paths disallowed by our robots.txt."
	case logstore.StatusSpoofed:
		return "User agent claimed to be " + g.Name + ", but the source addresses failed " + g.Name + "'s published verification. The requests came from " + ASNLabel(g.ASN, g.ASNOrg) + ". Only the claim is " + g.Name + "'s; the traffic is not attributed to " + g.Name + "."
	case logstore.StatusUnverifiable:
		return "User agent claims to be " + g.Name + ". We found no published way to verify that claim, so it is not confirmed; the networks the requests came from are listed below."
	}
	return "Every disallowed request from " + g.Name + ", by identity status. Clients with no known crawler user agent are listed as anonymous."
}

func cidrNote(g *Group) string {
	hasVerified := false
	for _, s := range g.Statuses {
		if s == logstore.StatusVerified {
			hasVerified = true
		}
	}
	switch {
	case hasVerified && len(g.Statuses) == 1:
		return "Verified crawler addresses are shown individually."
	case hasVerified:
		return "Verified crawler addresses are shown individually; everything else as /24 (IPv4) or /48 (IPv6) networks."
	}
	return "Shown as /24 (IPv4) or /48 (IPv6) networks. Individual addresses are only ever published for verified crawlers."
}

const sparkDays = 90

func spark(g *Group, now time.Time) *sparkView {
	if len(g.Daily) == 0 {
		return nil
	}
	end := now.UTC().Truncate(24 * time.Hour)
	start := end.AddDate(0, 0, -(sparkDays - 1))
	vals := make([]int64, sparkDays)
	var peak int64
	seen := false
	for _, d := range g.Daily {
		t, err := time.Parse("2006-01-02", d.Date)
		if err != nil || t.Before(start) || t.After(end) {
			continue
		}
		i := int(t.Sub(start) / (24 * time.Hour))
		vals[i] += d.Pages
		peak = max(peak, vals[i])
		seen = true
	}
	if !seen || peak == 0 {
		return nil
	}
	const w, h = 300, 40
	var b strings.Builder
	for i, v := range vals {
		if i > 0 {
			b.WriteByte(' ')
		}
		x := float64(i) * float64(w) / float64(sparkDays-1)
		y := float64(h-2) - float64(v)/float64(peak)*float64(h-4)
		b.WriteString(strconv.FormatFloat(x, 'f', 1, 64))
		b.WriteByte(',')
		b.WriteString(strconv.FormatFloat(y, 'f', 1, 64))
	}
	return &sparkView{W: w, H: h, Days: sparkDays, Peak: peak, Points: b.String()}
}

func renderOrg(t *template.Template, r *Report, g *Group, robots string, buf *bytes.Buffer) error {
	sp := spark(g, r.Generated)
	for _, c := range orgCapLevels {
		v := orgView{
			Title:       truncate(g.Name, 80) + " · Wall of Shame",
			Generated:   genTime(r.Generated),
			G:           g,
			Note:        orgNote(g),
			Windows:     windows(g.W),
			ASNTotal:    len(g.ASNs),
			MemberTotal: len(g.Members),
			Spark:       sp,
			DailyTotal:  len(g.Daily),
			UATotal:     len(g.TopUAs),
			UALen:       c.uaLen,
			CIDRTotal:   len(g.CIDRs),
			CIDRNote:    cidrNote(g),
			RobotsTxt:   robots,
		}
		if g.Kind != KindASN && g.Kind != logstore.StatusSpoofed {
			v.ASNs = g.ASNs[:min(c.asns, len(g.ASNs))]
		} else {
			v.ASNTotal = 0
		}
		v.Members = g.Members[:min(c.members, len(g.Members))]
		// Daily table: most recent first.
		n := min(c.days, len(g.Daily))
		v.Daily = make([]Day, 0, n)
		for i := len(g.Daily) - 1; i >= len(g.Daily)-n; i-- {
			v.Daily = append(v.Daily, g.Daily[i])
		}
		v.UAs = g.TopUAs[:min(c.uas, len(g.TopUAs))]
		v.CIDRs = g.CIDRs[:min(c.cidrs, len(g.CIDRs))]
		v.Paths = g.Paths[:min(c.paths, len(g.Paths))]
		buf.Reset()
		if err := t.ExecuteTemplate(buf, "shame-org", v); err != nil {
			return fmt.Errorf("shame: render org %s: %w", g.Slug, err)
		}
		if buf.Len() < MaxPageBytes {
			return nil
		}
	}
	return nil
}

func writeFile(path string, b []byte) error {
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("shame: %w", err)
	}
	return nil
}

func writeAll(ctx context.Context, t *template.Template, r *Report, opt Options, dir string) error {
	idx, err := renderIndex(t, r, opt.RobotsTxt)
	if err != nil {
		return err
	}
	if len(idx) >= MaxPageBytes {
		r.Warnings = append(r.Warnings, fmt.Sprintf("shame/index.html is %d bytes (limit %d)", len(idx), MaxPageBytes))
	}
	if err := writeFile(filepath.Join(dir, "index.html"), idx); err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, g := range r.Pages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := renderOrg(t, r, g, opt.RobotsTxt, &buf); err != nil {
			return err
		}
		if buf.Len() >= MaxPageBytes {
			r.Warnings = append(r.Warnings, fmt.Sprintf("shame/org/%s/index.html is %d bytes (limit %d)", g.Slug, buf.Len(), MaxPageBytes))
		}
		d := filepath.Join(dir, "org", g.Slug)
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("shame: %w", err)
		}
		if err := writeFile(filepath.Join(d, "index.html"), buf.Bytes()); err != nil {
			return err
		}
	}
	feed, err := json.MarshalIndent(r.Feed, "", " ")
	if err != nil {
		return fmt.Errorf("shame: feed: %w", err)
	}
	if err := writeFile(filepath.Join(dir, "feed.json"), append(feed, '\n')); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, "blocklist.txt"), BlocklistText(r, opt.BaseURL))
}

// BlocklistText renders blocklist.txt: a comment header, then one CIDR per line.
func BlocklistText(r *Report, baseURL string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# getoffmyfuckinglawn.com blocklist\n")
	fmt.Fprintf(&b, "# generated %s\n", r.Generated.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# methodology: clients that fetched paths disallowed by our robots.txt.\n")
	fmt.Fprintf(&b, "#   - verified crawlers (UA matched and passed the vendor's published verification): individual IPs (/32, /128)\n")
	fmt.Fprintf(&b, "#   - spoofed crawler UAs (failed that verification) with >= %d disallowed fetches per (claimed org, ASN): /24 (IPv4) or /48 (IPv6)\n", max(r.BlocklistMin, 1))
	fmt.Fprintf(&b, "#   - anonymous and unverifiable clients are never listed\n")
	fmt.Fprintf(&b, "# details: %s/#methodology\n", strings.TrimRight(baseURL, "/"))
	fmt.Fprintf(&b, "# entries: %d\n", len(r.Blocklist))
	for _, c := range r.Blocklist {
		b.WriteString(c)
		b.WriteByte('\n')
	}
	return b.Bytes()
}
