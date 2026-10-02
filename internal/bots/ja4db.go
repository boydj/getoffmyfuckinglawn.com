package bots

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
)

// JA4DB is a snapshot of FoxIO's JA4+ signature database, reduced to what
// `lawn bots` uses: for each JA4 (TLS client) fingerprint, the software it
// was observed from. FoxIO closed the database in May 2026; the snapshot is
// the CSV export at github.com/Niicolaa/ja4db-export (frozen, no licence
// stated), pinned to one commit by deploy/ja4db-refresh.sh. It is private
// analysis only; nothing from it is published.
type JA4DB struct {
	entries map[string][]JA4DBEntry // distinct per fingerprint
}

// JA4DBEntry is one distinct label for a fingerprint.
type JA4DBEntry struct {
	Name    string // application or library (plus OS), else the product its user agent names
	Browser bool   // describes a web browser
}

// JA4DBRow is one row of the export, before reduction.
type JA4DBRow struct {
	Application, Library, OS, UserAgent, JA4 string
}

// browserish matches application/library names of web browsers and the
// engines they are built on. The database labels entries in free text, so
// this errs towards "browser": a fingerprint counts as non-browser only when
// none of its entries looks like one.
var browserish = regexp.MustCompile(`(?i)chrom|firefox|safari|\bedge\b|opera|brave|vivaldi|browser|webkit|gecko|mozilla|samsung ?internet|yandex|duckduckgo|\barc\b|\btor\b`)

// Entry reduces a row to its label. Most rows of the export carry only the
// user agent the fingerprint was seen with; those are named the way `lawn
// bots` names any client ("curl", "python-requests", "Pleroma"), so the
// full user agent (which can hold contact addresses) is never kept.
func (r JA4DBRow) Entry() JA4DBEntry {
	name := strings.TrimSpace(r.Application)
	if name == "" {
		name = strings.TrimSpace(r.Library)
	}
	if name != "" {
		e := JA4DBEntry{Name: name, Browser: browserish.MatchString(r.Application) || browserish.MatchString(r.Library)}
		if os := strings.TrimSpace(r.OS); os != "" {
			e.Name += " (" + os + ")"
		}
		return e
	}
	ua := strings.TrimSpace(r.UserAgent)
	token, named := Token(ua)
	if named {
		return JA4DBEntry{Name: token}
	}
	// A browser-looking user agent: name the family when we can.
	if b, ok := ParseBrowser(ua); ok {
		return JA4DBEntry{Name: strings.ToUpper(b.Family[:1]) + b.Family[1:] + " user agent", Browser: true}
	}
	return JA4DBEntry{Name: "browser-like user agent", Browser: browserish.MatchString(ua)}
}

// Len is the number of distinct fingerprints known.
func (db *JA4DB) Len() int {
	if db == nil {
		return 0
	}
	return len(db.entries)
}

// Lookup returns the distinct labels of a JA4 fingerprint.
func (db *JA4DB) Lookup(fp string) []JA4DBEntry {
	if db == nil {
		return nil
	}
	return db.entries[fp]
}

// Names returns the distinct names of fp's labels, sorted, at most n.
func (db *JA4DB) Names(fp string, n int) []string {
	var out []string
	for _, e := range db.Lookup(fp) {
		if e.Name != "" && !slices.Contains(out, e.Name) {
			out = append(out, e.Name)
		}
	}
	slices.Sort(out)
	return out[:min(n, len(out))]
}

// NonBrowser reports whether every label of fp describes something other
// than a browser, and returns their names. A fingerprint with no labels, or
// with any browser label, is not non-browser.
func (db *JA4DB) NonBrowser(fp string) ([]string, bool) {
	es := db.Lookup(fp)
	if len(es) == 0 {
		return nil, false
	}
	for _, e := range es {
		if e.Browser {
			return nil, false
		}
	}
	return db.Names(fp, 3), true
}

// isJA4 reports whether s has the shape of a JA4 fingerprint:
// "t13d1516h2_8daaf6152771_e5627efa2ab1" (lower-case letters and digits,
// hex hashes, underscores at 10 and 23).
func isJA4(s string) bool {
	if len(s) != 36 || s[10] != '_' || s[23] != '_' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 10 || i == 23:
		case i > 10 && (c >= '0' && c <= '9' || c >= 'a' && c <= 'f'):
		case i < 10 && (c >= '0' && c <= '9' || c >= 'a' && c <= 'z'):
		default:
			return false
		}
	}
	return true
}

// maxJA4DBBytes bounds what LoadJA4DB reads; the export is about 12 MB.
const maxJA4DBBytes = 256 << 20

// LoadJA4DB reads the export. A missing file returns nil, nil: the JA4DB
// names and signal are then off.
func LoadJA4DB(path string) (*JA4DB, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	db, err := ParseJA4DB(io.LimitReader(f, maxJA4DBBytes))
	if err != nil {
		return nil, fmt.Errorf("bots: %s: %w", path, err)
	}
	return db, nil
}

// ParseJA4DB reads the export's CSV (a header row naming its columns, as in
// csv/ja4_fingerprint.csv). Only application, library, os,
// user_agent_string and ja4_fingerprint are used; rows without a
// 36-character JA4 are skipped, and repeated labels are kept once.
func ParseJA4DB(r io.Reader) (*JA4DB, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("ja4db: header: %w", err)
	}
	col := map[string]int{}
	for i, h := range head {
		col[strings.TrimSpace(strings.TrimPrefix(h, "\ufeff"))] = i
	}
	fpCol, ok := col["ja4_fingerprint"]
	if !ok {
		return nil, errors.New("ja4db: no ja4_fingerprint column")
	}
	get := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return rec[i]
		}
		return ""
	}
	db := &JA4DB{entries: map[string][]JA4DBEntry{}}
	// Most rows repeat a user agent; naming one runs several regexps.
	labels := map[JA4DBRow]JA4DBEntry{}
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ja4db: %w", err)
		}
		if fpCol >= len(rec) {
			continue
		}
		fp := strings.TrimSpace(rec[fpCol])
		if !isJA4(fp) {
			continue // no TLS client fingerprint, or a corrupt one (the export has some)
		}
		row := JA4DBRow{Application: get(rec, "application"), Library: get(rec, "library"), OS: get(rec, "os"),
			UserAgent: get(rec, "user_agent_string")}
		e, ok := labels[row]
		if !ok {
			e = row.Entry()
			labels[row] = e
		}
		if !slices.Contains(db.entries[fp], e) {
			db.entries[fp] = append(db.entries[fp], e)
		}
	}
	return db, nil
}
