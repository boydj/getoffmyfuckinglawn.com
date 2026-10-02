package bots

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
)

// JA4DB is FoxIO's JA4+ signature database (https://ja4db.com), reduced to
// what `lawn bots` uses: for each JA4 (TLS client) fingerprint, the software
// it has been observed from. It is private analysis only; nothing from it is
// published.
type JA4DB struct {
	entries map[string][]JA4DBEntry
}

// JA4DBEntry is one observation of a fingerprint.
type JA4DBEntry struct {
	Application string `json:"application"`
	Library     string `json:"library"`
	OS          string `json:"os"`
	UserAgent   string `json:"user_agent_string"`
	Verified    bool   `json:"verified"`
	JA4         string `json:"ja4_fingerprint"`
}

// Name is how the entry is shown: application, else library, plus the OS.
func (e JA4DBEntry) Name() string {
	n := strings.TrimSpace(e.Application)
	if n == "" {
		n = strings.TrimSpace(e.Library)
	}
	if n == "" {
		return ""
	}
	if os := strings.TrimSpace(e.OS); os != "" {
		n += " (" + os + ")"
	}
	return n
}

// browserish matches application/library names of web browsers and the
// engines they are built on. The database labels entries in free text, so
// this errs towards "browser": a fingerprint counts as non-browser only when
// none of its entries looks like one.
var browserish = regexp.MustCompile(`(?i)chrom|firefox|safari|\bedge\b|opera|brave|vivaldi|browser|webkit|gecko|mozilla|samsung ?internet|yandex|duckduckgo|\barc\b|\btor\b`)

// IsBrowser reports whether the entry describes a web browser.
func (e JA4DBEntry) IsBrowser() bool {
	return browserish.MatchString(e.Application) || browserish.MatchString(e.Library) ||
		e.Application == "" && e.Library == "" && browserish.MatchString(e.UserAgent)
}

// Len is the number of distinct fingerprints known.
func (db *JA4DB) Len() int {
	if db == nil {
		return 0
	}
	return len(db.entries)
}

// Lookup returns the entries for a JA4 fingerprint.
func (db *JA4DB) Lookup(fp string) []JA4DBEntry {
	if db == nil {
		return nil
	}
	return db.entries[fp]
}

// Names returns the distinct names of fp's entries, sorted, at most n.
func (db *JA4DB) Names(fp string, n int) []string {
	var out []string
	for _, e := range db.Lookup(fp) {
		if name := e.Name(); name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out[:min(n, len(out))]
}

// NonBrowser reports whether every entry for fp describes something other
// than a browser, and returns their names. A fingerprint with no entries, or
// with any browser entry, is not non-browser.
func (db *JA4DB) NonBrowser(fp string) ([]string, bool) {
	es := db.Lookup(fp)
	if len(es) == 0 {
		return nil, false
	}
	for _, e := range es {
		if e.IsBrowser() {
			return nil, false
		}
	}
	return db.Names(fp, 3), true
}

// maxJA4DBBytes bounds what LoadJA4DB reads; the real file is a few MB.
const maxJA4DBBytes = 256 << 20

// LoadJA4DB reads the database's JSON download (an array of objects; only
// the fields in JA4DBEntry are used, entries without a JA4 fingerprint are
// skipped). A missing file returns nil, nil: the JA4DB signal is then off.
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

// ParseJA4DB decodes the JSON array one entry at a time, so memory follows
// the entries kept, not the file size.
func ParseJA4DB(r io.Reader) (*JA4DB, error) {
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return nil, fmt.Errorf("ja4db: not a JSON array")
	}
	db := &JA4DB{entries: map[string][]JA4DBEntry{}}
	for dec.More() {
		var e JA4DBEntry
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("ja4db: %w", err)
		}
		e.JA4 = strings.TrimSpace(e.JA4)
		if len(e.JA4) != 36 {
			continue // no (or not a) TLS client fingerprint
		}
		e.UserAgent = truncateUA(e.UserAgent)
		db.entries[e.JA4] = append(db.entries[e.JA4], e)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("ja4db: %w", err)
	}
	return db, nil
}

func truncateUA(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
