package bots

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

const (
	fpChrome = "t13d1516h2_8daaf6152771_dcad5a053991"
	fpPython = "t13i181000_85036bcba153_d41ae481755e"
	fpMixed  = "t13d1715h2_5b57614c22b0_3d5424432f57"
)

// Rows in the shape of the ja4db-export CSV: most carry only the user agent
// a fingerprint was seen with; QUIC ("q…") and empty fingerprints occur.
var ja4dbCSV = "application,library,device,os,user_agent_string,certificate_authority,verified,notes,observation_count,ja4_fingerprint\n" +
	"Chromium Browser,,,Windows,,,true,,1," + fpChrome + "\n" +
	",,,,python-requests/2.32.3,,false,,3," + fpPython + "\n" +
	",Python,,Linux,,,false,,1," + fpPython + "\n" +
	",Python,,Linux,,,false,,1," + fpPython + "\n" + // repeated label kept once
	",,,,curl/8.7.1,,false,,1," + fpMixed + "\n" +
	",,,,\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\",,false,,9," + fpMixed + "\n" +
	"Chromium Browser,,,,,,true,,1,q13d0312h3_55b375c5d22e_06cda9e17597\n" +
	",,,,\"Pleroma 2.6.3; https://pl.example <admin@example.org>; Bot\",,false,,2,t13d2014h2_a09f3c656075_000000000000\n" +
	"Sliver,,,,,,true,,1,\n" +
	",,,,curl/8,,false,,1,t12d000600_\x03\nP\x98CN\xc3\x85_e28d05d9ca73\n" + // corrupt, as in the export
	",,,,curl/8,,false,,1,T13D1516H2_8DAAF6152771_DCAD5A053991\n"

func TestParseJA4DB(t *testing.T) {
	db, err := ParseJA4DB(strings.NewReader(ja4dbCSV))
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 5 {
		t.Errorf("fingerprints %d, want 5 (empty skipped, QUIC kept)", db.Len())
	}
	if got := db.Names(fpPython, 5); len(got) != 2 || got[0] != "Python (Linux)" || got[1] != "python-requests" {
		t.Errorf("python names %q", got)
	}
	if len(db.Lookup(fpPython)) != 2 {
		t.Errorf("labels not deduplicated: %v", db.Lookup(fpPython))
	}
	if names, ok := db.NonBrowser(fpPython); !ok || names[0] != "Python (Linux)" {
		t.Errorf("python NonBrowser %v %v", names, ok)
	}
	// Seen with curl and with a Chrome user agent: not non-browser.
	if _, ok := db.NonBrowser(fpMixed); ok {
		t.Error("a fingerprint also seen as a browser must not count as non-browser")
	}
	if got := db.Names(fpMixed, 5); len(got) != 2 || got[0] != "Chrome user agent" || got[1] != "curl" {
		t.Errorf("mixed names %q", got)
	}
	// Only the product name of a user agent is kept, never contact details.
	pl := db.Lookup("t13d2014h2_a09f3c656075_000000000000")
	if len(pl) != 1 || pl[0].Name != "Pleroma" || pl[0].Browser {
		t.Errorf("pleroma %+v", pl)
	}
	for _, fp := range []string{fpChrome, "t13d0000h2_000000000000_000000000000"} {
		if _, ok := db.NonBrowser(fp); ok {
			t.Errorf("%s: a browser entry, or no entry, is never non-browser", fp)
		}
	}
	var nilDB *JA4DB
	if nilDB.Len() != 0 || nilDB.Names(fpChrome, 2) != nil {
		t.Error("nil database")
	}
	for _, bad := range []string{"", "a,b,c\n1,2,3\n", "ja4_fingerprint\n\"unterminated\n"} {
		if _, err := ParseJA4DB(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestJA4DBRowEntry(t *testing.T) {
	for r, want := range map[JA4DBRow]JA4DBEntry{
		{Application: "Chromium Browser"}:   {Name: "Chromium Browser", Browser: true},
		{Application: "Microsoft Edge"}:     {Name: "Microsoft Edge", Browser: true},
		{Library: "WebKit", OS: "iOS"}:      {Name: "WebKit (iOS)", Browser: true},
		{Application: "Tor Browser"}:        {Name: "Tor Browser", Browser: true},
		{Application: "curl"}:               {Name: "curl"},
		{Application: "Log Collector"}:      {Name: "Log Collector"},      // "tor" inside a word
		{Application: "Knowledge base app"}: {Name: "Knowledge base app"}, // "edge" inside a word
		{UserAgent: "Go-http-client/1.1"}:   {Name: "go-http-client"},
		{UserAgent: "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"}:                 {Name: "GPTBot"},
		{UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"}:           {Name: "Firefox user agent", Browser: true},
		{UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"}: {Name: "browser-like user agent", Browser: true},
		{UserAgent: ""}: {Name: "(empty user agent)"},
	} {
		if got := r.Entry(); got != want {
			t.Errorf("%+v: %+v, want %+v", r, got, want)
		}
	}
}

func TestLoadJA4DBMissing(t *testing.T) {
	if db, err := LoadJA4DB(filepath.Join(t.TempDir(), "none.csv")); db != nil || err != nil {
		t.Errorf("missing file: %v %v", db, err)
	}
	p := filepath.Join(t.TempDir(), "bad.csv")
	os.WriteFile(p, []byte("<html>\n"), 0o644)
	if _, err := LoadJA4DB(p); err == nil || !strings.Contains(err.Error(), "bad.csv") {
		t.Errorf("bad file: %v", err)
	}
}

// A browser user agent whose fingerprint JA4DB knows only from Python gets
// the JA4DB signal; the detail block names fingerprints; a real Chrome
// fingerprint gets neither the signal nor a false name.
func TestJA4DBSignal(t *testing.T) {
	s, err := logstore.Open(filepath.Join(t.TempDir(), "lawn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
	row := func(ip string, asn uint32, fp string) logstore.Request {
		return logstore.Request{TsStart: now.Add(-time.Hour).UnixMilli(), IP: ip, ASN: asn, UserAgent: chrome, Method: "GET",
			Path: "/lawn/x", Depth: 0, IsViolation: true, Status: 200, HeaderNames: "Accept,Accept-Language,Sec-Fetch-Mode,User-Agent",
			AcceptLanguage: "en", Proto: "HTTP/2.0", Scheme: "https", JA4: fp}
	}
	if err := s.InsertRequests(context.Background(), []logstore.Request{
		row("192.0.2.1", 64501, fpPython), row("192.0.2.2", 64502, fpChrome)}); err != nil {
		t.Fatal(err)
	}
	db, _ := ParseJA4DB(strings.NewReader(ja4dbCSV))
	r, err := Collect(context.Background(), Options{DB: s.DB(), Since: 24 * time.Hour, Now: func() time.Time { return now }, JA4DB: db})
	if err != nil {
		t.Fatal(err)
	}
	byASN := map[string]*Bot{}
	for _, b := range r.Bots {
		byASN[b.Token] = b
	}
	fake, real := byASN["browser-like UA @ AS64501"], byASN["browser-like UA @ AS64502"]
	if fake == nil || real == nil {
		t.Fatalf("groups: %v", r.Bots)
	}
	if !fake.Reasons[SigTLSJA4DB+"Python (Linux)"] || Weight(SigTLSJA4DB+"Python (Linux)") != 3 {
		t.Errorf("python-TLS Chrome: %v", sortedKeys(fake.Reasons))
	}
	for sig := range real.Reasons {
		if strings.HasPrefix(sig, SigTLSJA4DB) {
			t.Errorf("real Chrome fingerprint flagged: %s", sig)
		}
	}
	if IsPublic(SigTLSJA4DB + "Python") {
		t.Error("the JA4DB signal must stay private")
	}
	var out bytes.Buffer
	Write(&out, r, WriteOptions{Details: 10})
	for _, w := range []string{"JA4 names from the JA4DB snapshot (5 fingerprints)",
		fpPython + " [JA4DB: Python (Linux); python-requests]", fpChrome + " [JA4DB: Chromium Browser (Windows)]"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("report lacks %q", w)
		}
	}
	out.Reset()
	r.JA4DB = nil
	Write(&out, r, WriteOptions{})
	if !strings.Contains(out.String(), "JA4DB snapshot not loaded") {
		t.Error("missing database not reported")
	}
}
