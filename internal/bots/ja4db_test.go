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

// A JA4DB download in the shape FoxIO publishes: an array of objects with
// many fingerprint kinds, most entries without a JA4 (TLS client) one.
var ja4dbJSON = `[
 {"application": "Chromium Browser", "library": null, "device": null, "os": "Windows", "user_agent_string": "Mozilla/5.0 ...", "verified": true, "ja4_fingerprint": "` + fpChrome + `", "ja4s_fingerprint": null},
 {"application": null, "library": "Python requests", "os": "Linux", "verified": false, "ja4_fingerprint": "` + fpPython + `"},
 {"application": "Python", "os": "", "ja4_fingerprint": "` + fpPython + `"},
 {"application": "Some Agent", "ja4_fingerprint": "` + fpMixed + `"},
 {"application": "Firefox", "ja4_fingerprint": "` + fpMixed + `"},
 {"application": "Sliver", "ja4_fingerprint": null, "ja4x_fingerprint": "abc"},
 {"application": "Odd", "ja4_fingerprint": "not-a-ja4"}
]`

func TestParseJA4DB(t *testing.T) {
	db, err := ParseJA4DB(strings.NewReader(ja4dbJSON))
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 3 {
		t.Errorf("fingerprints %d, want 3 (null and malformed skipped)", db.Len())
	}
	if got := db.Names(fpPython, 5); len(got) != 2 || got[0] != "Python" || got[1] != "Python requests (Linux)" {
		t.Errorf("python names %q", got)
	}
	if names, ok := db.NonBrowser(fpPython); !ok || names[0] != "Python" {
		t.Errorf("python NonBrowser %v %v", names, ok)
	}
	for _, fp := range []string{fpChrome, fpMixed, "t13d0000h2_000000000000_000000000000"} {
		if _, ok := db.NonBrowser(fp); ok {
			t.Errorf("%s: a browser entry, or no entry, is never non-browser", fp)
		}
	}
	var nilDB *JA4DB
	if nilDB.Len() != 0 || nilDB.Names(fpChrome, 2) != nil {
		t.Error("nil database")
	}
	for _, bad := range []string{`{}`, `[{"ja4_fingerprint": 5}]`, `[`, ``} {
		if _, err := ParseJA4DB(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIsBrowser(t *testing.T) {
	for e, want := range map[JA4DBEntry]bool{
		{Application: "Chromium Browser"}:                       true,
		{Application: "Microsoft Edge"}:                         true,
		{Library: "WebKit"}:                                     true,
		{Application: "Tor Browser"}:                            true,
		{Application: "curl"}:                                   false,
		{Application: "Go-http-client"}:                         false,
		{Application: "Log Collector"}:                          false, // "tor" inside a word
		{Application: "Knowledge base app"}:                     false, // "edge" inside a word
		{UserAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120"}: true,
		{Application: "python", UserAgent: "Mozilla/5.0"}:       false,
	} {
		if got := e.IsBrowser(); got != want {
			t.Errorf("%+v: IsBrowser %v", e, got)
		}
	}
}

func TestLoadJA4DBMissing(t *testing.T) {
	if db, err := LoadJA4DB(filepath.Join(t.TempDir(), "none.json")); db != nil || err != nil {
		t.Errorf("missing file: %v %v", db, err)
	}
	p := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(p, []byte("<html>"), 0o644)
	if _, err := LoadJA4DB(p); err == nil || !strings.Contains(err.Error(), "bad.json") {
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
	db, _ := ParseJA4DB(strings.NewReader(ja4dbJSON))
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
	if !fake.Reasons[SigTLSJA4DB+"Python"] || Weight(SigTLSJA4DB+"Python") != 3 {
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
	for _, w := range []string{"JA4 names from FoxIO's JA4DB (3 fingerprints)",
		fpPython + " [JA4DB: Python; Python requests (Linux)]", fpChrome + " [JA4DB: Chromium Browser (Windows)]"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("report lacks %q", w)
		}
	}
	out.Reset()
	r.JA4DB = nil
	Write(&out, r, WriteOptions{})
	if !strings.Contains(out.String(), "FoxIO JA4DB not loaded") {
		t.Error("missing database not reported")
	}
}
