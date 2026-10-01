package bots

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

func TestParseBrowser(t *testing.T) {
	for ua, want := range map[string]struct {
		fam      string
		secFetch bool
	}{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36":                         {"chrome", true},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36":                      {"chrome", false},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0":           {"edge", true},
		"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0":                                                                  {"firefox", true},
		"Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0":                                                                    {"firefox", false},
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15":                   {"safari", true},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1": {"safari", false},
	} {
		b, ok := ParseBrowser(ua)
		if !ok || b.Family != want.fam || b.SendsSecFetch() != want.secFetch {
			t.Errorf("%.60s: %+v ok=%v secfetch=%v", ua, b, ok, b.SendsSecFetch())
		}
	}
	for _, ua := range []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0 Mobile/15E148 Safari/604.1",
		"python-requests/2.31.0",
		"",
	} {
		if b, ok := ParseBrowser(ua); ok {
			t.Errorf("%q parsed as %+v", ua, b)
		}
	}
}

func TestLibrary(t *testing.T) {
	for ua, want := range map[string]string{
		"python-requests/2.31.0": "python-requests",
		"Go-http-client/2.0":     "go-http-client",
		"curl/8.5.0":             "curl",
		"HeadlessChrome/120":     "",
		"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0": "",
	} {
		if got := Library(ua); got != want {
			t.Errorf("Library(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestLoadHostingASNs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "asns.txt")
	os.WriteFile(p, []byte("AS63949 # LINODE-AP Linode, LLC, US\nAS14061\t#\n\n# comment\nas24940\nnot an asn\nAS0\n"), 0o644)
	m, err := LoadHostingASNs(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 || !m[63949] || !m[14061] || !m[24940] {
		t.Errorf("got %v", m)
	}
	if m, err := LoadHostingASNs(filepath.Join(t.TempDir(), "missing")); m != nil || err != nil {
		t.Errorf("missing file: %v %v", m, err)
	}
}

func TestTiming(t *testing.T) {
	var tm timing
	for i := range 40 {
		tm.ts = append(tm.ts, int64(i)*1000) // one per second
	}
	pm, gaps, cv := tm.result()
	if pm != 40 || gaps != 39 || cv > 0.001 {
		t.Errorf("steady: %d %d %.3f", pm, gaps, cv)
	}
	tm = timing{ts: []int64{0, 100, 50_000, 51_000, 200_000, 260_000}}
	pm, gaps, cv = tm.result()
	if pm != 4 || gaps != 5 || cv < 0.5 {
		t.Errorf("irregular: %d %d %.3f", pm, gaps, cv)
	}
	if pm, gaps, _ := (&timing{}).result(); pm != 0 || gaps != 0 {
		t.Error("empty")
	}
}

// A scripted client claiming to be Chrome on a hosting network shows most
// of the new signals; a real browser that wandered into the maze shows
// only that it entered.
func TestBrowserImpersonation(t *testing.T) {
	s, err := logstore.Open(filepath.Join(t.TempDir(), "lawn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	start := now.Add(-time.Hour).UnixMilli()
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
	pyJA4 := "t13i181000_85036bcba153_d41ae481755e"     // no ALPN: h2 not offered
	chromeJA4 := "t13d1516h2_8daaf6152771_dcad5a053991" // a real Chromium's
	var rows []logstore.Request
	// The impersonator: 40 maze pages one second apart over HTTP/1.1, no
	// Accept-Language, no Sec-Fetch-*, Python's TLS stack, a HEAD.
	for i := range 40 {
		rows = append(rows, logstore.Request{TsStart: start + int64(i)*1000, TsEnd: start + int64(i)*1000 + 500,
			IP: "172.105.1.2", ASN: 63949, ASNOrg: "AKAMAI-LINODE-AP Akamai Connected Cloud", UserAgent: chrome,
			Method: "GET", Path: "/lawn/p" + strconv.Itoa(i), Depth: i % 12, IsViolation: true, Status: 200,
			HeaderNames: "Accept,Accept-Encoding,User-Agent", Proto: "HTTP/1.1", Scheme: "https", JA4: pyJA4})
	}
	rows = append(rows, logstore.Request{TsStart: start + 50_000, IP: "172.105.1.2", ASN: 63949, UserAgent: chrome,
		Method: "HEAD", Path: "/", Depth: -1, Status: 200, HeaderNames: "User-Agent", Proto: "HTTP/1.1", Scheme: "https", JA4: pyJA4})
	// python-requests seen with the same TLS fingerprint elsewhere.
	rows = append(rows, logstore.Request{TsStart: start, IP: "198.51.100.3", ASN: 64501, UserAgent: "python-requests/2.31.0",
		Method: "GET", Path: "/", Depth: -1, Status: 200, HeaderNames: "Accept,User-Agent", Proto: "HTTP/1.1", Scheme: "https", JA4: pyJA4})
	// A person: h2, Sec-Fetch-*, Accept-Language, a favicon, one maze click.
	person := func(ts int64, path string, viol bool) logstore.Request {
		d := -1
		if viol {
			d = 0
		}
		return logstore.Request{TsStart: ts, IP: "192.0.2.77", ASN: 64502, ASNOrg: "HOME-ISP", UserAgent: chrome,
			Method: "GET", Path: path, Depth: d, IsViolation: viol, Status: 200, AcceptLanguage: "en-US,en;q=0.9",
			HeaderNames: "Accept,Accept-Language,Sec-Fetch-Mode,Sec-Fetch-Site,User-Agent", Proto: "HTTP/2.0", Scheme: "https", JA4: chromeJA4}
	}
	rows = append(rows, person(start, "/", false), person(start+300, "/favicon.ico", false), person(start+20_000, "/lawn/x", true))
	if err := s.InsertRequests(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	r, err := Collect(context.Background(), Options{DB: s.DB(), Since: 24 * time.Hour, Now: func() time.Time { return now },
		Hosting: map[uint32]bool{63949: true}})
	if err != nil {
		t.Fatal(err)
	}
	var fake, real *Bot
	for _, b := range r.Bots {
		switch {
		case strings.Contains(b.Token, "AS63949"):
			fake = b
		case strings.Contains(b.Token, "AS64502"):
			real = b
		}
	}
	if fake == nil || real == nil {
		t.Fatalf("groups: %+v", r.Bots)
	}
	for _, sig := range []string{SigEntered, SigNoAcceptLang, SigHosting, SigNoH2, SigTLSLibrary + "python-requests",
		SigHTTP1, SigNoSecFetch, SigHead, SigFast, SigRegular, SigDeep, SigNoFavicon} {
		if !fake.Reasons[sig] {
			t.Errorf("impersonator lacks %s; has %v", sig, sortedKeys(fake.Reasons))
		}
	}
	if fake.Score < 20 || fake.JA4[pyJA4] != 1 || fake.MaxPerMin != 40 {
		t.Errorf("impersonator: score %d ja4 %v pace %d", fake.Score, fake.JA4, fake.MaxPerMin)
	}
	if len(real.Reasons) != 1 || !real.Reasons[SigEntered] || real.Score != 1 {
		t.Errorf("person: %v score %d", sortedKeys(real.Reasons), real.Score)
	}
	var out bytes.Buffer
	Write(&out, r, WriteOptions{Details: 10})
	for _, want := range []string{"SCORE", "JA4:          " + pyJA4, "up to 40 /lawn/ pages in one minute", "browser-ua-tls-like-library:python-requests"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "Hosting-ASN list not loaded") {
		t.Error("hosting list reported missing")
	}

	// The wall's view: only public signals, per (ip, ua).
	tr, err := Traits(context.Background(), TraitOptions{DB: s.DB(), Hosting: map[uint32]bool{63949: true}})
	if err != nil {
		t.Fatal(err)
	}
	imp := tr[[2]string{"172.105.1.2", chrome}]
	if imp.PerMinute != 40 || len(imp.JA4s) != 1 || len(imp.Signals) < 10 {
		t.Errorf("impersonator traits: %+v", imp)
	}
	for _, c := range tr {
		for _, sig := range c.Signals {
			if !IsPublic(sig) || sig == SigEntered || sig == SigNamed || sig == SigRobots || sig == SigPTR {
				t.Errorf("non-public signal %s", sig)
			}
		}
	}
	if p := tr[[2]string{"192.0.2.77", chrome}]; len(p.Signals) != 0 {
		t.Errorf("person traits: %v", p.Signals)
	}
}

// Supporting signals alone (hosting network, no favicon) do not list a
// client.
func TestSupportingOnly(t *testing.T) {
	if listable([]string{SigHosting, SigNoFavicon}) || !listable([]string{SigHosting, SigEntered}) {
		t.Error("listable")
	}
	if Score(map[string]bool{SigTLSLibrary + "curl": true, SigHosting: true}) != 4 {
		t.Error("score")
	}
}

// Rows logged before the scheme column count as HTTPS when they carry TLS
// details (only Caddy's HTTPS site reached the app then), and not when
// they don't.
func TestPreSchemeRowsAreHTTPS(t *testing.T) {
	s, err := logstore.Open(filepath.Join(t.TempDir(), "lawn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
	row := func(ip, tls string) logstore.Request {
		return logstore.Request{TsStart: now.Add(-time.Hour).UnixMilli(), IP: ip, UserAgent: chrome, Method: "GET",
			Path: "/lawn/x", Depth: 0, IsViolation: true, Status: 200, HeaderNames: "Accept,User-Agent",
			Proto: "HTTP/1.1", TLS: tls} // no Scheme: logged before migration 6
	}
	if err := s.InsertRequests(context.Background(), []logstore.Request{
		row("192.0.2.1", "tls1.3 TLS_AES_128_GCM_SHA256"), row("192.0.2.2", "")}); err != nil {
		t.Fatal(err)
	}
	tr, err := Traits(context.Background(), TraitOptions{DB: s.DB()})
	if err != nil {
		t.Fatal(err)
	}
	has := func(ip, sig string) bool { return slices.Contains(tr[[2]string{ip, chrome}].Signals, sig) }
	if !has("192.0.2.1", SigNoSecFetch) || !has("192.0.2.1", SigHTTP1) {
		t.Errorf("TLS row not judged as HTTPS: %v", tr[[2]string{"192.0.2.1", chrome}].Signals)
	}
	if has("192.0.2.2", SigNoSecFetch) || has("192.0.2.2", SigHTTP1) {
		t.Errorf("row without TLS judged as HTTPS: %v", tr[[2]string{"192.0.2.2", chrome}].Signals)
	}
}

// A browser-like group merges every client on one network, so the detail
// block says how many of them showed each signal, strongest first.
func TestReasonCounts(t *testing.T) {
	s, err := logstore.Open(filepath.Join(t.TempDir(), "lawn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
	row := func(ip, headers, al string) logstore.Request {
		return logstore.Request{TsStart: now.Add(-time.Hour).UnixMilli(), IP: ip, ASN: 64999, ASNOrg: "NET", UserAgent: chrome,
			Method: "GET", Path: "/lawn/x", Depth: 0, IsViolation: true, Status: 200, HeaderNames: headers,
			AcceptLanguage: al, Proto: "HTTP/2.0", Scheme: "https"}
	}
	if err := s.InsertRequests(context.Background(), []logstore.Request{
		row("192.0.2.1", "Accept,User-Agent", ""),
		row("192.0.2.2", "Accept,Accept-Language,Sec-Fetch-Mode,User-Agent", "en"),
	}); err != nil {
		t.Fatal(err)
	}
	r, err := Collect(context.Background(), Options{DB: s.DB(), Since: 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil || len(r.Bots) != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	b := r.Bots[0]
	got := reasonSummary(b)
	want := SigNoSecFetch + " (1/2), " + SigNoAcceptLang + " (1/2), " + SigEntered + " (2/2)"
	if got != want {
		t.Errorf("summary:\n got %s\nwant %s", got, want)
	}
}
