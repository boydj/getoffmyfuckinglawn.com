package shame

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/bots"
)

// Observed traits appear on the group's pages as counts and plain-language
// facts, never with addresses, and add up into the ASN page.
func TestTraitsOnPages(t *testing.T) {
	s := standardFixture(t)
	opt := testOptions(t, s)
	fp := "t13i181000_85036bcba153_d41ae481755e"
	opt.Traits = map[[2]string]bots.ClientTraits{
		{"100.64.3.9", uaCurl}:           {Signals: []string{bots.SigNoAcceptLang, bots.SigFast, bots.SigHosting}, PerMinute: 42, JA4s: []string{fp}},
		{"2001:db8:abcd:12::1", uaNoise}: {Signals: []string{bots.SigNoAcceptLang}},
	}
	r := build(t, opt)
	var asn *Group
	for _, g := range r.Pages {
		if g.Slug == "as64520-eyeball-isp" {
			asn = g
		}
	}
	if asn == nil {
		t.Fatal("no EYEBALL-ISP page")
	}
	if asn.TraitClients != 2 || asn.Pace != 42 || len(asn.JA4s) != 1 || asn.JA4s[0].Clients != 1 {
		t.Errorf("group: clients %d pace %d ja4 %v", asn.TraitClients, asn.Pace, asn.JA4s)
	}
	// Ordered by weight, then clients: no-accept-language (2, 2 clients)
	// before fast-maze-walk (2, 1 client) before hosting (1).
	want := []TraitCount{{bots.SigNoAcceptLang, 2}, {bots.SigFast, 1}, {bots.SigHosting, 1}}
	if len(asn.Traits) != len(want) {
		t.Fatalf("traits %v", asn.Traits)
	}
	for i := range want {
		if asn.Traits[i] != want[i] {
			t.Errorf("trait %d: %v want %v", i, asn.Traits[i], want[i])
		}
	}
	root := filepath.Join(opt.PublicDir, "shame")
	html := read(t, filepath.Join(root, "org", "as64520-eyeball-isp", "index.html"))
	checkPage(t, "eyeball", html)
	for _, w := range []string{"Observed traits", "not a verdict", "the last 90 days", "2 clients here",
		"Sent no Accept-Language header", "30 or more maze pages within one minute", "X4BNet",
		"Fastest pace: 42 disallowed pages within one minute", fp} {
		if !strings.Contains(html, w) {
			t.Errorf("page lacks %q", w)
		}
	}
	for _, ip := range []string{"100.64.3.9", "2001:db8:abcd:12::1"} {
		if strings.Contains(html, ip) {
			t.Errorf("page leaks %s", ip)
		}
	}
	// Groups without trait data get no section.
	acme := read(t, filepath.Join(root, "org", "acme-ai", "index.html"))
	if strings.Contains(acme, "Observed traits") {
		t.Error("traits section without data")
	}
}

func TestTraitTextFactual(t *testing.T) {
	for _, sig := range append(bots.PublicSignals, bots.SigTLSLibrary+"python-requests") {
		txt := TraitText(sig)
		if txt == sig && sig != bots.SigTLSLibrary {
			t.Errorf("%s has no text", sig)
		}
		for _, w := range []string{"bot", "scraper", "malicious", "fake"} {
			if strings.Contains(strings.ToLower(txt), w) {
				t.Errorf("%s: %q makes a claim (%q)", sig, txt, w)
			}
		}
	}
	if !strings.Contains(TraitText(bots.SigTLSLibrary+"python-requests"), "identifying as python-requests") {
		t.Error("library text")
	}
}
