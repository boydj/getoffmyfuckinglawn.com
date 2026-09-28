package shame

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// Onion visitors appear as one "Tor onion service" network, on the wall and
// the well-behaved page, and no circuit id or pseudo-ASN is ever published.
func TestOnionOnTheWall(t *testing.T) {
	s := standardFixture(t)
	var f fx
	on, org := logstore.OnionASN, logstore.OnionOrg
	// Two circuits of one scraper walk into the maze; a claimed Googlebot
	// over Tor is unverifiable; a third circuit reads robots.txt and leaves.
	f.lawn("fc00:dead:beef:4dad::a:1", "OnionScraper/1.0", on, org, time.Hour, time.Minute, 2, 100, "/lawn/OOOO")
	f.lawn("fc00:dead:beef:4dad::a:2", "OnionScraper/1.0", on, org, 50*time.Minute, time.Minute, 3, 100, "/lawn/PPPP")
	f.lawn("fc00:dead:beef:4dad::b:1", uaAcme, on, org, 40*time.Minute, time.Minute, 1, 100, "/lawn/QQQQ")
	f.id("fc00:dead:beef:4dad::b:1", uaAcme, "Acme AI", logstore.StatusUnverifiable)
	f.robots("fc00:dead:beef:4dad::c:1", "PoliteOnion/1.0", on, org, 30*time.Minute)
	f.load(t, s)
	opt := testOptions(t, s)
	r := build(t, opt)

	var onionASN *Group
	for _, g := range r.ASNs {
		if g.ASN == on {
			onionASN = g
		}
	}
	if onionASN == nil || onionASN.Name != "Tor onion service" || onionASN.Slug != "tor-onion-service" {
		t.Fatalf("onion network group: %+v", onionASN)
	}
	if len(onionASN.CIDRs) != 0 {
		t.Errorf("onion group must publish no CIDRs: %v", onionASN.CIDRs)
	}
	for _, c := range r.Blocklist {
		if strings.HasPrefix(c, "fc00:") {
			t.Errorf("blocklist has a circuit: %s", c)
		}
	}
	// Nothing written anywhere mentions a circuit or the pseudo-ASN number.
	root := filepath.Join(opt.PublicDir, "shame")
	seen := false
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		txt := string(b)
		for _, bad := range []string{"fc00:", "4294967295"} {
			if strings.Contains(txt, bad) {
				t.Errorf("%s publishes %q", p, bad)
			}
		}
		seen = seen || strings.Contains(txt, "Tor onion service")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("no page names the Tor onion service")
	}
	if _, err := os.Stat(filepath.Join(root, "org", "tor-onion-service", "index.html")); err != nil {
		t.Errorf("onion network page: %v", err)
	}
}

func TestDisplayCIDROnion(t *testing.T) {
	for _, st := range []string{logstore.StatusVerified, logstore.StatusAnonymous, ""} {
		if c := DisplayCIDR("fc00:dead:beef:4dad::12:34", st); c != "" {
			t.Errorf("status %q: circuit shown as %q", st, c)
		}
	}
	if publishable("fc00:dead:beef:4dad::/96", logstore.StatusVerified) || publishable("fc00:dead::/32", logstore.StatusAnonymous) {
		t.Error("prefixes covering circuits must never be publishable")
	}
}
