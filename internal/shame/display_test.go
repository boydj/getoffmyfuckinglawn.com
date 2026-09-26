package shame

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

var allStatuses = []string{
	logstore.StatusVerified, logstore.StatusSpoofed, logstore.StatusUnverifiable, logstore.StatusAnonymous,
	"", "Verified", "VERIFIED", "verified ", " verified", "unclassified", "rdns", "ip_range", "none", "true", "1",
}

var ipInputs = []string{
	// IPv4
	"1.2.3.4", "8.8.8.8", "100.64.3.9", "192.168.1.1", "10.0.0.1", "203.0.113.255", "0.0.0.0",
	"255.255.255.255", "127.0.0.1", "198.51.100.77",
	// IPv6
	"2001:db8::1", "2001:db8:abcd:12::1", "fe80::1", "fe80::1%eth0", "::1", "::",
	"2a03:2880:f000:1::face:b00c", "2600:1f18:ffff:ffff:ffff:ffff:ffff:ffff",
	// IPv4-mapped / compatible IPv6
	"::ffff:1.2.3.4", "::ffff:203.0.113.10", "::ffff:c000:0280", "64:ff9b::192.0.2.33",
	// garbage
	"", " ", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.4/32", "1.2.3.4:80",
	"[2001:db8::1]", "2001:db8::1/128", "example.com", "not-an-ip", "1.2.3.4 ", " 1.2.3.4",
	"::ffff:1.2.3.4.5", "2001:db8:::1", "unknown", "<script>",
}

func TestDisplayCIDRNeverIndividualForNonVerified(t *testing.T) {
	for _, st := range allStatuses {
		for _, ip := range ipInputs {
			got := DisplayCIDR(ip, st)
			if got == "" {
				continue
			}
			if got == ip || got == strings.TrimSpace(ip) {
				t.Errorf("DisplayCIDR(%q,%q) echoed raw input", ip, st)
			}
			p, err := netip.ParsePrefix(got)
			if err != nil {
				t.Errorf("DisplayCIDR(%q,%q)=%q: not a CIDR: %v", ip, st, got, err)
				continue
			}
			if p != p.Masked() {
				t.Errorf("DisplayCIDR(%q,%q)=%q: host bits set", ip, st, got)
			}
			if st == logstore.StatusVerified {
				if p.Bits() != p.Addr().BitLen() {
					t.Errorf("verified DisplayCIDR(%q)=%q: want single address", ip, got)
				}
				continue
			}
			if p.Addr().Is4() && p.Bits() > 24 || !p.Addr().Is4() && p.Bits() > 48 {
				t.Errorf("DisplayCIDR(%q,%q)=%q: narrower than /24 or /48", ip, st, got)
			}
			if strings.HasSuffix(got, "/32") || strings.HasSuffix(got, "/128") {
				t.Errorf("DisplayCIDR(%q,%q)=%q: individual address for non-verified", ip, st, got)
			}
		}
	}
}

func TestDisplayCIDRNeverIndividualGenerated(t *testing.T) {
	// A few thousand generated v4 and v6 addresses, every non-verified status.
	for i := 0; i < 2000; i++ {
		v4 := fmt.Sprintf("%d.%d.%d.%d", (i*7)%256, (i*13)%256, (i*31)%256, (i*97)%256)
		v6 := fmt.Sprintf("2001:db8:%x:%x:%x::%x", i, i*3, i*5, i*7)
		m6 := "::ffff:" + v4
		for _, st := range allStatuses[1:] {
			for _, ip := range []string{v4, v6, m6} {
				got := DisplayCIDR(ip, st)
				if strings.HasSuffix(got, "/32") || strings.HasSuffix(got, "/128") || !publishable(got, st) {
					t.Fatalf("DisplayCIDR(%q,%q)=%q", ip, st, got)
				}
			}
		}
	}
}

func TestDisplayCIDRExamples(t *testing.T) {
	cases := []struct{ ip, st, want string }{
		{"203.0.113.10", "verified", "203.0.113.10/32"},
		{"203.0.113.10", "spoofed", "203.0.113.0/24"},
		{"203.0.113.10", "unverifiable", "203.0.113.0/24"},
		{"203.0.113.10", "anonymous", "203.0.113.0/24"},
		{"203.0.113.10", "", "203.0.113.0/24"},
		{"::ffff:203.0.113.10", "verified", "203.0.113.10/32"},
		{"::ffff:203.0.113.10", "anonymous", "203.0.113.0/24"},
		{"2001:db8:abcd:12::1", "verified", "2001:db8:abcd:12::1/128"},
		{"2001:db8:abcd:12::1", "anonymous", "2001:db8:abcd::/48"},
		{"fe80::1%eth0", "spoofed", "fe80::/48"},
		{"fe80::1%eth0", "verified", "fe80::1/128"},
		{"garbage", "verified", ""},
		{"garbage", "anonymous", ""},
		{"1.2.3.4/32", "anonymous", ""},
		{"", "verified", ""},
	}
	for _, c := range cases {
		if got := DisplayCIDR(c.ip, c.st); got != c.want {
			t.Errorf("DisplayCIDR(%q,%q)=%q want %q", c.ip, c.st, got, c.want)
		}
	}
}

func TestPublishable(t *testing.T) {
	cases := []struct {
		cidr, st string
		want     bool
	}{
		{"1.2.3.4/32", "verified", true},
		{"1.2.3.4/32", "spoofed", false},
		{"1.2.3.0/24", "spoofed", true},
		{"1.2.3.0/25", "anonymous", false},
		{"2001:db8::/48", "anonymous", true},
		{"2001:db8::/64", "anonymous", false},
		{"2001:db8::1/128", "unverifiable", false},
		{"nope", "verified", false},
	}
	for _, c := range cases {
		if got := publishable(c.cidr, c.st); got != c.want {
			t.Errorf("publishable(%q,%q)=%v", c.cidr, c.st, got)
		}
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Acme AI":                 "acme-ai",
		"  --Foo__Bar!! ":         "foo-bar",
		"":                        "unknown",
		"!!!":                     "unknown",
		"Ünïcode Crawler 2":       "n-code-crawler-2",
		strings.Repeat("ab", 100): strings.Repeat("ab", 32),
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q)=%q want %q", in, got, want)
		}
	}
	for _, in := range []string{"a b", "../../etc", "x/y", "<b>", strings.Repeat("-a", 80)} {
		s := Slugify(in)
		if len(s) > 64 || strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
			t.Errorf("Slugify(%q)=%q not a clean slug", in, s)
		}
	}
	if got := asnSlug(15169, "GOOGLE LLC"); got != "as15169-google-llc" {
		t.Errorf("asnSlug=%q", got)
	}
	if got := asnSlug(0, ""); got != "unknown-asn" {
		t.Errorf("asnSlug(0)=%q", got)
	}
}

func TestLabelsAndFormatting(t *testing.T) {
	if StatusLabel("verified") != "verified" || StatusLabel("spoofed") != "spoofed UA" ||
		StatusLabel("unverifiable") != "claimed, unverifiable" || StatusLabel("anonymous") != "anonymous" ||
		StatusLabel("") != "anonymous" || StatusLabel("VERIFIED") != "anonymous" {
		t.Error("status labels")
	}
	if statusClass("weird") != "anonymous" {
		t.Error("statusClass fallback")
	}
	if ASNLabel(64500, "ACME") != "AS64500 ACME" || ASNLabel(64500, "") != "AS64500" || ASNLabel(0, "") != "unknown ASN" {
		t.Error("ASNLabel")
	}
	if fmtHours(5_400_000) != "1.50" || fmtBytes(999) != "999 B" || fmtBytes(1500) != "1.5 kB" || fmtBytes(2_500_000) != "2.5 MB" {
		t.Errorf("fmt: %s %s %s %s", fmtHours(5_400_000), fmtBytes(999), fmtBytes(1500), fmtBytes(2_500_000))
	}
	if fmtTime(0) != "-" || fmtTime(1_700_000_000_000) != "2023-11-14 22:13Z" {
		t.Errorf("fmtTime %s", fmtTime(1_700_000_000_000))
	}
	if truncate("héllo world", 5) != "héll…" || truncate("abc", 5) != "abc" {
		t.Errorf("truncate %q", truncate("héllo world", 5))
	}
	for p, want := range map[string]bool{
		"/lawn/abc":                         true,
		"/lawn/archive/2019/ABCD2345":       true,
		"/lawn/":                            false,
		"/lawn/<script>":                    false,
		"/lawn/a b":                         false,
		"/lawn/x?q=1":                       false,
		"/other/x":                          false,
		"/lawn/" + strings.Repeat("a", 200): false,
	} {
		if samplePathOK([]byte(p)) != want {
			t.Errorf("samplePathOK(%q) != %v", p, want)
		}
	}
	if comparePrefix("10.0.0.0/24", "9.0.0.0/24") <= 0 || comparePrefix("1.0.0.0/24", "::/48") >= 0 {
		t.Error("comparePrefix order")
	}
}
