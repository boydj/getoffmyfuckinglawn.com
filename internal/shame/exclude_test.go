package shame

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// Operator networks vanish from every output, raw and rolled-up alike,
// while everyone else is unaffected.
func TestExcludeOperatorNetworks(t *testing.T) {
	s := standardFixture(t)
	addWellBehaved(t, s)
	opt := testOptions(t, s)
	dump := func(o Options) (*Report, string) {
		t.Helper()
		r, err := Collect(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return r, string(b)
	}
	before, all := dump(opt)
	gone := []string{
		"203.0.113.10/32", // verified violator (raw rows)
		"203.0.113.20/32", // verified, well-behaved (raw + daily_visits)
		"100.64.20.0/24",  // well-behaved, daily_visits only
		"100.64.21.0/24",  // violator, daily_aggregates only
	}
	for _, c := range gone {
		if !strings.Contains(all, c) {
			t.Fatalf("fixture lost %s; test needs updating", c)
		}
	}
	opt.Exclude = []netip.Prefix{
		netip.MustParsePrefix("203.0.113.10/32"), netip.MustParsePrefix("203.0.113.20/32"),
		netip.MustParsePrefix("100.64.20.0/24"), netip.MustParsePrefix("100.64.21.1/32"),
	}
	after, got := dump(opt)
	for _, c := range gone {
		if strings.Contains(got, c) {
			t.Errorf("excluded network %s still in the report", c)
		}
	}
	if !strings.Contains(got, "100.64.9.0/24") || len(after.WellBehaved) >= len(before.WellBehaved) {
		t.Errorf("exclusion should only remove the listed networks: %d -> %d well-behaved groups",
			len(before.WellBehaved), len(after.WellBehaved))
	}
}
