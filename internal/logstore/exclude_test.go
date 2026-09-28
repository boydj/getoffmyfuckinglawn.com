package logstore

import (
	"net/netip"
	"testing"
)

func TestIPSet(t *testing.T) {
	var none *IPSet
	if none.Has("203.0.113.1") || NewIPSet(nil) != nil {
		t.Fatal("nil set must contain nothing")
	}
	s := NewIPSet([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8:1::/48")})
	for ip, want := range map[string]bool{
		"203.0.113.9": true, "::ffff:203.0.113.9": true, "203.0.114.1": false,
		"2001:db8:1:2::5": true, "2001:db8:2::1": false, "garbage": false, "": false,
	} {
		if s.Has(ip) != want || s.HasBytes([]byte(ip)) != want {
			t.Errorf("%q: want %v", ip, want)
		}
	}
}
