package server

import (
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name, remote, xff, want string
	}{
		{"direct no xff", "198.51.100.9:5555", "", "198.51.100.9"},
		{"untrusted peer ignores xff", "198.51.100.9:5555", "1.2.3.4", "198.51.100.9"},
		{"trusted peer uses xff", "127.0.0.1:4444", "203.0.113.7", "203.0.113.7"},
		{"rightmost untrusted wins", "127.0.0.1:4444", "6.6.6.6, 203.0.113.7", "203.0.113.7"},
		{"skip trusted hops", "127.0.0.1:4444", "203.0.113.7, 10.1.2.3", "203.0.113.7"},
		{"all trusted", "127.0.0.1:4444", "10.1.2.3", "10.1.2.3"},
		{"garbage hop", "127.0.0.1:4444", "junk", "127.0.0.1"},
		{"garbage after good", "127.0.0.1:4444", "junk, 10.0.0.5", "10.0.0.5"},
		{"v6 peer", "[::1]:80", "2001:db8::1", "2001:db8::1"},
		{"4in6 unmapped", "[::ffff:198.51.100.1]:80", "", "198.51.100.1"},
		{"xff with spaces", "127.0.0.1:1", "  203.0.113.8  ", "203.0.113.8"},
	}
	for _, c := range cases {
		got := ClientIP(c.remote, c.xff, trusted)
		if got.String() != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	if ClientIP("nonsense", "", trusted).IsValid() {
		t.Error("expected invalid addr")
	}
}
