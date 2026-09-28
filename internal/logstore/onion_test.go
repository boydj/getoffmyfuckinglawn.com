package logstore

import (
	"net/netip"
	"testing"
)

func TestOnion(t *testing.T) {
	for ip, want := range map[string]bool{
		"fc00:dead:beef:4dad::ffff:ffff": true, "fc00:dead:beef:4dad::1": true,
		"fc00:dead:beef:4dae::1": false, "fc00::1": false, "203.0.113.1": false, "junk": false,
	} {
		if IsOnionIP(ip) != want {
			t.Errorf("IsOnionIP(%q) != %v", ip, want)
		}
		if a, err := netip.ParseAddr(ip); err == nil && IsOnion(a) != want {
			t.Errorf("IsOnion(%q) != %v", ip, want)
		}
	}
	for _, c := range []struct {
		asn       uint32
		org, want string
	}{
		{OnionASN, "anything", "Tor onion service"}, {0, "", "unknown ASN"}, {0, "Some Org", "Some Org"},
		{64500, "", "AS64500"}, {64500, "EXAMPLE", "AS64500 EXAMPLE"}, {4294967294, "", "AS4294967294"},
	} {
		if got := NetworkLabel(c.asn, c.org, "unknown ASN"); got != c.want {
			t.Errorf("NetworkLabel(%d, %q) = %q", c.asn, c.org, got)
		}
	}
}
