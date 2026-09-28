package logstore

import (
	"net/netip"
	"strconv"
)

// Visitors of the Tor onion mirror have no client address. tor's
// "HiddenServiceExportCircuitID haproxy" (deploy/torrc) instead sends a PROXY
// header whose source is fc00:dead:beef:4dad::<32-bit circuit id> (tor(1)),
// and Caddy passes that on as X-Forwarded-For. Those pseudo-addresses are
// stored as the request IP, so sessions and per-client limits work per
// circuit, but they are never published and never looked up in DNS.
var OnionNet = netip.MustParsePrefix("fc00:dead:beef:4dad::/96")

// Onion requests are logged under a pseudo-network so every report groups
// them without special cases: AS4294967295 is reserved (RFC 7300) and never
// routed, so it cannot collide with a real network. Labels print OnionOrg
// alone, without the number.
const (
	OnionASN uint32 = 4294967295
	OnionOrg        = "Tor onion service"
)

// IsOnion reports whether a (from X-Forwarded-For) is a Tor circuit.
func IsOnion(a netip.Addr) bool { return OnionNet.Contains(a) }

// IsOnionIP is IsOnion for an address as stored in the requests table.
func IsOnionIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && OnionNet.Contains(a)
}

// NetworkLabel is the display name of a network: "AS64500 EXAMPLE-NET",
// "AS64500", OnionOrg for onion traffic, or unknown when there is no ASN.
func NetworkLabel(asn uint32, org, unknown string) string {
	switch {
	case asn == OnionASN:
		return OnionOrg
	case asn == 0 && org == "":
		return unknown
	case asn == 0:
		return org
	case org == "":
		return "AS" + strconv.FormatUint(uint64(asn), 10)
	}
	return "AS" + strconv.FormatUint(uint64(asn), 10) + " " + org
}
