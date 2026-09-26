package server

import (
	"net/netip"
	"strings"
)

// ClientIP returns the real client address. X-Forwarded-For is honoured
// only when the direct peer is a trusted proxy; then the right-most hop that
// is not itself a trusted proxy wins (left-most entries are client-supplied
// and forgeable). Returns the zero Addr if remoteAddr is unparseable.
func ClientIP(remoteAddr, xff string, trusted []netip.Prefix) netip.Addr {
	peer := parseHostAddr(remoteAddr)
	if !peer.IsValid() || xff == "" || !inPrefixes(peer, trusted) {
		return peer
	}
	for xff != "" {
		var hop string
		if i := strings.LastIndexByte(xff, ','); i >= 0 {
			hop, xff = xff[i+1:], xff[:i]
		} else {
			hop, xff = xff, ""
		}
		a, err := netip.ParseAddr(strings.TrimSpace(hop))
		if err != nil {
			// Garbage in the chain: stop trusting it and use the last good peer.
			return peer
		}
		a = a.Unmap()
		if !inPrefixes(a, trusted) {
			return a
		}
		peer = a
	}
	return peer
}

func parseHostAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
