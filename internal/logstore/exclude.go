package logstore

import "net/netip"

// IPSet answers "is this logged IP inside one of these networks?" for
// report readers, which filter the operator's own traffic (config
// exclude_cidrs) at read time: the rows stay in the database, and changing
// the list applies to history too. Results are cached per IP string.
// A nil *IPSet contains nothing. Not safe for concurrent use.
type IPSet struct {
	nets  []netip.Prefix
	cache map[string]bool
}

// NewIPSet returns a set over nets, or nil when nets is empty.
func NewIPSet(nets []netip.Prefix) *IPSet {
	if len(nets) == 0 {
		return nil
	}
	return &IPSet{nets: nets, cache: map[string]bool{}}
}

// Has reports whether ip (as stored in the requests table) is in the set.
// Unparsable addresses are never in it.
func (s *IPSet) Has(ip string) bool {
	if s == nil {
		return false
	}
	if v, ok := s.cache[ip]; ok {
		return v
	}
	v := false
	if a, err := netip.ParseAddr(ip); err == nil {
		a = a.Unmap()
		for _, n := range s.nets {
			if n.Contains(a) {
				v = true
				break
			}
		}
	}
	s.cache[ip] = v
	return v
}

// HasBytes is Has for a sql.RawBytes value; the map lookup does not copy.
func (s *IPSet) HasBytes(ip []byte) bool {
	if s == nil {
		return false
	}
	if v, ok := s.cache[string(ip)]; ok {
		return v
	}
	return s.Has(string(ip))
}
