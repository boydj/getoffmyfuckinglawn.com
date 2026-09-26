// Package attrib attributes clients: ASN lookup (iptoasn.com data), crawler
// user-agent matching, rDNS and vendor IP-range verification, and the
// asynchronous identity classifier (SPEC.md sections 3 and 7).
package attrib

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
)

// u128 is an IPv6 address as two big-endian halves.
type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) }

func (a u128) lessEq(b u128) bool { return !b.less(a) }

func addrU128(a netip.Addr) u128 {
	b := a.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

type asnRange4 struct {
	start, end uint32
	asn        uint32
	org        uint32 // index into ASNTable.orgs
}

type asnRange6 struct {
	start, end u128
	asn        uint32
	org        uint32
}

// ASNTable is an immutable in-memory IP range → ASN table.
type ASNTable struct {
	v4   []asnRange4
	v6   []asnRange6
	orgs []string
}

// LoadASN reads an iptoasn.com ip2asn-combined.tsv.gz file.
func LoadASN(path string) (*ASNTable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("attrib: asn: %w", err)
	}
	defer f.Close()
	return ParseASN(bufio.NewReaderSize(f, 1<<16))
}

// ParseASN parses gzipped ip2asn-combined TSV: range_start, range_end,
// AS_number, country_code, AS_description. Rows with AS 0 ("Not routed")
// and malformed rows are skipped; a stream with no usable rows is an error.
func ParseASN(r io.Reader) (*ASNTable, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("attrib: asn: gzip: %w", err)
	}
	defer zr.Close()
	t := &ASNTable{}
	orgIdx := make(map[string]uint32, 1<<16)
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var fields [5][]byte
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		n := 0
		for n < 4 {
			i := bytes.IndexByte(b, '\t')
			if i < 0 {
				break
			}
			fields[n], b = b[:i], b[i+1:]
			n++
		}
		if n < 4 {
			continue // malformed
		}
		fields[4] = b
		asn64, err := strconv.ParseUint(string(fields[2]), 10, 32)
		if err != nil || asn64 == 0 {
			continue
		}
		start, err1 := netip.ParseAddr(string(fields[0]))
		end, err2 := netip.ParseAddr(string(fields[1]))
		if err1 != nil || err2 != nil {
			continue
		}
		start, end = start.Unmap(), end.Unmap()
		if start.Is4() != end.Is4() || end.Less(start) {
			continue
		}
		org, ok := orgIdx[string(fields[4])] // no alloc for map lookup
		if !ok {
			org = uint32(len(t.orgs))
			s := string(fields[4])
			t.orgs = append(t.orgs, s)
			orgIdx[s] = org
		}
		if start.Is4() {
			s4, e4 := start.As4(), end.As4()
			t.v4 = append(t.v4, asnRange4{binary.BigEndian.Uint32(s4[:]), binary.BigEndian.Uint32(e4[:]), uint32(asn64), org})
		} else {
			t.v6 = append(t.v6, asnRange6{addrU128(start), addrU128(end), uint32(asn64), org})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("attrib: asn: line %d: %w", line, err)
	}
	if len(t.v4)+len(t.v6) == 0 {
		return nil, fmt.Errorf("attrib: asn: no routed ranges found")
	}
	// The file is sorted already; sorting is cheap insurance for Lookup.
	slices.SortFunc(t.v4, func(a, b asnRange4) int {
		switch {
		case a.start < b.start:
			return -1
		case a.start > b.start:
			return 1
		}
		return 0
	})
	slices.SortFunc(t.v6, func(a, b asnRange6) int {
		switch {
		case a.start.less(b.start):
			return -1
		case b.start.less(a.start):
			return 1
		}
		return 0
	})
	t.v4 = slices.Clip(t.v4)
	t.v6 = slices.Clip(t.v6)
	return t, nil
}

// Len returns the number of routed ranges loaded.
func (t *ASNTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.v4) + len(t.v6)
}

// Lookup returns the ASN and org for a. It does not allocate. A nil table
// or an address in no routed range returns ok=false.
func (t *ASNTable) Lookup(a netip.Addr) (asn uint32, org string, ok bool) {
	if t == nil || !a.IsValid() {
		return 0, "", false
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		x := binary.BigEndian.Uint32(b[:])
		// Find the last range with start <= x.
		lo, hi := 0, len(t.v4)
		for lo < hi {
			m := int(uint(lo+hi) >> 1)
			if t.v4[m].start <= x {
				lo = m + 1
			} else {
				hi = m
			}
		}
		if lo == 0 {
			return 0, "", false
		}
		r := &t.v4[lo-1]
		if x > r.end {
			return 0, "", false
		}
		return r.asn, t.orgs[r.org], true
	}
	x := addrU128(a)
	lo, hi := 0, len(t.v6)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if t.v6[m].start.lessEq(x) {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo == 0 {
		return 0, "", false
	}
	r := &t.v6[lo-1]
	if r.end.less(x) {
		return 0, "", false
	}
	return r.asn, t.orgs[r.org], true
}
