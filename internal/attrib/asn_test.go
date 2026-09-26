package attrib

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func gz(t testing.TB, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Fixture in the ip2asn-combined format. Values are illustrative test data,
// not real routing information.
const asnFixture = "1.0.0.0\t1.0.0.255\t64496\tUS\tEXAMPLE-ONE\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
	"1.0.4.0\t1.0.7.255\t64497\tAU\tEXAMPLE-TWO Pty Ltd\n" +
	"this line is garbage\n" +
	"8.8.8.0\t8.8.8.255\t64498\tUS\tEXAMPLE-THREE\n" +
	"9.9.9.9\t9.9.9.1\t64499\tUS\tBACKWARDS\n" + // end < start: skipped
	"2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64498\tUS\tEXAMPLE-THREE\n" +
	"2001:db9::\t2001:db9::ff\t64496\tUS\tEXAMPLE-ONE\n" +
	"::\t2001:db7:ffff:ffff:ffff:ffff:ffff:ffff\t0\tNone\tNot routed\n"

func TestParseASN(t *testing.T) {
	tab, err := ParseASN(bytes.NewReader(gz(t, asnFixture)))
	if err != nil {
		t.Fatal(err)
	}
	if tab.Len() != 5 {
		t.Fatalf("Len=%d", tab.Len())
	}
	if len(tab.orgs) != 3 {
		t.Fatalf("orgs not deduplicated: %q", tab.orgs)
	}
	for _, c := range []struct {
		ip  string
		asn uint32
		org string
	}{
		{"1.0.0.0", 64496, "EXAMPLE-ONE"},
		{"1.0.0.255", 64496, "EXAMPLE-ONE"},
		{"1.0.2.1", 0, ""}, // not routed
		{"1.0.5.9", 64497, "EXAMPLE-TWO Pty Ltd"},
		{"8.8.8.8", 64498, "EXAMPLE-THREE"},
		{"::ffff:8.8.8.8", 64498, "EXAMPLE-THREE"}, // 4in6
		{"8.8.9.0", 0, ""},
		{"0.0.0.1", 0, ""},
		{"255.255.255.255", 0, ""},
		{"9.9.9.5", 0, ""},
		{"2001:db8::1", 64498, "EXAMPLE-THREE"},
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 64498, "EXAMPLE-THREE"},
		{"2001:db9::ff", 64496, "EXAMPLE-ONE"},
		{"2001:db9::100", 0, ""},
		{"::1", 0, ""},
		{"ffff::1", 0, ""},
	} {
		asn, org, ok := tab.Lookup(netip.MustParseAddr(c.ip))
		if ok != (c.asn != 0) || asn != c.asn || org != c.org {
			t.Errorf("%s: got %d %q %v", c.ip, asn, org, ok)
		}
	}
	if _, _, ok := tab.Lookup(netip.Addr{}); ok {
		t.Error("zero addr found")
	}
}

func TestASNNilAndErrors(t *testing.T) {
	var tab *ASNTable
	if _, _, ok := tab.Lookup(netip.MustParseAddr("1.2.3.4")); ok {
		t.Fatal("nil table found something")
	}
	if tab.Len() != 0 {
		t.Fatal("nil Len")
	}
	if _, err := LoadASN(filepath.Join(t.TempDir(), "missing.tsv.gz")); err == nil {
		t.Fatal("missing file: no error")
	}
	if _, err := ParseASN(strings.NewReader("not gzip")); err == nil {
		t.Fatal("non-gzip: no error")
	}
	if _, err := ParseASN(bytes.NewReader(gz(t, "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n"))); err == nil {
		t.Fatal("empty table: no error")
	}
}

func TestASNLookupNoAlloc(t *testing.T) {
	tab, err := ParseASN(bytes.NewReader(gz(t, asnFixture)))
	if err != nil {
		t.Fatal(err)
	}
	a4, a6 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:db8::1")
	if n := testing.AllocsPerRun(1000, func() {
		tab.Lookup(a4)
		tab.Lookup(a6)
	}); n != 0 {
		t.Fatalf("Lookup allocates %v", n)
	}
}

// synthASN generates n rows alternating IPv4 and IPv6 with ~n/8 distinct
// orgs, roughly the shape of the real ~500k-row file.
func synthASN(n int) string {
	var sb strings.Builder
	sb.Grow(n * 60)
	v4, v6 := n*6/10, n-n*6/10
	for i := range v4 {
		a := uint32(0x01000000) + uint32(i)*256
		fmt.Fprintf(&sb, "%d.%d.%d.0\t%d.%d.%d.255\t%d\tUS\tORG-%d\n",
			a>>24, a>>16&255, a>>8&255, a>>24, a>>16&255, a>>8&255, 64512+i%1000, i/8%(n/8))
	}
	for i := range v6 {
		fmt.Fprintf(&sb, "2001:%x:%x::\t2001:%x:%x:ffff:ffff:ffff:ffff:ffff\t%d\tDE\tORG6-%d\n",
			i>>16, i&0xffff, i>>16, i&0xffff, 64512+i%1000, i/8%(n/8))
	}
	return sb.String()
}

// BenchmarkParseASN500k reports load time and retained heap for a
// synthetic 500k-row file (the real one is ~500k rows).
func BenchmarkParseASN500k(b *testing.B) {
	data := gz(b, synthASN(500_000))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	var tab *ASNTable
	for b.Loop() {
		var err error
		if tab, err = ParseASN(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	runtime.KeepAlive(tab)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	tab, _ = ParseASN(bytes.NewReader(data))
	el := time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&after)
	b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), "retainedMB")
	b.ReportMetric(el.Seconds(), "loadSec")
	runtime.KeepAlive(tab)
}

func BenchmarkLookup(b *testing.B) {
	tab, err := ParseASN(bytes.NewReader(gz(b, synthASN(500_000))))
	if err != nil {
		b.Fatal(err)
	}
	addrs := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("3.100.7.1"),
		netip.MustParseAddr("2001:3:1::1"), netip.MustParseAddr("192.0.2.1"),
	}
	b.ReportAllocs()
	b.ResetTimer()
	i := 0
	for b.Loop() {
		tab.Lookup(addrs[i&3])
		i++
	}
}
