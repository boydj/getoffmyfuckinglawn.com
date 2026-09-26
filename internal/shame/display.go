package shame

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// DisplayCIDR applies the SPEC.md section 8 IP display rule. Only a client
// whose identity status is exactly "verified" (a vendor-verified corporate
// crawler) is shown as its individual address (/32 or /128). Every other
// status, including unknown or empty ones, is shown as the enclosing /24
// (IPv4) or /48 (IPv6). Unparseable input yields "" and never echoes the raw
// string. IPv4-mapped IPv6 addresses are treated as IPv4.
func DisplayCIDR(ip string, status string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.IsValid() {
		return ""
	}
	a = a.WithZone("").Unmap()
	if status == logstore.StatusVerified {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// publishable reports whether a prefix produced for status obeys the display
// rule. It is a belt-and-braces check applied before anything is written.
func publishable(cidr, status string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	if status == logstore.StatusVerified {
		return true
	}
	if p.Addr().Is4() {
		return p.Bits() <= 24
	}
	return p.Bits() <= 48
}

// comparePrefix orders CIDR strings numerically (IPv4 before IPv6, then
// address, then prefix length). Unparseable strings sort last, lexically.
func comparePrefix(a, b string) int {
	pa, ea := netip.ParsePrefix(a)
	pb, eb := netip.ParsePrefix(b)
	switch {
	case ea != nil && eb != nil:
		return strings.Compare(a, b)
	case ea != nil:
		return 1
	case eb != nil:
		return -1
	}
	if c := pa.Addr().Compare(pb.Addr()); c != 0 {
		return c
	}
	return pa.Bits() - pb.Bits()
}

// Slugify turns a display name into a lowercase [a-z0-9-] URL segment. The
// result is never empty and at most 64 bytes.
func Slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
		if b.Len() >= 64 {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 64 {
		out = strings.Trim(out[:64], "-")
	}
	if out == "" {
		return "unknown"
	}
	return out
}

// ASNLabel is the display name of an autonomous system.
func ASNLabel(asn uint32, org string) string {
	switch {
	case asn == 0 && org == "":
		return "unknown ASN"
	case asn == 0:
		return org
	case org == "":
		return "AS" + strconv.FormatUint(uint64(asn), 10)
	}
	return "AS" + strconv.FormatUint(uint64(asn), 10) + " " + org
}

func asnSlug(asn uint32, org string) string {
	if asn == 0 {
		return "unknown-asn"
	}
	s := "as" + strconv.FormatUint(uint64(asn), 10)
	if org != "" {
		s += "-" + Slugify(org)
	}
	return strings.Trim(s, "-")
}

// StatusLabel is the badge text for an identity status. Unknown statuses
// render as anonymous so nothing is ever shown as confirmed by accident.
func StatusLabel(status string) string {
	switch status {
	case logstore.StatusVerified:
		return "verified"
	case logstore.StatusSpoofed:
		return "spoofed UA"
	case logstore.StatusUnverifiable:
		return "claimed, unverifiable"
	}
	return "anonymous"
}

func statusClass(status string) string {
	switch status {
	case logstore.StatusVerified, logstore.StatusSpoofed, logstore.StatusUnverifiable:
		return status
	}
	return logstore.StatusAnonymous
}

// fmtHours renders milliseconds as hours with two decimals.
func fmtHours(ms int64) string {
	return strconv.FormatFloat(float64(ms)/3.6e6, 'f', 2, 64)
}

// fmtBytes renders a byte count with SI units.
func fmtBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

// fmtTime renders a unix-ms timestamp as a compact UTC time; 0 is "-".
func fmtTime(ms int64) string {
	if ms <= 0 {
		return "-"
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04Z")
}

func rfc3339(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// truncate shortens s to at most n runes, appending an ellipsis if cut.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for j := range s {
		if i == n-1 {
			return s[:j] + "…"
		}
		i++
	}
	return s
}

// samplePathOK limits sample paths to our own maze URL shape so a client
// cannot get arbitrary text published by requesting a crafted /lawn/ URL.
func samplePathOK(p []byte) bool {
	if len(p) < 7 || len(p) > 120 || string(p[:6]) != "/lawn/" {
		return false
	}
	for _, c := range p {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '/', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}
