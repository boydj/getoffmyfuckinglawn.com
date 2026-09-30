package attrib

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// ---- prefix sets -----------------------------------------------------------

type span struct{ start, end u128 }

// prefixSet is a sorted, merged set of address spans. IPv4 is stored in the
// IPv4-mapped IPv6 space so one table serves both families.
type prefixSet []span

func hostMask(bits int) u128 {
	n := 128 - bits
	switch {
	case n <= 0:
		return u128{}
	case n >= 128:
		return u128{math.MaxUint64, math.MaxUint64}
	case n >= 64:
		return u128{uint64(1)<<(n-64) - 1, math.MaxUint64}
	default:
		return u128{0, uint64(1)<<n - 1}
	}
}

func prefixSpan(p netip.Prefix) span {
	p = p.Masked()
	bits := p.Bits()
	a := p.Addr()
	if a.Is4() {
		bits += 96
	}
	s := addrU128(a) // As16 maps IPv4 into ::ffff:0:0/96
	m := hostMask(bits)
	return span{s, u128{s.hi | m.hi, s.lo | m.lo}}
}

func newPrefixSet(pfx []netip.Prefix) prefixSet {
	if len(pfx) == 0 {
		return nil
	}
	spans := make([]span, 0, len(pfx))
	for _, p := range pfx {
		if p.IsValid() {
			spans = append(spans, prefixSpan(p))
		}
	}
	slices.SortFunc(spans, func(a, b span) int {
		switch {
		case a.start.less(b.start):
			return -1
		case b.start.less(a.start):
			return 1
		}
		return 0
	})
	out := spans[:0]
	for _, s := range spans {
		if n := len(out); n > 0 && s.start.lessEq(out[n-1].end) {
			if out[n-1].end.less(s.end) {
				out[n-1].end = s.end
			}
			continue
		}
		out = append(out, s)
	}
	return prefixSet(slices.Clip(out))
}

// contains reports whether a is inside the set. It does not allocate.
func (ps prefixSet) contains(a netip.Addr) bool {
	if len(ps) == 0 || !a.IsValid() {
		return false
	}
	x := addrU128(a.Unmap())
	lo, hi := 0, len(ps)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if ps[m].start.lessEq(x) {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo > 0 && x.lessEq(ps[lo-1].end)
}

// ---- parsing ---------------------------------------------------------------

// ParsePrefixes parses a vendor IP list. JSON documents are walked in full
// and every string value that parses as a CIDR is collected (covers the
// {"prefixes":[{"ipv4Prefix":...}]} style and any nesting). A JSON list
// with no CIDRs at all is taken to list bare addresses instead (some
// vendors publish {"ips": ["192.0.2.1", ...]}), each one a /32 or /128. Anything else
// is treated as text: one CIDR (or bare address) per line, '#' comments and
// blank lines ignored. An input yielding no prefixes is an error, so a
// broken download never replaces a good list.
func ParsePrefixes(b []byte) ([]netip.Prefix, error) {
	t := bytes.TrimSpace(b)
	var out []netip.Prefix
	if len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		var doc any
		if err := json.Unmarshal(t, &doc); err != nil {
			return nil, fmt.Errorf("attrib: ranges: json: %w", err)
		}
		out = walkJSON(doc, out, false)
		if len(out) == 0 {
			out = walkJSON(doc, out, true)
		}
	} else {
		sc := bufio.NewScanner(bytes.NewReader(t))
		sc.Buffer(make([]byte, 0, 4096), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if p, ok := parsePrefixOrAddr(line); ok {
				out = append(out, p)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("attrib: ranges: %w", err)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("attrib: ranges: no prefixes found")
	}
	return out, nil
}

func parsePrefixOrAddr(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// walkJSON collects the CIDR strings in v, or with bare the bare addresses
// too. Bare addresses are only used when a document has no CIDR at all: in
// a CIDR list, a lone address is more likely metadata.
func walkJSON(v any, out []netip.Prefix, bare bool) []netip.Prefix {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			out = walkJSON(e, out, bare)
		}
	case []any:
		for _, e := range x {
			out = walkJSON(e, out, bare)
		}
	case string:
		s := strings.TrimSpace(x)
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		} else if bare {
			if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	return out
}

// ---- fetching --------------------------------------------------------------

// Fetcher downloads a URL. Tests inject fakes; nil means HTTPFetcher.
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// maxRangeBody caps a vendor list download.
const maxRangeBody = 16 << 20

// HTTPFetcher returns a Fetcher using a net/http client with timeout.
func HTTPFetcher(timeout time.Duration) Fetcher {
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "lawn-range-refresh/1 (+https://getoffmyfuckinglawn.com/)")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxRangeBody+1))
		if err != nil {
			return nil, err
		}
		if len(b) > maxRangeBody {
			return nil, fmt.Errorf("GET %s: body over %d bytes", url, maxRangeBody)
		}
		return b, nil
	}
}

// ---- store -----------------------------------------------------------------

// RangeOptions configures a RangeStore.
type RangeOptions struct {
	Crawlers []Crawler
	CacheDir string        // "" disables the on-disk cache
	MaxAge   time.Duration // refetch lists older than this (default 24h)
	Fetcher  Fetcher       // nil = HTTPFetcher(30s)
	Now      func() time.Time
}

type rangeList struct {
	set     prefixSet
	n       int // prefixes before merging, for reporting
	fetched time.Time
}

// RangeStore holds vendor-published IP lists for ip_ranges crawlers,
// cached on disk and refreshed when older than MaxAge.
type RangeStore struct {
	cacheDir string
	maxAge   time.Duration
	fetch    Fetcher
	now      func() time.Time

	refreshMu sync.Mutex // one refresh at a time
	mu        sync.RWMutex
	urls      []string
	lists     map[string]*rangeList
}

// NewRangeStore builds a store and loads any cached lists from CacheDir.
// It never touches the network; call Refresh or RefreshLoop for that.
func NewRangeStore(opt RangeOptions) *RangeStore {
	r := &RangeStore{
		cacheDir: opt.CacheDir,
		maxAge:   opt.MaxAge,
		fetch:    opt.Fetcher,
		now:      opt.Now,
		lists:    map[string]*rangeList{},
	}
	if r.maxAge <= 0 {
		r.maxAge = 24 * time.Hour
	}
	if r.fetch == nil {
		r.fetch = HTTPFetcher(30 * time.Second)
	}
	if r.now == nil {
		r.now = time.Now
	}
	r.SetCrawlers(opt.Crawlers)
	return r
}

// SetCrawlers replaces the tracked URL set (e.g. after a SIGHUP reload),
// loading newly referenced lists from the cache and forgetting dropped ones.
func (r *RangeStore) SetCrawlers(crawlers []Crawler) {
	urls := RangeURLs(crawlers)
	loaded := map[string]*rangeList{}
	r.mu.RLock()
	for _, u := range urls {
		if l, ok := r.lists[u]; ok {
			loaded[u] = l
		}
	}
	r.mu.RUnlock()
	for _, u := range urls {
		if _, ok := loaded[u]; ok {
			continue
		}
		if l, err := r.loadCache(u); err == nil {
			loaded[u] = l
		}
	}
	r.mu.Lock()
	r.urls = urls
	r.lists = loaded
	r.mu.Unlock()
}

// Contains reports whether a is in the list fetched from url. known is
// false when no copy of that list is available (never fetched, no cache),
// in which case the answer is meaningless.
func (r *RangeStore) Contains(url string, a netip.Addr) (in, known bool) {
	if r == nil {
		return false, false
	}
	r.mu.RLock()
	l := r.lists[url]
	r.mu.RUnlock()
	if l == nil {
		return false, false
	}
	return l.set.contains(a), true
}

// Fetched returns when the list for url was last fetched.
func (r *RangeStore) Fetched(url string) (time.Time, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if l := r.lists[url]; l != nil {
		return l.fetched, true
	}
	return time.Time{}, false
}

// Refresh fetches every tracked list whose copy is missing or older than
// MaxAge. A failed fetch keeps the previous copy; errors are joined.
func (r *RangeStore) Refresh(ctx context.Context) error { return r.refresh(ctx, false) }

// RefreshAll fetches every tracked list regardless of age (lawn
// verify-refresh). A failed fetch keeps the previous copy.
func (r *RangeStore) RefreshAll(ctx context.Context) error { return r.refresh(ctx, true) }

func (r *RangeStore) refresh(ctx context.Context, force bool) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	r.mu.RLock()
	urls := slices.Clone(r.urls)
	r.mu.RUnlock()
	var errs []error
	for _, u := range urls {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		now := r.now()
		if !force {
			if t, ok := r.Fetched(u); ok && now.Sub(t) < r.maxAge {
				continue
			}
		}
		b, err := r.fetch(ctx, u)
		if err != nil {
			errs = append(errs, fmt.Errorf("attrib: ranges: fetch %s: %w", u, err))
			continue
		}
		pfx, err := ParsePrefixes(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("attrib: ranges: %s: %w", u, err))
			continue
		}
		l := &rangeList{set: newPrefixSet(pfx), n: len(pfx), fetched: now}
		if err := r.writeCache(u, pfx, now); err != nil {
			errs = append(errs, err) // still use the fresh list in memory
		}
		r.mu.Lock()
		if slices.Contains(r.urls, u) {
			r.lists[u] = l
		}
		r.mu.Unlock()
	}
	return errors.Join(errs...)
}

// RefreshLoop refreshes stale lists now and then every `every` until ctx is
// done. Errors go to logf (may be nil).
func (r *RangeStore) RefreshLoop(ctx context.Context, every time.Duration, logf func(string, ...any)) {
	if every <= 0 {
		every = time.Hour
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := r.Refresh(ctx); err != nil && ctx.Err() == nil {
			logf("attrib: range refresh: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *RangeStore) cachePath(url string) string {
	h := sha256.Sum256([]byte(url))
	return filepath.Join(r.cacheDir, "ranges-"+hex.EncodeToString(h[:8])+".txt")
}

const fetchedHeader = "# fetched: "

func (r *RangeStore) writeCache(url string, pfx []netip.Prefix, fetched time.Time) error {
	if r.cacheDir == "" {
		return nil
	}
	if err := os.MkdirAll(r.cacheDir, 0o755); err != nil {
		return fmt.Errorf("attrib: ranges: cache dir: %w", err)
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# source: %s\n%s%s\n", url, fetchedHeader, fetched.UTC().Format(time.RFC3339))
	for _, p := range pfx {
		buf.WriteString(p.String())
		buf.WriteByte('\n')
	}
	dst := r.cachePath(url)
	tmp, err := os.CreateTemp(r.cacheDir, ".ranges-*.tmp")
	if err != nil {
		return fmt.Errorf("attrib: ranges: cache: %w", err)
	}
	_, werr := tmp.Write(buf.Bytes())
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("attrib: ranges: cache: %w", err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("attrib: ranges: cache: %w", err)
	}
	return nil
}

func (r *RangeStore) loadCache(url string) (*rangeList, error) {
	if r.cacheDir == "" {
		return nil, os.ErrNotExist
	}
	path := r.cachePath(url)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pfx, err := ParsePrefixes(b)
	if err != nil {
		return nil, err
	}
	var fetched time.Time
	for line := range strings.Lines(string(b)) {
		if !strings.HasPrefix(line, "#") {
			break
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), fetchedHeader); ok {
			fetched, _ = time.Parse(time.RFC3339, v)
		}
	}
	if fetched.IsZero() { // header missing: fall back to mtime
		if fi, err := os.Stat(path); err == nil {
			fetched = fi.ModTime()
		}
	}
	return &rangeList{set: newPrefixSet(pfx), n: len(pfx), fetched: fetched}, nil
}
