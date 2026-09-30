package attrib

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

// Resolver is the subset of *net.Resolver used for rDNS verification.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// IdentityStore caches classifications; *logstore.Store satisfies it.
type IdentityStore interface {
	GetIdentity(ctx context.Context, ip, ua string) (logstore.Identity, bool, error)
	UpsertIdentity(ctx context.Context, id logstore.Identity) error
}

// HostStore caches reverse DNS per IP. It is optional: when the
// IdentityStore also implements it (as *logstore.Store does), every
// observed IP gets its PTR recorded, which is how new crawlers are often
// spotted (crawl-1-2-3.example-bot.com).
type HostStore interface {
	GetHost(ctx context.Context, ip string) (logstore.Host, bool, error)
	UpsertHost(ctx context.Context, h logstore.Host) error
}

// ErrIndeterminate means verification could not reach a verdict (DNS
// timeout/SERVFAIL, vendor IP list unavailable). It must never be read as
// "spoofed".
var ErrIndeterminate = errors.New("attrib: verification indeterminate")

// Options configures a Classifier. Zero values get defaults.
type Options struct {
	Crawlers   []Crawler
	Resolver   Resolver      // default net.DefaultResolver
	Store      IdentityStore // required for Run/ReverifyStale
	Ranges     *RangeStore   // needed for ip_ranges crawlers with a url
	TTL        time.Duration // identities cache TTL (default 7d)
	DNSTimeout time.Duration // per lookup (default 2s)
	QueueSize  int           // Observe buffer (default 4096)
	Workers    int           // Run worker count (default 4)
	Now        func() time.Time

	// SeenTTL is how long Observe suppresses repeat pairs (default 10m);
	// SeenMax caps the recently-seen set (default 65536 entries).
	SeenTTL time.Duration
	SeenMax int
	// RetryAfter is how soon an indeterminate result is retried (default 1h).
	RetryAfter time.Duration
}

// ClassifierStats are counters for /metrics.
type ClassifierStats struct {
	Queued        int64 // pairs waiting for a worker
	Dropped       int64 // pairs Observe dropped because the queue was full
	Classified    int64 // classifications completed (any status)
	Indeterminate int64 // classifications that hit ErrIndeterminate
	Errors        int64 // identity store errors
	PTRLookups    int64 // reverse-DNS lookups for the hosts table
}

type pair struct{ ip, ua string }

const seenShards = 16

type seenShard struct {
	mu sync.Mutex
	m  map[uint64]int64 // key hash → expiry (unix ns)
}

// Classifier assigns an identity status to (ip, user_agent) pairs off the
// hot path (SPEC.md section 7.2).
type Classifier struct {
	crawlers   atomic.Pointer[[]Crawler]
	resolver   Resolver
	store      IdentityStore
	ranges     *RangeStore
	ttl        time.Duration
	dnsTimeout time.Duration
	workers    int
	now        func() time.Time
	seenTTL    time.Duration
	seenMax    int
	retryAfter time.Duration

	queue chan pair
	seed  maphash.Seed
	seen  [seenShards]seenShard

	dropped, classified, indeterminate, errs, ptrLookups atomic.Int64
}

// NewClassifier builds a classifier. Call Run to start the workers.
func NewClassifier(opt Options) *Classifier {
	c := &Classifier{
		resolver:   opt.Resolver,
		store:      opt.Store,
		ranges:     opt.Ranges,
		ttl:        opt.TTL,
		dnsTimeout: opt.DNSTimeout,
		workers:    opt.Workers,
		now:        opt.Now,
		seenTTL:    opt.SeenTTL,
		seenMax:    opt.SeenMax,
		retryAfter: opt.RetryAfter,
		seed:       maphash.MakeSeed(),
	}
	if c.resolver == nil {
		c.resolver = net.DefaultResolver
	}
	if c.ttl <= 0 {
		c.ttl = 7 * 24 * time.Hour
	}
	if c.dnsTimeout <= 0 {
		c.dnsTimeout = 2 * time.Second
	}
	if opt.QueueSize <= 0 {
		opt.QueueSize = 4096
	}
	if c.workers <= 0 {
		c.workers = 4
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.seenTTL <= 0 {
		c.seenTTL = 10 * time.Minute
	}
	if c.seenMax <= 0 {
		c.seenMax = 65536
	}
	if c.retryAfter <= 0 {
		c.retryAfter = time.Hour
	}
	c.queue = make(chan pair, opt.QueueSize)
	for i := range c.seen {
		c.seen[i].m = make(map[uint64]int64)
	}
	c.SetCrawlers(opt.Crawlers)
	return c
}

// SetCrawlers atomically swaps the crawler list (SIGHUP reload).
func (c *Classifier) SetCrawlers(cs []Crawler) {
	c.crawlers.Store(&cs)
}

func (c *Classifier) crawlerList() []Crawler { return *c.crawlers.Load() }

// Stats returns a snapshot of the counters.
func (c *Classifier) Stats() ClassifierStats {
	return ClassifierStats{
		Queued:        int64(len(c.queue)),
		Dropped:       c.dropped.Load(),
		Classified:    c.classified.Load(),
		Indeterminate: c.indeterminate.Load(),
		Errors:        c.errs.Load(),
		PTRLookups:    c.ptrLookups.Load(),
	}
}

func (c *Classifier) key(ip, ua string) uint64 {
	h1 := maphash.String(c.seed, ip)
	h2 := maphash.String(c.seed, ua)
	return h1 ^ (h2*0x9e3779b97f4a7c15 + 0x7f4a7c15)
}

// Observe queues (ip, ua) for classification. It is safe on the request hot
// path: it never blocks, never does I/O, and does not allocate. Pairs seen
// within SeenTTL are ignored; if the queue is full the pair is dropped and
// forgotten so a later request can retry.
func (c *Classifier) Observe(ip, ua string) {
	k := c.key(ip, ua)
	sh := &c.seen[k%seenShards]
	now := c.now().UnixNano()
	sh.mu.Lock()
	if exp, ok := sh.m[k]; ok && exp > now {
		sh.mu.Unlock()
		return
	}
	if len(sh.m) >= c.seenMax/seenShards+1 {
		for kk, exp := range sh.m {
			if exp <= now {
				delete(sh.m, kk)
			}
		}
		if len(sh.m) >= c.seenMax/seenShards+1 {
			// Still full of live entries: start over. Workers dedupe
			// against the identities TTL anyway.
			clear(sh.m)
		}
	}
	sh.m[k] = now + int64(c.seenTTL)
	sh.mu.Unlock()

	select {
	case c.queue <- pair{ip, ua}:
	default:
		c.dropped.Add(1)
		sh.mu.Lock()
		delete(sh.m, k)
		sh.mu.Unlock()
	}
}

// Run starts the worker pool and blocks until ctx is done. Pairs still
// queued at shutdown are discarded (they will be re-observed or picked up
// by ReverifyStale).
func (c *Classifier) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for range c.workers {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case p := <-c.queue:
					c.handle(ctx, p.ip, p.ua)
				}
			}
		})
	}
	wg.Wait()
}

func (c *Classifier) handle(ctx context.Context, ip, ua string) {
	if c.store == nil {
		return
	}
	if hs, ok := c.store.(HostStore); ok {
		c.recordHost(ctx, hs, ip)
	}
	old, ok, err := c.store.GetIdentity(ctx, ip, ua)
	if err != nil {
		c.errs.Add(1)
		return
	}
	if ok && c.now().Sub(time.UnixMilli(old.CheckedAt)) < c.ttl {
		return
	}
	c.classifyAndStore(ctx, ip, ua, old, ok)
}

// classifyAndStore classifies and upserts, applying the indeterminate
// policy: keep an existing row untouched (it stays stale and is retried);
// with no row, store "unverifiable" backdated so it is retried after
// RetryAfter. Returns whether a row was written.
func (c *Classifier) classifyAndStore(ctx context.Context, ip, ua string, old logstore.Identity, hadOld bool) bool {
	id, err := c.ClassifyDetailed(ctx, ip, ua)
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		if hadOld {
			return false
		}
		id.CheckedAt = c.now().Add(c.retryAfter - c.ttl).UnixMilli()
	}
	if err := c.store.UpsertIdentity(ctx, id); err != nil {
		c.errs.Add(1)
		return false
	}
	return true
}

// Classify returns the identity for (ip, ua). If verification is
// indeterminate the result is "unverifiable" (never "spoofed"); use
// ClassifyDetailed to tell the difference.
func (c *Classifier) Classify(ctx context.Context, ip, ua string) logstore.Identity {
	id, _ := c.ClassifyDetailed(ctx, ip, ua)
	return id
}

// ClassifyDetailed is Classify plus an ErrIndeterminate-wrapping error when
// no verdict could be reached. The identity returned alongside such an
// error is status unverifiable, method none.
func (c *Classifier) ClassifyDetailed(ctx context.Context, ip, ua string) (logstore.Identity, error) {
	id := logstore.Identity{IP: ip, UserAgent: ua, CheckedAt: c.now().UnixMilli()}
	defer c.classified.Add(1)
	cr := MatchUA(c.crawlerList(), ua)
	if cr == nil {
		id.Status, id.Method = logstore.StatusAnonymous, logstore.MethodNone
		return id, nil
	}
	id.ClaimedOrg = cr.Org
	if logstore.IsOnionIP(ip) {
		// Over Tor there is no source address to check a claim against:
		// neither confirmed nor refuted, so never "spoofed".
		id.Status, id.Method = logstore.StatusUnverifiable, logstore.MethodNone
		return id, nil
	}
	var (
		ok     bool
		err    error
		method string
	)
	addr, perr := netip.ParseAddr(ip)
	switch cr.Verify.Method {
	case VerifyRDNS:
		method = logstore.MethodRDNS
		if perr != nil {
			err = fmt.Errorf("%w: bad ip %q", ErrIndeterminate, ip)
			break
		}
		ok, err = c.verifyRDNS(ctx, addr, cr.Verify.Domains)
	case VerifyIPRanges:
		method = logstore.MethodIPRange
		if perr != nil {
			err = fmt.Errorf("%w: bad ip %q", ErrIndeterminate, ip)
			break
		}
		ok, err = c.verifyRanges(addr, cr)
	default:
		id.Status, id.Method = logstore.StatusUnverifiable, logstore.MethodNone
		return id, nil
	}
	switch {
	case err != nil:
		c.indeterminate.Add(1)
		id.Status, id.Method = logstore.StatusUnverifiable, logstore.MethodNone
		return id, err
	case ok:
		id.Status, id.Method = logstore.StatusVerified, method
	default:
		id.Status, id.Method = logstore.StatusSpoofed, method
	}
	return id, nil
}

func (c *Classifier) verifyRanges(a netip.Addr, cr *Crawler) (bool, error) {
	if cr.static.contains(a) {
		return true, nil
	}
	lists := cr.Verify.Lists()
	if len(lists) == 0 {
		return false, nil // static list only: clean miss
	}
	// In any list: verified. Missing from every list: spoofed, but only
	// once every list is known; a missing copy leaves it undecided.
	var missing string
	for _, l := range lists {
		in, known := c.ranges.Contains(l, a)
		if in {
			return true, nil
		}
		if !known {
			missing = l
		}
	}
	if missing != "" {
		return false, fmt.Errorf("%w: no copy of %s", ErrIndeterminate, missing)
	}
	return false, nil
}

// domainMatch reports whether host equals one of domains or is a subdomain
// of one (label boundary: "x.googlebot.com" matches, "evilgooglebot.com"
// does not). host and domains must be lower-case without trailing dots.
func domainMatch(host string, domains []string) bool {
	for _, d := range domains {
		if host == d || (len(host) > len(d) && strings.HasSuffix(host, d) && host[len(host)-len(d)-1] == '.') {
			return true
		}
	}
	return false
}

// notFound reports whether err is an authoritative "no such record"
// answer, which is a clean negative rather than a failure.
func notFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// verifyRDNS does forward-confirmed reverse DNS: some PTR for a must be in
// domains and resolve back to a. NXDOMAIN answers are clean negatives;
// timeouts and other DNS failures return ErrIndeterminate.
func (c *Classifier) verifyRDNS(ctx context.Context, a netip.Addr, domains []string) (bool, error) {
	a = a.Unmap()
	lctx, cancel := context.WithTimeout(ctx, c.dnsTimeout)
	names, err := c.resolver.LookupAddr(lctx, a.String())
	cancel()
	if err != nil && !notFound(err) {
		return false, fmt.Errorf("%w: PTR %s: %v", ErrIndeterminate, a, err)
	}
	var fwdErr error
	for _, n := range names {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if !domainMatch(host, domains) {
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, c.dnsTimeout)
		addrs, err := c.resolver.LookupHost(lctx, host)
		cancel()
		if err != nil {
			if !notFound(err) {
				fwdErr = fmt.Errorf("%w: A/AAAA %s: %v", ErrIndeterminate, host, err)
			}
			continue
		}
		for _, s := range addrs {
			if b, err := netip.ParseAddr(s); err == nil && b.Unmap().WithZone("") == a.WithZone("") {
				return true, nil
			}
		}
	}
	if fwdErr != nil {
		return false, fwdErr
	}
	return false, nil
}

// ReverifyStale is the `lawn verify-refresh` pass: it re-classifies
// identities older than TTL that still have raw requests (history that was
// rolled up keeps the status it had), and classifies every (ip,
// user_agent) in requests that has no identity yet, violator or not, so
// well-behaved bots are labelled too. Each job also refreshes the IP's
// reverse DNS when the store keeps hosts. Work is spread over
// Workers goroutines. It returns the number of identities written.
func (c *Classifier) ReverifyStale(ctx context.Context, db *sql.DB) (int, error) {
	if c.store == nil {
		return 0, errors.New("attrib: ReverifyStale needs a Store")
	}
	cutoff := c.now().Add(-c.ttl).UnixMilli()
	type job struct {
		p      pair
		old    logstore.Identity
		hadOld bool
	}
	var jobs []job
	rows, err := db.QueryContext(ctx, `SELECT ip, user_agent, COALESCE(claimed_org, ''), status, COALESCE(method, ''), checked_at
	 FROM identities i WHERE checked_at < ?
	 AND EXISTS (SELECT 1 FROM requests r WHERE r.ip = i.ip AND COALESCE(r.user_agent, '') = i.user_agent)`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("attrib: reverify: %w", err)
	}
	for rows.Next() {
		var id logstore.Identity
		if err := rows.Scan(&id.IP, &id.UserAgent, &id.ClaimedOrg, &id.Status, &id.Method, &id.CheckedAt); err != nil {
			rows.Close()
			return 0, fmt.Errorf("attrib: reverify: %w", err)
		}
		jobs = append(jobs, job{pair{id.IP, id.UserAgent}, id, true})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("attrib: reverify: %w", err)
	}
	rows, err = db.QueryContext(ctx, `SELECT DISTINCT r.ip, COALESCE(r.user_agent, '') FROM requests r
	 WHERE NOT EXISTS
	 (SELECT 1 FROM identities i WHERE i.ip = r.ip AND i.user_agent = COALESCE(r.user_agent, ''))`)
	if err != nil {
		return 0, fmt.Errorf("attrib: reverify: %w", err)
	}
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.ip, &p.ua); err != nil {
			rows.Close()
			return 0, fmt.Errorf("attrib: reverify: %w", err)
		}
		jobs = append(jobs, job{p: p})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("attrib: reverify: %w", err)
	}

	var n atomic.Int64
	ch := make(chan job)
	var wg sync.WaitGroup
	for range c.workers {
		wg.Go(func() {
			hs, keepsHosts := c.store.(HostStore)
			for j := range ch {
				if keepsHosts {
					c.recordHost(ctx, hs, j.p.ip)
				}
				if c.classifyAndStore(ctx, j.p.ip, j.p.ua, j.old, j.hadOld) {
					n.Add(1)
				}
			}
		})
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		ch <- j
	}
	close(ch)
	wg.Wait()
	return int(n.Load()), ctx.Err()
}

// recordHost stores the PTR name for ip unless a row fresher than the TTL
// exists. The name is not forward-confirmed: it is a lead for a human, not
// a verification (identities does that for known crawlers). A clean "no
// PTR" is stored as ""; DNS timeouts and failures store nothing, so the IP
// is retried the next time it is observed.
func (c *Classifier) recordHost(ctx context.Context, hs HostStore, ip string) {
	old, ok, err := hs.GetHost(ctx, ip)
	if err != nil {
		c.errs.Add(1)
		return
	}
	if ok && c.now().Sub(time.UnixMilli(old.CheckedAt)) < c.ttl {
		return
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || logstore.IsOnion(a) {
		return // a Tor circuit id has no reverse DNS
	}
	c.ptrLookups.Add(1)
	lctx, cancel := context.WithTimeout(ctx, c.dnsTimeout)
	names, err := c.resolver.LookupAddr(lctx, a.Unmap().String())
	cancel()
	if err != nil && !notFound(err) {
		return
	}
	ptr := ""
	if len(names) > 0 {
		ptr = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(names[0])), ".")
		if len(ptr) > 253 {
			ptr = ptr[:253]
		}
	}
	if err := hs.UpsertHost(ctx, logstore.Host{IP: ip, PTR: ptr, CheckedAt: c.now().UnixMilli()}); err != nil {
		c.errs.Add(1)
	}
}
