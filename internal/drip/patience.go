package drip

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

// PatienceKey identifies a client for adaptive pacing. Crawlers rotate IPs
// within a network far more often than they change user agent, so the key
// is (ASN, UA) when the ASN is known and (/24 or /48, UA) otherwise.
type PatienceKey struct {
	ASN uint32
	Net netip.Prefix // zero when ASN != 0
	UA  string
}

// maxKeyUA bounds per-entry memory; the tail of a longer UA is noise.
const maxKeyUA = 256

// KeyFor builds the PatienceKey for a client.
func KeyFor(ip netip.Addr, asn uint32, ua string) PatienceKey {
	if len(ua) > maxKeyUA {
		ua = ua[:maxKeyUA]
	}
	if asn != 0 {
		return PatienceKey{ASN: asn, UA: ua}
	}
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits) // invalid ip: zero prefix, still a usable key
	return PatienceKey{Net: p, UA: ua}
}

// PatienceOptions configures a Patience tracker.
type PatienceOptions struct {
	// Max is the budget for clients never seen giving up (drip.max_duration).
	Max time.Duration
	// Factor scales the observed give-up time into the next budget, so the
	// page completes just before the client would hang up (0 < Factor <= 1).
	Factor float64
	// TTL forgets clients not seen for this long (default 24h).
	TTL time.Duration
	// Capacity bounds the number of tracked clients (default 100k).
	Capacity int
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Minimum budget: below this the drip is pointless and a bot that gives up
// almost instantly still gets a (fast) page with links.
const minBudget = 250 * time.Millisecond

// Growth applied to a client's estimated patience each time it waits out a
// whole budget, so the estimate creeps back up toward its real timeout
// (and recovers from a noisy low sample) instead of staying low forever.
const patienceGrowth = 1.02

type patienceEntry struct {
	patience time.Duration // estimated time the client waits before giving up
	seen     time.Time
}

// Patience learns how long each client waits for a dripped response before
// giving up, and budgets its later responses to finish just before that:
// a crawler with a 30 s timeout then receives whole pages (and follows
// their links) in ~24 s instead of timing out on every page at depth 0.
// Clients never seen giving up keep the full Max. Safe for concurrent use.
type Patience struct {
	opt PatienceOptions
	mu  sync.Mutex
	m   map[PatienceKey]patienceEntry
}

// NewPatience returns a tracker.
func NewPatience(opt PatienceOptions) *Patience {
	if opt.Factor <= 0 || opt.Factor > 1 {
		opt.Factor = 0.8
	}
	if opt.TTL <= 0 {
		opt.TTL = 24 * time.Hour
	}
	if opt.Capacity <= 0 {
		opt.Capacity = 100_000
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Patience{opt: opt, m: make(map[PatienceKey]patienceEntry)}
}

// Budget returns how long to drip the next response for k. A nil tracker
// returns 0 (use the default).
func (p *Patience) Budget(k PatienceKey) time.Duration {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	e, ok := p.m[k]
	p.mu.Unlock()
	if !ok || p.opt.Now().Sub(e.seen) > p.opt.TTL {
		return p.opt.Max
	}
	b := time.Duration(float64(e.patience) * p.opt.Factor)
	return min(max(b, minBudget), p.opt.Max)
}

// Observe records how a dripped response for k ended after held.
func (p *Patience) Observe(k PatienceKey, held time.Duration, o Outcome) {
	if p == nil {
		return
	}
	now := p.opt.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[k]
	if ok && now.Sub(e.seen) > p.opt.TTL {
		ok = false
	}
	switch o {
	case ClientGone, WriteFailed:
		// It gave up after held: that is its patience (timeouts are
		// usually fixed per client, so the latest sample wins).
		e.patience = held
	default:
		if !ok {
			return // waited out the full budget: nothing to learn, don't track
		}
		e.patience = min(time.Duration(float64(e.patience)*patienceGrowth), p.opt.Max)
	}
	e.seen = now
	if !ok {
		if len(p.m) >= p.opt.Capacity {
			p.evictLocked(now)
		}
		// k.UA may be a slice of a much longer header string (KeyFor
		// truncates by slicing); copy it so the map never pins the original.
		k.UA = strings.Clone(k.UA)
	}
	p.m[k] = e
}

// evictLocked drops expired entries, then (if still full) about a tenth of
// the rest; map iteration order makes that an arbitrary sample.
func (p *Patience) evictLocked(now time.Time) {
	for k, e := range p.m {
		if now.Sub(e.seen) > p.opt.TTL {
			delete(p.m, k)
		}
	}
	drop := len(p.m) - p.opt.Capacity + p.opt.Capacity/10
	for k := range p.m {
		if drop <= 0 {
			break
		}
		delete(p.m, k)
		drop--
	}
}

// Len is the number of tracked clients (for /metrics).
func (p *Patience) Len() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}
