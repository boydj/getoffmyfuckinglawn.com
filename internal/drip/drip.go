// Package drip holds the tarpit's slow writer, the connection limiter and
// daily egress accounting.
package drip

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"net/http"
	"time"
)

// DefaultJitter is the ±fraction applied to Interval when Options.Jitter is 0.
const DefaultJitter = 0.3

// Options controls the slow writer.
type Options struct {
	// ChunkBytes is the size of each dripped write (<= 0 means 16).
	ChunkBytes int
	// Interval is the pause between chunks. <= 0 disables pacing: Drip then
	// behaves like Fast.
	Interval time.Duration
	// MaxDuration caps how long one response is dripped; once it elapses the
	// remainder is written at once. <= 0 means no cap.
	MaxDuration time.Duration
	// Jitter is the ±fraction applied to every Interval, so the actual pause
	// is uniform in [Interval*(1-Jitter), Interval*(1+Jitter)]. 0 means
	// DefaultJitter (0.3); negative disables jitter. Values above 1 are
	// clamped to 1.
	Jitter float64
}

// Clock abstracts time for tests.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer is the subset of *time.Timer that Drip uses.
type Timer interface {
	C() <-chan time.Time
	Reset(d time.Duration)
	Stop() bool
}

// RealClock is the wall clock. The zero value is ready to use.
type RealClock struct{}

// Now returns time.Now().
func (RealClock) Now() time.Time { return time.Now() }

// NewTimer returns a real timer.
func (RealClock) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time   { return r.t.C }
func (r realTimer) Reset(d time.Duration) { r.t.Reset(d) }
func (r realTimer) Stop() bool            { return r.t.Stop() }

// Dripper writes response bodies slowly. It is safe for concurrent use.
type Dripper struct {
	opt    Options
	clock  Clock
	egress *Egress
}

// NewDripper returns a Dripper. A nil clock means RealClock{}; a nil egress
// disables egress accounting.
func NewDripper(opt Options, clock Clock, egress *Egress) *Dripper {
	if opt.ChunkBytes <= 0 {
		opt.ChunkBytes = 16
	}
	switch {
	case opt.Jitter == 0:
		opt.Jitter = DefaultJitter
	case opt.Jitter < 0:
		opt.Jitter = 0
	case opt.Jitter > 1:
		opt.Jitter = 1
	}
	if clock == nil {
		clock = RealClock{}
	}
	return &Dripper{opt: opt, clock: clock, egress: egress}
}

// Drip writes body to w in chunks of ChunkBytes every Interval ± Jitter,
// flushing after every chunk. The first chunk is written immediately.
//
// It stops as soon as ctx is done (client disconnect; returns ctx.Err())
// or a write/flush fails (returns that error). Once MaxDuration has elapsed
// since the call began, the remainder is written in one go. Drip does not
// set headers or status: the caller has already done so and flushed them.
// Every byte written is added to the egress counter. seed feeds a
// per-connection PRNG for the jitter. Drip does not allocate per chunk.
func (d *Dripper) Drip(ctx context.Context, w http.ResponseWriter, body []byte, seed uint64) (int64, error) {
	if d.opt.Interval <= 0 {
		return d.Fast(w, body)
	}
	rc := http.NewResponseController(w)
	pcg := rand.NewPCG(seed, 0x9e3779b97f4a7c15)
	var deadline time.Time
	if d.opt.MaxDuration > 0 {
		deadline = d.clock.Now().Add(d.opt.MaxDuration)
	}
	var timer Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	var written int64
	for off := 0; off < len(body); {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		end := min(off+d.opt.ChunkBytes, len(body))
		var now time.Time
		if !deadline.IsZero() {
			now = d.clock.Now()
			if !now.Before(deadline) {
				end = len(body) // out of patience: finish the page quickly
			}
		}
		n, err := w.Write(body[off:end])
		written += int64(n)
		d.egress.Add(int64(n))
		if err != nil {
			return written, err
		}
		if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return written, err
		}
		off = end
		if off >= len(body) {
			break
		}

		wait := d.jittered(pcg)
		if !deadline.IsZero() {
			wait = min(wait, deadline.Sub(now))
		}
		if timer == nil {
			timer = d.clock.NewTimer(wait)
		} else {
			timer.Reset(wait)
		}
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		case <-timer.C():
		}
	}
	return written, nil
}

// jittered returns Interval scaled by a uniform factor in [1-J, 1+J].
func (d *Dripper) jittered(pcg *rand.PCG) time.Duration {
	if d.opt.Jitter == 0 {
		return d.opt.Interval
	}
	u := float64(pcg.Uint64()>>11) / (1 << 53) // [0,1)
	f := 1 + d.opt.Jitter*(2*u-1)
	return time.Duration(math.Round(float64(d.opt.Interval) * f))
}

// Fast writes body in one go, adds it to egress and returns bytes written.
func (d *Dripper) Fast(w http.ResponseWriter, body []byte) (int64, error) {
	n, err := w.Write(body)
	d.egress.Add(int64(n))
	return int64(n), err
}
