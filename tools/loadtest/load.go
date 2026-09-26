package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type config struct {
	URL       string
	Conns     int
	Duration  time.Duration
	Ramp      time.Duration
	PID       int
	MaxRSSMB  float64
	MaxCPUPct float64
	Interval  time.Duration // server drip interval, for the dripped/fast heuristic
	IPs       int           // distinct synthetic X-Forwarded-For clients; 0 = none
	Follow    bool
	ReadDelay time.Duration
	ClkTck    int
	ProcRoot  string
	MaxErrPct float64
	Quiet     bool
}

func parseFlags(args []string, out io.Writer) (config, error) {
	var c config
	fs := flag.NewFlagSet("loadtest", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&c.URL, "url", "http://127.0.0.1:8080/lawn/", "maze URL to load")
	fs.IntVar(&c.Conns, "conns", 5000, "concurrent slow-reading connections")
	fs.DurationVar(&c.Duration, "duration", 60*time.Second, "total test duration (including ramp)")
	fs.DurationVar(&c.Ramp, "ramp", 10*time.Second, "time over which connections are opened")
	fs.IntVar(&c.PID, "pid", 0, "server PID to sample via /proc (0 = don't sample)")
	fs.Float64Var(&c.MaxRSSMB, "max-rss-mb", 500, "FAIL if server peak RSS exceeds this (MiB)")
	fs.Float64Var(&c.MaxCPUPct, "max-cpu-pct", 50, "FAIL if server steady-state CPU exceeds this % of the whole box")
	fs.DurationVar(&c.Interval, "interval", time.Second, "server drip interval (a body taking > 2x this counts as dripped)")
	fs.IntVar(&c.IPs, "ips", -1, "distinct synthetic client IPs sent as X-Forwarded-For (-1 = one per conn, 0 = send none)")
	fs.BoolVar(&c.Follow, "follow", true, "after a page completes, follow one of its links")
	fs.DurationVar(&c.ReadDelay, "read-delay", 0, "extra pause between body reads (slower client)")
	fs.IntVar(&c.ClkTck, "clk-tck", 100, "kernel USER_HZ for /proc/<pid>/stat")
	fs.Float64Var(&c.MaxErrPct, "max-err-pct", 1, "FAIL if connection errors exceed this % of attempts")
	fs.BoolVar(&c.Quiet, "quiet", false, "no per-second progress lines")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if c.IPs < 0 {
		c.IPs = c.Conns
	}
	c.ProcRoot = "/proc"
	if c.Conns <= 0 || c.Duration <= 0 || c.Interval <= 0 || c.ClkTck <= 0 {
		return c, errors.New("conns, duration, interval and clk-tck must be > 0")
	}
	if _, err := url.Parse(c.URL); err != nil {
		return c, err
	}
	return c, nil
}

// counters are shared by all workers.
type counters struct {
	attempts   atomic.Int64
	responses  atomic.Int64
	dripped    atomic.Int64 // completed bodies that took > 2x interval
	fast       atomic.Int64 // completed bodies within 2x interval
	heldAtEnd  atomic.Int64 // still being dripped when the test ended
	cutShort   atomic.Int64 // open at the end but not yet past 2x interval
	errors     atomic.Int64
	status2xx  atomic.Int64
	status5xx  atomic.Int64
	statusElse atomic.Int64
	bytes      atomic.Int64
	open       atomic.Int64
	peakOpen   atomic.Int64
}

func (c *counters) opened() {
	n := c.open.Add(1)
	for {
		p := c.peakOpen.Load()
		if n <= p || c.peakOpen.CompareAndSwap(p, n) {
			return
		}
	}
}

// syntheticIP maps a client index into 198.18.0.0/15 (RFC 2544 benchmarking
// space), so X-Forwarded-For never names a real host.
func syntheticIP(i int) string {
	i %= 1 << 17
	return netip.AddrFrom4([4]byte{198, 18 + byte(i>>16), byte(i >> 8), byte(i)}).String()
}

func newClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil, // never route the load through an env proxy
			DialContext:         (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
			DisableKeepAlives:   true,
			DisableCompression:  true,
			MaxConnsPerHost:     0,
			MaxIdleConnsPerHost: -1,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

var hrefPrefix = []byte(`href="/lawn/`)

// nextURL returns the first maze link in page resolved against base, or base.
func nextURL(base *url.URL, page []byte) string {
	i := bytes.Index(page, hrefPrefix)
	if i < 0 {
		return base.String()
	}
	rest := page[i+len(`href="`):]
	j := bytes.IndexByte(rest, '"')
	if j < 0 {
		return base.String()
	}
	ref, err := url.Parse(string(rest[:j]))
	if err != nil {
		return base.String()
	}
	return base.ResolveReference(ref).String()
}

// worker loops GET → slow read → (follow) until ctx is done.
func worker(ctx context.Context, cfg *config, client *http.Client, base *url.URL, id int, c *counters) {
	target := base.String()
	var xff string
	if cfg.IPs > 0 {
		xff = syntheticIP(id % cfg.IPs)
	}
	buf := make([]byte, 256)
	var page []byte
	if cfg.Follow {
		page = make([]byte, 0, 8192)
	}
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			c.errors.Add(1)
			return
		}
		req.Header.Set("User-Agent", "lawn-loadtest/1 (self-test)")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		c.attempts.Add(1)
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.errors.Add(1)
			sleepCtx(ctx, 200*time.Millisecond)
			continue
		}
		c.responses.Add(1)
		switch {
		case resp.StatusCode >= 500:
			c.status5xx.Add(1)
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			c.status2xx.Add(1)
		default:
			c.statusElse.Add(1)
		}
		c.opened()
		start := time.Now()
		page = page[:0]
		var rerr error
		for {
			n, err := resp.Body.Read(buf)
			c.bytes.Add(int64(n))
			if cfg.Follow && len(page)+n <= cap(page) {
				page = append(page, buf[:n]...)
			}
			if err != nil {
				rerr = err
				break
			}
			if cfg.ReadDelay > 0 {
				sleepCtx(ctx, cfg.ReadDelay)
			}
		}
		resp.Body.Close()
		c.open.Add(-1)
		took := time.Since(start)
		switch {
		case errors.Is(rerr, io.EOF):
			if took > 2*cfg.Interval {
				c.dripped.Add(1)
			} else {
				c.fast.Add(1)
			}
		case ctx.Err() != nil:
			if took > 2*cfg.Interval {
				c.heldAtEnd.Add(1)
			} else {
				c.cutShort.Add(1)
			}
			return
		default:
			c.errors.Add(1)
		}
		if cfg.Follow {
			target = nextURL(base, page)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

type result struct {
	cfg      config
	elapsed  time.Duration
	c        *counters
	sampled  bool
	cpu      cpuStats
	nproc    int
	pass     bool
	failures []string
}

// runLoad drives the load and returns the result (not yet judged).
func runLoad(ctx context.Context, cfg config, progress io.Writer) (*result, error) {
	base, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()
	client := newClient()
	c := &counters{}
	res := &result{cfg: cfg, c: c, nproc: runtime.NumCPU()}
	begin := time.Now()

	var samples []sample
	var sampWG sync.WaitGroup
	if cfg.PID > 0 {
		s := &sampler{procRoot: cfg.ProcRoot, pid: cfg.PID, clkTck: float64(cfg.ClkTck), nproc: res.nproc}
		if _, err := s.read(time.Now()); err != nil {
			return nil, fmt.Errorf("cannot sample pid %d: %w", cfg.PID, err)
		}
		res.sampled = true
		sampWG.Add(1)
		go func() {
			defer sampWG.Done()
			samples = s.loop(ctx, time.Second, func(sm sample) {
				if progress != nil {
					fmt.Fprintf(progress, "t=%4.0fs open=%5d rss=%6.1fMiB cpu=%5.1f%% (one) %5.1f%% (box) dripped=%d fast=%d err=%d 5xx=%d\n",
						time.Since(begin).Seconds(), c.open.Load(), float64(sm.rssKB)/1024, sm.cpuOne, sm.cpuBox,
						c.dripped.Load(), c.fast.Load(), c.errors.Load(), c.status5xx.Load())
				}
			})
		}()
	}

	var wg sync.WaitGroup
	for i := range cfg.Conns {
		var delay time.Duration
		if cfg.Ramp > 0 {
			delay = cfg.Ramp * time.Duration(i) / time.Duration(cfg.Conns)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if delay > 0 {
				sleepCtx(ctx, delay)
			}
			worker(ctx, &cfg, client, base, i, c)
		}()
	}
	wg.Wait()
	cancel()
	sampWG.Wait()
	res.elapsed = time.Since(begin)
	res.cpu = summarise(samples, begin.Add(cfg.Ramp))
	return res, nil
}

// judge applies the spec-12 thresholds.
func (r *result) judge() {
	c, cfg := r.c, r.cfg
	var f []string
	if n := c.status5xx.Load(); n > 0 {
		f = append(f, fmt.Sprintf("%d responses were 5xx (load shedding must never 5xx)", n))
	}
	if att := c.attempts.Load(); att > 0 {
		if pct := 100 * float64(c.errors.Load()) / float64(att); pct > cfg.MaxErrPct {
			f = append(f, fmt.Sprintf("connection errors %.2f%% > %.2f%%", pct, cfg.MaxErrPct))
		}
	}
	if c.dripped.Load()+c.heldAtEnd.Load() == 0 {
		f = append(f, "no connection was dripped (is the tarpit on?)")
	}
	if r.sampled {
		if mb := float64(r.cpu.maxRSSKB) / 1024; mb > cfg.MaxRSSMB {
			f = append(f, fmt.Sprintf("peak RSS %.1f MiB > %.0f MiB", mb, cfg.MaxRSSMB))
		}
		if r.cpu.avgBox > cfg.MaxCPUPct {
			f = append(f, fmt.Sprintf("steady-state CPU %.1f%% of box > %.0f%%", r.cpu.avgBox, cfg.MaxCPUPct))
		}
	}
	r.failures = f
	r.pass = len(f) == 0
}

func (r *result) print(w io.Writer) {
	c := r.c
	fmt.Fprintf(w, "\n== lawn load test ==\n")
	fmt.Fprintf(w, "target            %s\n", r.cfg.URL)
	fmt.Fprintf(w, "conns / ramp      %d over %v, ran %v\n", r.cfg.Conns, r.cfg.Ramp, r.elapsed.Round(time.Millisecond))
	fmt.Fprintf(w, "attempts          %d (responses %d, conn errors %d)\n", c.attempts.Load(), c.responses.Load(), c.errors.Load())
	fmt.Fprintf(w, "status            2xx=%d 5xx=%d other=%d\n", c.status2xx.Load(), c.status5xx.Load(), c.statusElse.Load())
	fmt.Fprintf(w, "dripped           %d completed + %d still held at end\n", c.dripped.Load(), c.heldAtEnd.Load())
	fmt.Fprintf(w, "fast (limited)    %d (+%d open < 2x interval at end)\n", c.fast.Load(), c.cutShort.Load())
	fmt.Fprintf(w, "peak open conns   %d\n", c.peakOpen.Load())
	fmt.Fprintf(w, "bytes received    %d\n", c.bytes.Load())
	if r.sampled {
		fmt.Fprintf(w, "server RSS peak   %.1f MiB (limit %.0f)\n", float64(r.cpu.maxRSSKB)/1024, r.cfg.MaxRSSMB)
		fmt.Fprintf(w, "server CPU        avg %.1f%% of one CPU, avg %.1f%% / peak %.1f%% of box (%d CPUs, limit %.0f%%, %d steady samples)\n",
			r.cpu.avgOne, r.cpu.avgBox, r.cpu.peakBox, r.nproc, r.cfg.MaxCPUPct, r.cpu.n)
	} else {
		fmt.Fprintf(w, "server RSS/CPU    not sampled (no -pid)\n")
	}
	if r.pass {
		fmt.Fprintf(w, "RESULT            PASS\n")
		return
	}
	fmt.Fprintf(w, "RESULT            FAIL\n")
	for _, f := range r.failures {
		fmt.Fprintf(w, "  - %s\n", f)
	}
}
