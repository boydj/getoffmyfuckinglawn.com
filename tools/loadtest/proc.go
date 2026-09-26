package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// parseVmRSS extracts VmRSS (in kB) from the contents of /proc/<pid>/status.
func parseVmRSS(status string) (int64, error) {
	sc := bufio.NewScanner(strings.NewReader(status))
	for sc.Scan() {
		line := sc.Text()
		rest, ok := strings.CutPrefix(line, "VmRSS:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0, errors.New("VmRSS: no value")
		}
		kb, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("VmRSS: %w", err)
		}
		if len(f) > 1 && f[1] != "kB" {
			return 0, fmt.Errorf("VmRSS: unexpected unit %q", f[1])
		}
		return kb, nil
	}
	return 0, errors.New("VmRSS not found")
}

// parseStatTicks returns utime+stime (clock ticks) from /proc/<pid>/stat.
// The comm field is parenthesised and may itself contain spaces and
// parentheses, so fields are counted from the last ')'.
func parseStatTicks(stat string) (uint64, error) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("stat: no comm field")
	}
	// After ")": field 3 (state) is f[0]; utime is field 14, stime field 15.
	f := strings.Fields(stat[i+1:])
	if len(f) < 13 {
		return 0, fmt.Errorf("stat: only %d fields after comm", len(f))
	}
	ut, err := strconv.ParseUint(f[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("stat utime: %w", err)
	}
	st, err := strconv.ParseUint(f[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("stat stime: %w", err)
	}
	return ut + st, nil
}

// sample is one reading of the server process.
type sample struct {
	at     time.Time
	rssKB  int64
	ticks  uint64
	cpuOne float64 // % of one CPU since the previous sample
	cpuBox float64 // cpuOne / nproc
}

// sampler reads RSS and CPU of a process from a procfs root.
type sampler struct {
	procRoot string // normally "/proc"
	pid      int
	clkTck   float64
	nproc    int
	prev     *sample
}

func (s *sampler) read(now time.Time) (sample, error) {
	dir := filepath.Join(s.procRoot, strconv.Itoa(s.pid))
	st, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return sample{}, err
	}
	rss, err := parseVmRSS(string(st))
	if err != nil {
		return sample{}, err
	}
	sb, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return sample{}, err
	}
	ticks, err := parseStatTicks(string(sb))
	if err != nil {
		return sample{}, err
	}
	cur := sample{at: now, rssKB: rss, ticks: ticks}
	if p := s.prev; p != nil {
		if wall := now.Sub(p.at).Seconds(); wall > 0 && ticks >= p.ticks {
			cur.cpuOne = float64(ticks-p.ticks) / s.clkTck / wall * 100
			cur.cpuBox = cur.cpuOne / float64(max(s.nproc, 1))
		}
	}
	s.prev = &cur
	return cur, nil
}

// cpuStats summarises samples: CPU is judged on samples taken after the
// ramp (steady state); RSS on the peak over the whole run.
type cpuStats struct {
	n                       int
	maxRSSKB                int64
	avgOne, avgBox, peakBox float64
}

func summarise(samples []sample, steadyFrom time.Time) cpuStats {
	var c cpuStats
	var sumOne, sumBox float64
	for i, s := range samples {
		c.maxRSSKB = max(c.maxRSSKB, s.rssKB)
		if i == 0 || s.at.Before(steadyFrom) {
			continue // first sample has no delta
		}
		c.n++
		sumOne += s.cpuOne
		sumBox += s.cpuBox
		c.peakBox = max(c.peakBox, s.cpuBox)
	}
	if c.n > 0 {
		c.avgOne = sumOne / float64(c.n)
		c.avgBox = sumBox / float64(c.n)
	}
	return c
}

// sampleLoop reads the process every interval until ctx is done, calling
// report after each successful sample.
func (s *sampler) loop(ctx context.Context, every time.Duration, report func(sample)) []sample {
	var out []sample
	if smp, err := s.read(time.Now()); err == nil {
		out = append(out, smp)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return out
		case now := <-t.C:
			smp, err := s.read(now)
			if err != nil {
				continue
			}
			out = append(out, smp)
			if report != nil {
				report(smp)
			}
		}
	}
}
