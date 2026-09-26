package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const statusFixture = `Name:	lawn
Umask:	0022
State:	S (sleeping)
VmPeak:	 1234567 kB
VmSize:	 1200000 kB
VmHWM:	  300000 kB
VmRSS:	  204800 kB
RssAnon:	  150000 kB
Threads:	12
`

// comm with spaces and parentheses, as a hostile process name could have.
const statFixture = `4242 (la wn) (x)) S 1 4242 4242 0 -1 4194560 5000 0 0 0 1234 567 0 0 20 0 12 0 78345 2920448 367 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 2 0 0 0 0 0`

func TestParseVmRSS(t *testing.T) {
	kb, err := parseVmRSS(statusFixture)
	if err != nil || kb != 204800 {
		t.Fatalf("got %d, %v", kb, err)
	}
	for _, bad := range []string{"", "Name: x\n", "VmRSS:\n", "VmRSS: abc kB\n", "VmRSS: 12 MB\n"} {
		if _, err := parseVmRSS(bad); err == nil {
			t.Errorf("parseVmRSS(%q) should fail", bad)
		}
	}
}

func TestParseStatTicks(t *testing.T) {
	ticks, err := parseStatTicks(statFixture)
	if err != nil || ticks != 1234+567 {
		t.Fatalf("got %d, %v", ticks, err)
	}
	for _, bad := range []string{"", "12 (x", "12 (x) S 1 2 3", "12 (x) S 1 2 3 4 5 6 7 8 9 10 zz 5 6"} {
		if _, err := parseStatTicks(bad); err == nil {
			t.Errorf("parseStatTicks(%q) should fail", bad)
		}
	}
}

func writeProc(t *testing.T, root string, pid int, rssKB, ticks int) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := strings.Replace(statusFixture, "204800", strconv.Itoa(rssKB), 1)
	stat := strings.Replace(statFixture, "1234 567", strconv.Itoa(ticks)+" 0", 1)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSamplerCPUMath(t *testing.T) {
	root := t.TempDir()
	s := &sampler{procRoot: root, pid: 4242, clkTck: 100, nproc: 4}
	t0 := time.Unix(1000, 0)
	writeProc(t, root, 4242, 1000, 500)
	first, err := s.read(t0)
	if err != nil || first.cpuOne != 0 || first.rssKB != 1000 {
		t.Fatalf("first sample %+v, %v", first, err)
	}
	// 2 s wall, 100 ticks at 100 Hz = 1 CPU-second => 50% of one CPU, 12.5% of 4.
	writeProc(t, root, 4242, 3000, 600)
	second, err := s.read(t0.Add(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if second.cpuOne != 50 || second.cpuBox != 12.5 {
		t.Fatalf("cpu one=%v box=%v", second.cpuOne, second.cpuBox)
	}
	sum := summarise([]sample{first, second}, t0)
	if sum.maxRSSKB != 3000 || sum.n != 1 || sum.avgBox != 12.5 || sum.peakBox != 12.5 {
		t.Fatalf("summary %+v", sum)
	}
	// Samples before steady state are excluded from CPU but not RSS.
	if s2 := summarise([]sample{first, second}, t0.Add(time.Hour)); s2.n != 0 || s2.maxRSSKB != 3000 {
		t.Fatalf("summary %+v", s2)
	}
	if _, err := (&sampler{procRoot: root, pid: 1}).read(t0); err == nil {
		t.Fatal("missing pid should error")
	}
}

func TestJudge(t *testing.T) {
	cfg := config{MaxRSSMB: 500, MaxCPUPct: 50, MaxErrPct: 1}
	mk := func() *result {
		r := &result{cfg: cfg, c: &counters{}, sampled: true}
		r.c.attempts.Store(1000)
		r.c.dripped.Store(10)
		r.cpu = cpuStats{maxRSSKB: 100 << 10, avgBox: 10}
		return r
	}
	r := mk()
	r.judge()
	if !r.pass {
		t.Fatalf("should pass: %v", r.failures)
	}
	cases := map[string]func(*result){
		"5xx":     func(r *result) { r.c.status5xx.Store(1) },
		"errors":  func(r *result) { r.c.errors.Store(11) },
		"rss":     func(r *result) { r.cpu.maxRSSKB = 501 << 10 },
		"cpu":     func(r *result) { r.cpu.avgBox = 50.1 },
		"no-drip": func(r *result) { r.c.dripped.Store(0) },
	}
	for name, mut := range cases {
		r := mk()
		mut(r)
		r.judge()
		if r.pass {
			t.Errorf("%s: should fail", name)
		}
		var b bytes.Buffer
		r.print(&b)
		if !strings.Contains(b.String(), "FAIL") {
			t.Errorf("%s: summary lacks FAIL", name)
		}
	}
	// Held-at-end connections count as dripped.
	r = mk()
	r.c.dripped.Store(0)
	r.c.heldAtEnd.Store(3)
	r.judge()
	if !r.pass {
		t.Fatalf("held connections should count as dripped: %v", r.failures)
	}
}

func TestParseFlags(t *testing.T) {
	c, err := parseFlags([]string{"-conns", "10", "-duration", "2s"}, &bytes.Buffer{})
	if err != nil || c.Conns != 10 || c.IPs != 10 || c.URL != "http://127.0.0.1:8080/lawn/" || c.MaxRSSMB != 500 || c.MaxCPUPct != 50 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := parseFlags([]string{"-conns", "0"}, &bytes.Buffer{}); err == nil {
		t.Fatal("conns 0 should fail")
	}
}

func TestSyntheticIPAndNextURL(t *testing.T) {
	if got := syntheticIP(0); got != "198.18.0.0" {
		t.Fatalf("got %s", got)
	}
	if got := syntheticIP(1<<16 + 258); got != "198.19.1.2" {
		t.Fatalf("got %s", got)
	}
	base, _ := url.Parse("http://127.0.0.1:8080/lawn/")
	page := []byte(`<p>x</p><a href="/elsewhere">y</a><a href="/lawn/archive/abc">z</a>`)
	if got := nextURL(base, page); got != "http://127.0.0.1:8080/lawn/archive/abc" {
		t.Fatalf("got %s", got)
	}
	if got := nextURL(base, []byte("no links")); got != base.String() {
		t.Fatalf("got %s", got)
	}
}

// TestRunLoad drives a tiny in-process server: one route drips, one is fast.
func TestRunLoad(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/lawn/slow", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "" {
			http.Error(w, "no xff", http.StatusBadRequest)
			return
		}
		rc := http.NewResponseController(w)
		w.WriteHeader(http.StatusOK)
		for range 6 {
			if _, err := w.Write([]byte(`<a href="/lawn/slow">x</a>`)); err != nil {
				return
			}
			rc.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
	mux.HandleFunc("/lawn/fast", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<a href="/lawn/fast">x</a>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	base := config{Conns: 4, Duration: 400 * time.Millisecond, Ramp: 20 * time.Millisecond,
		Interval: 20 * time.Millisecond, IPs: 2, Follow: true, MaxErrPct: 1, ClkTck: 100, ProcRoot: "/proc"}

	slow := base
	slow.URL = srv.URL + "/lawn/slow"
	r, err := runLoad(context.Background(), slow, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.judge()
	if r.c.dripped.Load() == 0 || r.c.fast.Load() != 0 || r.c.errors.Load() != 0 || !r.pass {
		var b bytes.Buffer
		r.print(&b)
		t.Fatalf("slow run:\n%s", b.String())
	}

	fast := base
	fast.URL = srv.URL + "/lawn/fast"
	fast.Duration = 100 * time.Millisecond
	r, err = runLoad(context.Background(), fast, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.judge()
	if r.c.fast.Load() == 0 || r.c.dripped.Load() != 0 || r.pass {
		var b bytes.Buffer
		r.print(&b)
		t.Fatalf("fast run should be all fast and FAIL (nothing dripped):\n%s", b.String())
	}
}
