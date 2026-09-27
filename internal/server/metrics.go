package server

import (
	"bufio"
	"fmt"
	"html"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/drip"
)

type route int

const (
	routeOther route = iota
	routeHome
	routeRobots
	routeSitemap
	routeLawn
	routeShame
	routeHealth
	numRoutes
)

var routeNames = [numRoutes]string{"other", "home", "robots", "sitemap", "lawn", "shame", "healthz"}

// Metrics are hot-path counters; all fields are atomics.
type Metrics struct {
	Requests    [numRoutes]atomic.Uint64
	Violations  atomic.Uint64
	Dripped     atomic.Uint64
	Fast        atomic.Uint64
	LimitShed   atomic.Uint64
	BytesSent   atomic.Uint64
	LogDropped  atomic.Uint64
	RateLimited atomic.Uint64
	DripEnds    [4]atomic.Uint64 // by drip.Outcome
}

func (m *Metrics) observeDrip(o drip.Outcome) {
	if int(o) < len(m.DripEnds) {
		m.DripEnds[o].Add(1)
	}
}

func (m *Metrics) observe(r route, violation, dripped bool, sent int64) {
	m.Requests[r].Add(1)
	if violation {
		m.Violations.Add(1)
		if dripped {
			m.Dripped.Add(1)
		} else {
			m.Fast.Add(1)
		}
	}
	if sent > 0 {
		m.BytesSent.Add(uint64(sent))
	}
}

// Gauge is an extra metric sampled at scrape time (writer, classifier, etc.).
type Gauge struct {
	Name, Help, Type string // Type: "gauge" or "counter"
	Value            func() float64
}

// MetricsRegistry renders Prometheus text format. Extra gauges may be
// registered by the app wiring.
type MetricsRegistry struct {
	srv    *Server
	mu     sync.Mutex
	extras []Gauge
}

// NewMetricsRegistry exposes s's counters plus any registered extras.
func NewMetricsRegistry(s *Server) *MetricsRegistry { return &MetricsRegistry{srv: s} }

// Register adds a scrape-time metric.
func (m *MetricsRegistry) Register(g Gauge) {
	m.mu.Lock()
	m.extras = append(m.extras, g)
	m.mu.Unlock()
}

// ServeHTTP writes the Prometheus text exposition.
func (m *MetricsRegistry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	b := bufio.NewWriter(w)
	defer b.Flush()
	mt := m.srv.Metrics
	fmt.Fprintf(b, "# HELP lawn_requests_total Requests by route.\n# TYPE lawn_requests_total counter\n")
	for i := route(0); i < numRoutes; i++ {
		fmt.Fprintf(b, "lawn_requests_total{route=%q} %d\n", routeNames[i], mt.Requests[i].Load())
	}
	counter := func(name, help string, v uint64) {
		fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	counter("lawn_violations_total", "Requests to /lawn/*.", mt.Violations.Load())
	counter("lawn_dripped_total", "Maze pages served through the slow drip.", mt.Dripped.Load())
	counter("lawn_fast_total", "Maze pages served fast (limits, HEAD).", mt.Fast.Load())
	counter("lawn_limit_shed_total", "Maze pages served fast because a connection cap was hit.", mt.LimitShed.Load())
	counter("lawn_bytes_sent_total", "Response body bytes sent.", mt.BytesSent.Load())
	counter("lawn_rate_limited_total", "Maze requests answered with the tiny page because their /24 or /48 exceeded prefix_rate.", mt.RateLimited.Load())
	counter("lawn_log_dropped_total", "Log records dropped because the writer queue was full.", mt.LogDropped.Load())
	fmt.Fprintf(b, "# HELP lawn_drip_end_total Dripped maze responses by how they ended.\n# TYPE lawn_drip_end_total counter\n")
	for o := drip.Completed; int(o) < len(mt.DripEnds); o++ {
		fmt.Fprintf(b, "lawn_drip_end_total{reason=%q} %d\n", o.String(), mt.DripEnds[o].Load())
	}
	gauge := func(name, help string, v float64) {
		fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
	}
	gauge("lawn_active_drips", "Connections currently being dripped.", float64(m.srv.d.Limiter.Active()))
	gauge("lawn_egress_today_bytes", "Bytes sent since UTC midnight.", float64(m.srv.d.Egress.Today()))

	m.mu.Lock()
	extras := append([]Gauge(nil), m.extras...)
	m.mu.Unlock()
	sort.Slice(extras, func(i, j int) bool { return extras[i].Name < extras[j].Name })
	for _, g := range extras {
		typ := g.Type
		if typ == "" {
			typ = "gauge"
		}
		fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n%s %g\n", g.Name, g.Help, g.Name, typ, g.Name, g.Value())
	}
}

func buildSitemap(baseURL string, entries []string) []byte {
	var b []byte
	b = append(b, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`+"\n"...)
	add := func(p string) {
		b = append(b, "  <url><loc>"...)
		b = append(b, html.EscapeString(baseURL+p)...)
		b = append(b, "</loc></url>\n"...)
	}
	add("/")
	add("/shame/")
	for _, e := range entries {
		add(e)
	}
	b = append(b, "</urlset>\n"...)
	return b
}
