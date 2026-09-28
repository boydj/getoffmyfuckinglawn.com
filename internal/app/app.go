// Package app wires config, storage, attribution, the maze, and the HTTP
// servers together, and runs the background loops (log writer,
// classifier, range refresh, shame rebuild, retention rollup).
package app

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/attrib"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/bots"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/config"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/drip"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/maze"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/server"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/shame"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/smallweb"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/visitors"
	"github.com/boydj/getoffmyfuckinglawn.com/web"
)

// Options inject fakes for tests. Zero values mean production defaults.
type Options struct {
	Resolver attrib.Resolver
	Fetcher  attrib.Fetcher
	Now      func() time.Time
	Clock    drip.Clock
	Logf     func(format string, args ...any)
}

// App is a fully wired service.
type App struct {
	Cfg        config.Config
	Store      *logstore.Store
	Writer     *logstore.Writer
	Classifier *attrib.Classifier
	Ranges     *attrib.RangeStore
	Server     *server.Server
	Metrics    *server.MetricsRegistry

	opt        Options
	lastBuild  atomic.Int64 // unix seconds of last successful shame build
	buildMu    sync.Mutex
	asnEntries atomic.Int64
	patience   *drip.Patience
	rate       *drip.RateLimiter
	crawlers   atomic.Pointer[[]attrib.Crawler] // for the shame builder's exemptions
	exclude    atomic.Pointer[[]netip.Prefix]   // operator networks (exclude_cidrs)
	pages      server.PageRenderer              // maze generator, for the admin preview
	small      *smallweb.Server                 // Gopher and Gemini; nil when both are off
}

func (o *Options) defaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.Clock == nil {
		o.Clock = drip.RealClock{}
	}
}

// New builds the app. It opens the database and loads the corpus, ASN
// table (optional: a missing file only disables ASN attribution), and
// crawler list.
func New(cfg config.Config, opt Options) (*App, error) {
	opt.defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.RequireSecret(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.PublicDir, 0o755); err != nil {
		return nil, fmt.Errorf("app: public dir: %w", err)
	}
	chain, err := maze.LoadCorpus(cfg.CorpusDir)
	if err != nil {
		return nil, fmt.Errorf("app: corpus: %w", err)
	}
	gen := maze.NewGenerator(cfg.Secret, chain)

	st, err := logstore.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	a := &App{Cfg: cfg, Store: st, opt: opt, pages: gen}
	a.Writer = logstore.NewWriter(st, cfg.Log.BufferSize, cfg.Log.BatchSize, cfg.Log.FlushInterval)

	crawlers, err := attrib.LoadCrawlers(cfg.CrawlersFile)
	if err != nil {
		st.Close()
		return nil, err
	}
	a.crawlers.Store(&crawlers)
	a.SetExclude(cfg.Exclude)
	a.Ranges = newRangeStore(cfg, crawlers, opt)
	a.Classifier = newClassifier(cfg, crawlers, a.Ranges, st, opt)

	// Counts bytes for /metrics only; there is no egress cap (operator decision).
	egress := drip.NewEgress(0, func() time.Time { return opt.Now().UTC() })
	dripper := drip.NewDripper(drip.Options{
		ChunkBytes:  cfg.Drip.ChunkBytes,
		Interval:    cfg.Drip.Interval,
		MaxDuration: cfg.Drip.MaxDuration,
		Jitter:      0.3,
	}, opt.Clock, egress)
	limiter := drip.NewLimiter(cfg.Limits.MaxConnsGlobal, cfg.Limits.MaxConnsPerASN, cfg.Limits.MaxConnsPerIP).
		WithPrefixCap(cfg.Limits.MaxConnsPerPrefix)
	rate := drip.NewRateLimiter(cfg.Limits.PrefixRate, cfg.Limits.PrefixBurst, opt.Now)
	a.rate = rate
	var patience *drip.Patience
	if cfg.Drip.Adaptive {
		patience = drip.NewPatience(drip.PatienceOptions{
			Max:    cfg.Drip.MaxDuration,
			Factor: cfg.Drip.AdaptiveFactor,
			Now:    opt.Now,
		})
	}
	a.patience = patience

	home, err := server.RenderHome(web.Templates(cfg.TemplatesDir), server.HomeData{
		RobotsTxt: server.RobotsTxt,
		Bait:      gen.EntryURLs(6),
		BaseURL:   cfg.BaseURL,
		Onion:     cfg.OnionAddress,
		Gopher:    template.URL(smallURL("gopher", cfg.Host(), cfg.GopherListen, 70)),
		Gemini:    template.URL(smallURL("gemini", cfg.Host(), cfg.GeminiListen, 1965)),
	})
	if err != nil {
		st.Close()
		return nil, err
	}

	a.Server = server.New(server.Deps{
		Pages:     gen,
		Dripper:   dripper,
		Limiter:   limiter,
		Rate:      rate,
		Patience:  patience,
		Egress:    egress,
		Logger:    a.Writer,
		Observer:  a.Classifier,
		Trusted:   cfg.Proxies,
		PublicDir: cfg.PublicDir,
		Home:      home,
		BaseURL:   cfg.BaseURL,
		Onion:     cfg.OnionAddress,
		Now:       opt.Now,
	})
	if cfg.GopherListen != "" || cfg.GeminiListen != "" {
		port := 0
		if cfg.GopherListen != "" {
			port, _ = cfg.GopherPort() // validated by config
		}
		a.small = smallweb.New(smallweb.Deps{
			Pages: gen, Dripper: dripper, Limiter: limiter, Rate: rate, Patience: patience,
			Logger: a.Writer, Observer: a.Classifier, Lookup: a.Server.LookupASN,
			Host: cfg.Host(), GopherPort: port, WebURL: cfg.BaseURL,
			MaxDrip: cfg.Drip.MaxDuration, Now: opt.Now,
		})
	}
	if err := a.loadASN(); err != nil {
		opt.Logf("asn: %v (continuing without ASN attribution)", err)
	}
	a.registerMetrics()
	return a, nil
}

func newRangeStore(cfg config.Config, crawlers []attrib.Crawler, opt Options) *attrib.RangeStore {
	return attrib.NewRangeStore(attrib.RangeOptions{
		Crawlers: crawlers,
		CacheDir: cfg.Attrib.RangesCache,
		MaxAge:   cfg.Attrib.RangesRefresh,
		Fetcher:  opt.Fetcher,
		Now:      opt.Now,
	})
}

func newClassifier(cfg config.Config, crawlers []attrib.Crawler, rs *attrib.RangeStore, st *logstore.Store, opt Options) *attrib.Classifier {
	return attrib.NewClassifier(attrib.Options{
		Crawlers:   crawlers,
		Resolver:   opt.Resolver,
		Store:      st,
		Ranges:     rs,
		TTL:        cfg.Attrib.IdentityTTL,
		DNSTimeout: cfg.Attrib.DNSTimeout,
		QueueSize:  cfg.Attrib.QueueSize,
		Workers:    cfg.Attrib.Workers,
		Now:        opt.Now,
	})
}

func (a *App) loadASN() error {
	t, err := attrib.LoadASN(a.Cfg.ASNDBPath)
	if err != nil {
		return err
	}
	a.Server.SetASN(t)
	a.asnEntries.Store(int64(t.Len()))
	a.opt.Logf("asn: loaded %d ranges from %s", t.Len(), a.Cfg.ASNDBPath)
	return nil
}

// Reload re-reads the ASN table and crawler list (SIGHUP). Failures keep
// the previous data.
func (a *App) Reload() error {
	var errs []error
	if err := a.loadASN(); err != nil {
		errs = append(errs, err)
	}
	crawlers, err := attrib.LoadCrawlers(a.Cfg.CrawlersFile)
	if err != nil {
		errs = append(errs, err)
	} else {
		a.crawlers.Store(&crawlers)
		a.Ranges.SetCrawlers(crawlers)
		a.Classifier.SetCrawlers(crawlers)
	}
	return errors.Join(errs...)
}

// SetExclude swaps the operator networks kept out of the reports (config
// exclude_cidrs, re-read on SIGHUP). It takes effect at the next build.
func (a *App) SetExclude(nets []netip.Prefix) { a.exclude.Store(&nets) }

// Handler is the public handler (for tests).
func (a *App) Handler() http.Handler { return a.Server }

// ShameOptions returns the builder options for this config. crawlers
// supplies the robots_exempt user-initiated fetchers (nil: none exempt).
func ShameOptions(cfg config.Config, st *logstore.Store, now func() time.Time, crawlers []attrib.Crawler) shame.Options {
	return shame.Options{
		RobotsExempt: func(ua string) bool { return attrib.RobotsExemptUA(crawlers, ua) },
		DB:           st.DB(),
		Templates:    web.Templates(cfg.TemplatesDir),
		PublicDir:    cfg.PublicDir,
		RobotsTxt:    server.RobotsTxt,
		BaseURL:      cfg.BaseURL,
		SessionGap:   cfg.Session.Gap,
		BlocklistMin: cfg.Shame.BlocklistMinViolations,
		Now:          now,
		Exclude:      cfg.Exclude,
	}
}

// BuildShame rebuilds the static leaderboard. Serialized.
func (a *App) BuildShame(ctx context.Context) (*shame.Report, error) {
	a.buildMu.Lock()
	defer a.buildMu.Unlock()
	opt := ShameOptions(a.Cfg, a.Store, a.opt.Now, *a.crawlers.Load())
	opt.Exclude = *a.exclude.Load()
	r, err := shame.Build(ctx, opt)
	if err == nil {
		a.lastBuild.Store(a.opt.Now().Unix())
	}
	return r, err
}

// Run starts every loop and both listeners, and blocks until ctx is done,
// then shuts down gracefully: listeners stop, in-flight drips are cut, the
// log writer drains, and the database is closed.
func (a *App) Run(ctx context.Context) error {
	pub := server.NewPublicServer(a.Cfg.Listen, a.Server, a.Cfg.Drip.MaxDuration)
	adm := server.NewAdminServer(a.Cfg.AdminListen, a.Metrics, a.pages)
	pubLn, err := net.Listen("tcp", a.Cfg.Listen)
	if err != nil {
		return err
	}
	admLn, err := net.Listen("tcp", a.Cfg.AdminListen)
	if err != nil {
		pubLn.Close()
		return err
	}
	small, err := a.listenSmallWeb()
	if err != nil {
		pubLn.Close()
		admLn.Close()
		return err
	}
	return a.serve(ctx, pub, adm, pubLn, admLn, small...)
}

// smallURL is the public URL of a small-web mirror listening on listen
// ("" when off), with the port only when it isn't the protocol's default.
func smallURL(scheme, host, listen string, defPort int) string {
	if listen == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "0" || port == strconv.Itoa(defPort) {
		return scheme + "://" + host + "/"
	}
	return scheme + "://" + net.JoinHostPort(host, port) + "/"
}

// smallListener is a Gopher or Gemini listener ready to serve.
type smallListener struct {
	name  string
	ln    net.Listener
	serve func(net.Listener) error
}

// listenSmallWeb opens the Gopher and Gemini listeners that are configured
// (binding ports below 1024 needs CAP_NET_BIND_SERVICE; see lawn.service).
func (a *App) listenSmallWeb() ([]smallListener, error) {
	if a.small == nil {
		return nil, nil
	}
	var out []smallListener
	fail := func(err error) ([]smallListener, error) {
		for _, l := range out {
			l.ln.Close()
		}
		return nil, err
	}
	if a.Cfg.GopherListen != "" {
		ln, err := net.Listen("tcp", a.Cfg.GopherListen)
		if err != nil {
			return fail(fmt.Errorf("gopher: %w", err))
		}
		out = append(out, smallListener{"gopher", ln, a.small.ServeGopher})
	}
	if a.Cfg.GeminiListen != "" {
		cert, err := smallweb.LoadOrCreateCert(a.Cfg.GeminiCertDir, a.Cfg.Host(), a.opt.Now())
		if err != nil {
			return fail(err)
		}
		ln, err := net.Listen("tcp", a.Cfg.GeminiListen)
		if err != nil {
			return fail(fmt.Errorf("gemini: %w", err))
		}
		out = append(out, smallListener{"gemini", ln, func(l net.Listener) error { return a.small.ServeGemini(l, cert) }})
	}
	return out, nil
}

func (a *App) serve(ctx context.Context, pub, adm *http.Server, pubLn, admLn net.Listener, small ...smallListener) error {
	bg, cancelBG := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	start := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(bg) }()
	}
	var writerWG sync.WaitGroup
	writerCtx, stopWriter := context.WithCancel(context.Background())
	writerWG.Add(1)
	go func() { defer writerWG.Done(); a.Writer.Run(writerCtx) }()

	start(a.Classifier.Run)
	start(func(ctx context.Context) { a.Ranges.RefreshLoop(ctx, a.Cfg.Attrib.RangesRefresh, a.opt.Logf) })
	start(a.shameLoop)
	start(a.retentionLoop)

	errc := make(chan error, 2+len(small))
	go func() { errc <- pub.Serve(pubLn) }()
	go func() { errc <- adm.Serve(admLn) }()
	a.opt.Logf("serving public on %s, admin on %s", pubLn.Addr(), admLn.Addr())
	for _, l := range small {
		go func() { errc <- l.serve(l.ln) }()
		a.opt.Logf("serving %s on %s", l.name, l.ln.Addr())
	}

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, smallweb.ErrClosed) {
			runErr = err
		}
	}
	// Drips hold connections for minutes; give them a moment, then cut.
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := pub.Shutdown(sctx); err != nil {
		pub.Close()
	}
	adm.Shutdown(sctx)
	if a.small != nil {
		a.small.Shutdown(sctx)
	}
	cancel()
	cancelBG()
	wg.Wait()
	stopWriter()
	writerWG.Wait()
	return errors.Join(runErr, a.Store.Close())
}

func (a *App) shameLoop(ctx context.Context) {
	build := func() {
		t0 := time.Now()
		r, err := a.BuildShame(ctx)
		if err != nil {
			if ctx.Err() == nil {
				a.opt.Logf("shame: build failed: %v", err)
			}
			return
		}
		for _, w := range r.Warnings {
			a.opt.Logf("shame: %s", w)
		}
		a.opt.Logf("shame: rebuilt in %s", time.Since(t0).Round(time.Millisecond))
	}
	build()
	t := time.NewTicker(a.Cfg.Shame.RebuildInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			build()
		}
	}
}

// retentionLoop rolls old raw rows into daily_aggregates shortly after
// start and then every 6 hours (cheap when nothing is due).
func (a *App) retentionLoop(ctx context.Context) {
	run := func() {
		n, err := a.Store.Rollup(ctx, a.opt.Now(), a.Cfg.Retention.RawRequestsDays, a.Cfg.Session.Gap.Milliseconds())
		if err != nil {
			if ctx.Err() == nil {
				a.opt.Logf("retention: %v", err)
			}
			return
		}
		if n > 0 {
			a.opt.Logf("retention: rolled up %d raw rows", n)
		}
	}
	first := time.NewTimer(time.Minute)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
	}
	run()
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func (a *App) registerMetrics() {
	a.Metrics = server.NewMetricsRegistry(a.Server)
	g := func(name, help, typ string, f func() float64) {
		a.Metrics.Register(server.Gauge{Name: name, Help: help, Type: typ, Value: f})
	}
	g("lawn_log_written_total", "Rows written by the async log writer.", "counter", func() float64 { return float64(a.Writer.Stats().Written) })
	g("lawn_log_writer_dropped_total", "Rows the writer dropped (queue full).", "counter", func() float64 { return float64(a.Writer.Stats().Dropped) })
	g("lawn_log_writer_errors_total", "Rows lost to failed SQLite writes.", "counter", func() float64 { return float64(a.Writer.Stats().Errors) })
	g("lawn_log_queue_depth", "Rows waiting in the writer queue.", "gauge", func() float64 { return float64(a.Writer.Stats().Queued) })
	g("lawn_classifier_queue_depth", "Identities waiting for verification.", "gauge", func() float64 { return float64(a.Classifier.Stats().Queued) })
	g("lawn_classifier_dropped_total", "Identities not queued because the queue was full.", "counter", func() float64 { return float64(a.Classifier.Stats().Dropped) })
	g("lawn_classifier_classified_total", "Identities classified.", "counter", func() float64 { return float64(a.Classifier.Stats().Classified) })
	g("lawn_rate_limit_prefixes", "Network prefixes with a live request-rate bucket.", "gauge", func() float64 { return float64(a.rate.Len()) })
	g("lawn_patience_tracked", "Clients with a learned drip budget (adaptive drip).", "gauge", func() float64 { return float64(a.patience.Len()) })
	g("lawn_classifier_ptr_lookups_total", "Reverse-DNS lookups recorded for the hosts table.", "counter", func() float64 { return float64(a.Classifier.Stats().PTRLookups) })
	g("lawn_asn_ranges", "Ranges in the loaded ASN table.", "gauge", func() float64 { return float64(a.asnEntries.Load()) })
	if sw := a.small; sw != nil {
		g("lawn_gopher_requests_total", "Gopher requests.", "counter", func() float64 { return float64(sw.Metrics.Gopher.Load()) })
		g("lawn_gemini_requests_total", "Gemini requests.", "counter", func() float64 { return float64(sw.Metrics.Gemini.Load()) })
		g("lawn_smallweb_violations_total", "Gopher and Gemini requests for /lawn/.", "counter", func() float64 { return float64(sw.Metrics.Violations.Load()) })
		g("lawn_smallweb_shed_total", "Gopher and Gemini maze requests over a limit.", "counter", func() float64 { return float64(sw.Metrics.Shed.Load()) })
		g("lawn_smallweb_bytes_sent_total", "Bytes sent over Gopher and Gemini.", "counter", func() float64 { return float64(sw.Metrics.BytesSent.Load()) })
	}
	g("lawn_shame_last_build_timestamp_seconds", "Unix time of the last successful shame build.", "gauge", func() float64 { return float64(a.lastBuild.Load()) })
}

// Close releases resources for an App that was never Run.
func (a *App) Close() error { return a.Store.Close() }

// BuildShameOnce is `lawn build-shame`.
func BuildShameOnce(ctx context.Context, cfg config.Config, out io.Writer) error {
	st, err := logstore.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := os.MkdirAll(cfg.PublicDir, 0o755); err != nil {
		return err
	}
	r, err := shame.Build(ctx, ShameOptions(cfg, st, time.Now, loadCrawlersOrNil(cfg, out)))
	if err != nil {
		return err
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(out, "warning: %s\n", w)
	}
	fmt.Fprintf(out, "built %s/shame (%d offender groups)\n", cfg.PublicDir, len(r.Groups))
	return nil
}

// Stats is `lawn stats`.
func Stats(ctx context.Context, cfg config.Config, since string, limit int, out io.Writer) error {
	switch since {
	case "24h", "7d", "30d", "all":
	default:
		return fmt.Errorf("--since must be one of 24h, 7d, 30d, all (got %q)", since)
	}
	st, err := logstore.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	r, err := shame.Collect(ctx, ShameOptions(cfg, st, time.Now, loadCrawlersOrNil(cfg, out)))
	if err != nil {
		return err
	}
	return shame.WriteStats(out, r, since, limit)
}

// VerifyRefresh is `lawn verify-refresh`: refresh vendor IP ranges, then
// re-verify stale identities and classify unclassified violators.
func VerifyRefresh(ctx context.Context, cfg config.Config, opt Options, out io.Writer) error {
	opt.defaults()
	crawlers, err := attrib.LoadCrawlers(cfg.CrawlersFile)
	if err != nil {
		return err
	}
	st, err := logstore.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	rs := newRangeStore(cfg, crawlers, opt)
	rerr := rs.RefreshAll(ctx)
	if rerr != nil {
		fmt.Fprintf(out, "range refresh: %v (continuing with cached ranges)\n", rerr)
	}
	c := newClassifier(cfg, crawlers, rs, st, opt)
	n, err := c.ReverifyStale(ctx, st.DB())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "re-verified %d identities\n", n)
	return nil
}

// BotsOptions are the `lawn bots` flags.
type BotsOptions struct {
	Since       string
	UnknownOnly bool
	NewOnly     bool
	All         bool
	Limit       int
	Details     int
}

// Bots is `lawn bots`: a private report on every bot-like client.
func Bots(ctx context.Context, cfg config.Config, o BotsOptions, out io.Writer) error {
	since, err := bots.ParseSince(o.Since)
	if err != nil {
		return err
	}
	crawlers, err := attrib.LoadCrawlers(cfg.CrawlersFile)
	if err != nil {
		return err
	}
	st, err := logstore.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	r, err := bots.Collect(ctx, bots.Options{DB: st.DB(), Crawlers: crawlers, Since: since, All: o.All, Exclude: cfg.Exclude})
	if err != nil {
		return err
	}
	bots.Write(out, r, bots.WriteOptions{UnknownOnly: o.UnknownOnly, NewOnly: o.NewOnly, Limit: o.Limit, Details: o.Details})
	return nil
}

// Visitors is `lawn visitors`: the private per-request log. Since uses the
// same syntax as `lawn bots` ("24h", "7d", "all").
func Visitors(ctx context.Context, cfg config.Config, since string, o visitors.Options, out io.Writer) error {
	d, err := bots.ParseSince(since)
	if err != nil {
		return err
	}
	st, err := logstore.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	o.DB, o.Since, o.Exclude = st.DB(), d, cfg.Exclude
	r, err := visitors.List(ctx, o)
	if err != nil {
		return err
	}
	visitors.Write(out, r)
	return nil
}

// loadCrawlersOrNil loads crawlers.yaml for the one-off commands. Without
// it nobody is treated as robots-exempt (the conservative direction) and a
// warning is printed.
func loadCrawlersOrNil(cfg config.Config, out io.Writer) []attrib.Crawler {
	cs, err := attrib.LoadCrawlers(cfg.CrawlersFile)
	if err != nil {
		fmt.Fprintf(out, "warning: %v (no user-initiated fetchers will be exempted)\n", err)
		return nil
	}
	return cs
}
