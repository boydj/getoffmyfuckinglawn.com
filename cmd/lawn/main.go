// Command lawn is the tarpit server and its maintenance subcommands.
//
//	lawn serve                 # run server + shame rebuild ticker
//	lawn build-shame           # one-off leaderboard build
//	lawn verify-refresh        # refresh vendor IP ranges, re-verify stale identities
//	lawn stats [--since 24h]   # print top offenders to stdout
//	lawn gen-robots            # print robots.txt in effect
//
// Every subcommand accepts -config <path> (default $LAWN_CONFIG, else
// /etc/lawn/config.yaml if present, else built-in defaults).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/app"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/config"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/server"
	"github.com/boydj/getoffmyfuckinglawn.com/internal/visitors"
)

const usage = `usage: lawn <command> [-config path] [flags]

commands:
  serve            run server + shame rebuild ticker
  build-shame      one-off leaderboard build
  verify-refresh   refresh vendor IP ranges, re-verify stale identities
  stats            print top offenders (--since 24h|7d|30d|all, --limit N)
  bots             private report on every bot seen, compliant or not; flags
                   new and unknown ones (--since 7d|36h|all, --unknown, --new,
                   --all, --limit N, --details N)
  visitors         private log of recent visits, newest first (--since 24h|7d|all,
                   --limit N [100], --ip ADDR|CIDR, --asn N, --ua TEXT,
                   --path PREFIX, --scheme S, --lawn, --operators); --ip ADDR gives
                   that client's timeline, oldest first
  gen-robots       print robots.txt in effect
  version          print the build version
`

// version is set at build time: -ldflags "-X main.version=<git sha>".
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "lawn:", err)
		os.Exit(1)
	}
}

func defaultConfigPath() string {
	if p := os.Getenv("LAWN_CONFIG"); p != "" {
		return p
	}
	if _, err := os.Stat("/etc/lawn/config.yaml"); err == nil {
		return "/etc/lawn/config.yaml"
	}
	return ""
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		return flag.ErrHelp
	}
	cmd, rest := args[0], args[1:]
	if cmd == "version" || cmd == "-version" || cmd == "--version" {
		fmt.Fprintln(stdout, version)
		return nil
	}
	fs := flag.NewFlagSet("lawn "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "path to config.yaml")
	since := fs.String("since", "24h", "stats window: 24h, 7d, 30d, or all")
	limit := fs.Int("limit", 20, "stats/bots: rows per section")
	unknown := fs.Bool("unknown", false, "bots: only bots not in crawlers.yaml")
	onlyNew := fs.Bool("new", false, "bots: only bots first seen in the last 7 days")
	all := fs.Bool("all", false, "bots: include clients with no bot signal (likely people)")
	details := fs.Int("details", 10, "bots: detail blocks for unknown/new bots")
	ipFlag := fs.String("ip", "", "visitors: one address (timeline) or a CIDR")
	asnFlag := fs.String("asn", "", "visitors: AS number, e.g. AS15169")
	uaFlag := fs.String("ua", "", "visitors: user agent contains (case-insensitive)")
	pathFlag := fs.String("path", "", "visitors: path starts with")
	lawnOnly := fs.Bool("lawn", false, "visitors: only /lawn/ requests")
	schemeFlag := fs.String("scheme", "", "visitors: only https, http, gopher or gemini")
	operators := fs.Bool("operators", false, "visitors: include your own networks (exclude_cidrs), marked *")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath, os.Getenv)
	if err != nil {
		return err
	}
	if cmd == "gen-robots" {
		// Loading the config first means this doubles as a config check.
		fmt.Fprint(stdout, server.RobotsTxt)
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "serve":
		return serve(ctx, cfg, *cfgPath)
	case "build-shame":
		return app.BuildShameOnce(ctx, cfg, stdout)
	case "verify-refresh":
		return app.VerifyRefresh(ctx, cfg, app.Options{}, stdout)
	case "stats":
		return app.Stats(ctx, cfg, *since, *limit, stdout)
	case "bots":
		window := *since
		explicit := false
		fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "since" })
		if !explicit {
			window = "7d"
		}
		return app.Bots(ctx, cfg, app.BotsOptions{Since: window, UnknownOnly: *unknown, NewOnly: *onlyNew,
			All: *all, Limit: *limit, Details: *details}, stdout)
	case "visitors":
		n := *limit
		explicit := false
		fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "limit" })
		if !explicit {
			n = 100
		}
		return app.Visitors(ctx, cfg, *since, visitors.Options{IP: *ipFlag, ASN: *asnFlag, UA: *uaFlag,
			Path: *pathFlag, LawnOnly: *lawnOnly, Scheme: *schemeFlag, Operators: *operators, Limit: n}, stdout)
	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func serve(ctx context.Context, cfg config.Config, cfgPath string) error {
	log.Printf("lawn %s starting", version)
	a, err := app.New(cfg, app.Options{Logf: log.Printf})
	if err != nil {
		return err
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				err := a.Reload()
				// exclude_cidrs is the one config.yaml key applied live;
				// everything else still needs a restart.
				if c, cerr := config.Load(cfgPath, os.Getenv); cerr != nil {
					err = errors.Join(err, cerr)
				} else {
					a.SetExclude(c.Exclude)
				}
				if err != nil {
					log.Printf("reload: %v", err)
				} else {
					log.Printf("reload: ok")
				}
			}
		}
	}()
	return a.Run(ctx)
}
