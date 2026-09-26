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
)

const usage = `usage: lawn <command> [-config path] [flags]

commands:
  serve            run server + shame rebuild ticker
  build-shame      one-off leaderboard build
  verify-refresh   refresh vendor IP ranges, re-verify stale identities
  stats            print top offenders (--since 24h|7d|30d|all, --limit N)
  gen-robots       print robots.txt in effect
`

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
	fs := flag.NewFlagSet("lawn "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "path to config.yaml")
	since := fs.String("since", "24h", "stats window: 24h, 7d, 30d, or all")
	limit := fs.Int("limit", 20, "stats: rows per section")
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
		return serve(ctx, cfg)
	case "build-shame":
		return app.BuildShameOnce(ctx, cfg, stdout)
	case "verify-refresh":
		return app.VerifyRefresh(ctx, cfg, app.Options{}, stdout)
	case "stats":
		return app.Stats(ctx, cfg, *since, *limit, stdout)
	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func serve(ctx context.Context, cfg config.Config) error {
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
				if err := a.Reload(); err != nil {
					log.Printf("reload: %v", err)
				} else {
					log.Printf("reload: ok")
				}
			}
		}
	}()
	return a.Run(ctx)
}
