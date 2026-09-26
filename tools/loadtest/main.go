// Command loadtest is the SPEC section 12 load test: it holds N concurrent
// slow-reading connections open against the maze, samples the server's RSS
// and CPU from /proc, and prints PASS/FAIL against the thresholds.
//
// Usage: go run ./tools/loadtest -url http://127.0.0.1:8080/lawn/ -pid <server pid>
// See tools/loadtest.sh for a wrapper that builds and starts the server.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, err := parseFlags(os.Args[1:], os.Stderr)
	if err != nil {
		os.Exit(2)
	}
	if err := raiseNoFile(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: raising RLIMIT_NOFILE: %v\n", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var progress io.Writer = os.Stdout
	if cfg.Quiet {
		progress = nil
	}
	res, err := runLoad(ctx, cfg, progress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loadtest: %v\n", err)
		os.Exit(2)
	}
	res.judge()
	res.print(os.Stdout)
	if !res.pass {
		os.Exit(1)
	}
}
