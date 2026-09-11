package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mble/redis-rest-api/internal/app"
)

var (
	version = "v0.2.0-dev"
	commit  = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	const (
		exitSuccess = 0
		exitFailure = 1
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	build := app.Build{Version: version, Commit: commit}
	if err := app.Run(ctx, os.Args[1:], build, os.Stdout, os.Stderr, os.Getenv); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)

		return exitFailure
	}

	return exitSuccess
}
