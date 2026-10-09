package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/maintenance"
)

func runMaintenance(args []string, stdout, stderr io.Writer, observe bool) int {
	name := "maintenance"
	if observe {
		name = "maintenance-observe"
	}
	path, done, status := parseConfigArgs(name, args, stdout, stderr)
	if done {
		return status
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "macserve maintenance: observer must run as root")
		return 1
	}
	if runtime.GOOS != "darwin" {
		fmt.Fprintln(stderr, "macserve maintenance: observer requires macOS")
		return 1
	}
	if err := hostguard.RootConfig(path); err != nil {
		fmt.Fprintf(stderr, "macserve maintenance: %v\n", err)
		return 1
	}
	config, err := maintenance.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(stderr, "macserve maintenance: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if observe {
		observation, err := maintenance.Inspect(ctx, config)
		if err == nil {
			err = json.NewEncoder(stdout).Encode(observation)
		}
		if err != nil {
			fmt.Fprintf(stderr, "macserve maintenance-observe: %v\n", err)
			return 1
		}
		return 0
	}
	if err := maintenance.Run(ctx, config); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "macserve maintenance: %v\n", err)
		return 1
	}
	return 0
}
