package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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
	printUsage := func(w io.Writer) {
		extra := ""
		if observe {
			extra = " [--coexistence-only]"
		}
		fmt.Fprintf(w, "Usage: macserve %s --config /absolute/path/to/maintenance.json%s\n", name, extra)
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printUsage(stdout)
		return 0
	}
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fmt.Fprintln(stderr, "help must be used without other arguments")
			return 2
		}
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	configPath := flags.String("config", "", "root-owned service configuration")
	var coexistenceOnly bool
	if observe {
		flags.BoolVar(&coexistenceOnly, "coexistence-only", false, "observe configured peers without qualification prerequisites")
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *configPath == "" || flags.NArg() != 0 {
		printUsage(stderr)
		return 2
	}
	path := *configPath
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
		var observation any
		var err error
		if coexistenceOnly {
			observation, err = maintenance.ObserveCoexistence(ctx, config)
		} else {
			observation, err = maintenance.Inspect(ctx, config)
		}
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
