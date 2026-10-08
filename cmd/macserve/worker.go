package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/worker"
	"github.com/jerryfane/macserve/internal/workerclient"
)

func parseConfigArgs(name string, args []string, stdout, stderr io.Writer) (string, bool, int) {
	printUsage := func(w io.Writer) {
		fmt.Fprintf(w, "Usage: macserve %s --config /absolute/path/to/%s.json\n", name, name)
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printUsage(stdout)
		return "", true, 0
	}
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fmt.Fprintln(stderr, "help must be used without other arguments")
			return "", true, 2
		}
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { printUsage(stderr) }
	path := flags.String("config", "", "root-owned service configuration")
	if err := flags.Parse(args); err != nil {
		return "", true, 2
	}
	if *path == "" || flags.NArg() != 0 {
		printUsage(stderr)
		return "", true, 2
	}
	return *path, false, 0
}

func runWorker(args []string, stdout, stderr io.Writer) int {
	path, done, status := parseConfigArgs("worker", args, stdout, stderr)
	if done {
		return status
	}
	if err := hostguard.Worker(path); err != nil {
		fmt.Fprintf(stderr, "macserve worker: %v\n", err)
		return 1
	}
	config, err := workerclient.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(stderr, "macserve worker: %v\n", err)
		return 1
	}
	if config.ControllerUID == uint32(os.Geteuid()) {
		fmt.Fprintln(stderr, "macserve worker: controller and worker UIDs must differ")
		return 1
	}
	engine, err := worker.New(worker.Options{Root: config.Root, ExportRoot: config.ExportRoot})
	if err != nil {
		fmt.Fprintf(stderr, "macserve worker: %v\n", err)
		return 1
	}
	defer engine.Close()
	client, err := workerclient.New(config, engine)
	if err != nil {
		fmt.Fprintf(stderr, "macserve worker: %v\n", err)
		return 1
	}
	defer client.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := client.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "macserve worker: %v\n", err)
		return 1
	}
	return 0
}
