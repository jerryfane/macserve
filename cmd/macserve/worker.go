package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

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
	engine, err := worker.New(executionOptions(config))
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

func executionOptions(config workerclient.Config) worker.Options {
	return worker.Options{Root: config.Root, ExportRoot: config.ExportRoot, WorkspaceRoot: config.WorkspaceRoot, JobUID: config.JobUID, JobGID: config.JobGID, OwnerUID: config.OwnerUID, ControllerUID: config.ControllerUID, HelperPath: config.HelperPath, BaselinePath: config.BaselinePath}
}

func runWorkerReset(args []string, stdout, stderr io.Writer) int {
	const name = "worker-reset"
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "root-owned broker configuration")
	explicit := flags.String("pids", "", "comma-separated PIDs explicitly audited as trusted GUI services")
	flags.Usage = func() {
		fmt.Fprintf(stderr, "Usage: macserve %s --config /absolute/worker.json --pids PID,PID\n", name)
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintf(stdout, "Usage: macserve %s --config /absolute/worker.json --pids PID,PID\n", name)
		return 0
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *configPath == "" || *explicit == "" || flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	var pids []int
	for _, value := range strings.Split(*explicit, ",") {
		pid, err := strconv.Atoi(value)
		if err != nil || pid <= 1 {
			fmt.Fprintln(stderr, "invalid audited GUI PID")
			return 2
		}
		pids = append(pids, pid)
	}
	if err := hostguard.Worker(*configPath); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	config, err := workerclient.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := worker.ResetGUIBaseline(ctx, executionOptions(config), pids); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "Audited GUI baseline reset; scoped cleanup verified, quarantine cleared, pending evidence retained. Native delayed persistence remains a trust limit.")
	return 0
}
