package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/worker"
	"github.com/jerryfane/macserve/internal/workerclient"
)

// A full scan has its own eight-minute bound. Public review/accept/reset leave
// one additional minute for fixed account and protected-authority overhead.
const workerPersistenceInspectionTimeout = worker.PersistenceOperationTimeout

func workerPersistenceInspectionContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, workerPersistenceInspectionTimeout)
}

func runWorkerPersistence(args []string, stdout, stderr io.Writer) int {
	const usage = "Usage: macserve worker-persistence inspect --config /absolute/worker.json --out /root/private-candidate.json\n       macserve worker-persistence accept --config /absolute/worker.json --candidate /root/private-candidate.json --reviewed-sha256 SHA256\n"
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if len(args) == 0 || (args[0] != "inspect" && args[0] != "accept") {
		fmt.Fprint(stderr, usage)
		return 2
	}
	flags := flag.NewFlagSet("worker-persistence "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "root-protected worker configuration")
	var candidate, reviewed *string
	if args[0] == "inspect" {
		candidate = flags.String("out", "", "new root-private review candidate, never authority")
	} else {
		candidate = flags.String("candidate", "", "exact individually reviewed root-private candidate")
		reviewed = flags.String("reviewed-sha256", "", "explicit digest of the reviewed candidate")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if *configPath == "" || *candidate == "" || flags.NArg() != 0 || (reviewed != nil && *reviewed == "") {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err := hostguard.Worker(*configPath); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	cfg, err := workerclient.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := workerPersistenceInspectionContext(context.Background())
	defer cancel()
	if args[0] == "inspect" {
		digest, err := worker.ReviewPersistence(ctx, executionOptions(cfg), *candidate)
		if digest != "" {
			fmt.Fprintln(stdout, "Candidate SHA256:", digest, "(private review only; not accepted)")
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if err := worker.AcceptPersistence(ctx, executionOptions(cfg), *candidate, *reviewed); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "Exact reviewed persistence accepted. Baseline reset and requalification still required; quarantine and services unchanged.")
	return 0
}
