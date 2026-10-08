package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jerryfane/macserve/internal/worker"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "_job-exec", "_job-signal", "_job-login-items":
		var err error
		if args[0] == "_job-exec" {
			err = worker.PrivateJobExec(args[1:])
		} else if args[0] == "_job-login-items" {
			err = worker.PrivateJobLoginItems(args[1:])
		} else {
			err = worker.PrivateJobSignal(args[1:])
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "worker-reset":
		return runWorkerReset(args[1:], stdout, stderr)
	case "-h", "--help":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "macserve: help does not accept arguments")
			return 2
		}
		usage(stdout)
		return 0
	case "worker":
		return runWorker(args[1:], stdout, stderr)
	case "controller":
		if len(args) == 2 && (args[1] == "-h" || args[1] == "--help") {
			fmt.Fprintf(stdout, "Usage: macserve %s\n\nThis command is not implemented yet; no service is started.\n", args[0])
			return 0
		}
		if len(args) != 1 {
			fmt.Fprintf(stderr, "macserve %s: unexpected arguments %q\n", args[0], args[1:])
			return 2
		}
		fmt.Fprintf(stderr, "macserve %s: not implemented yet; no service started\n", args[0])
		return 1
	default:
		fmt.Fprintf(stderr, "macserve: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: macserve <command>

Commands:
  controller  Queue, API and evidence service (not implemented yet)
  worker      Protected root execution broker via the private controller socket
  worker-reset  Reset job-user persistence and record audited GUI baseline PIDs

Use macserve <command> --help for command help.
`)
}
