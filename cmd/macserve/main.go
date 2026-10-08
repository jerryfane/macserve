package main

import (
	"fmt"
	"io"
	"os"
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
	case "-h", "--help":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "macserve: help does not accept arguments")
			return 2
		}
		usage(stdout)
		return 0
	case "controller", "worker":
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
  worker      Native build and test execution (not implemented yet)

Use macserve <command> --help for command help.
`)
}
