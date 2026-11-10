// Command macserve-controller is the macserve controller daemon: private
// API, durable queue and worker coordination. It is the only binary that
// links the class K packages (internal/controllerk/...); every root, worker,
// signer and owner role is in the separate macserve binary.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/jerryfane/macserve/internal/controllerk/store"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usageText = `Usage:
  macserve-controller --config /absolute/path/to/controller.json
  macserve-controller version --json

Runs the macserve controller daemon: private API, durable queue and worker
coordination. version --json prints the build identity and store schema
version without opening the store or reading secrets.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "version" {
		return runVersion(args[1:], stdout, stderr)
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, usageText)
		return 0
	}
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fmt.Fprintln(stderr, "help must be used without other arguments")
			return 2
		}
	}
	flags := flag.NewFlagSet("macserve-controller", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stderr, usageText) }
	path := flags.String("config", "", "root-owned controller configuration")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *path == "" || flags.NArg() != 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	return runController(*path, stderr)
}

// versionInfo is the carry contract's `version --json` output.
type versionInfo struct {
	Version            string `json:"version"`
	Commit             string `json:"commit"`
	StoreSchemaVersion int    `json:"store_schema_version"`
}

// buildVersion reads this binary's build identity. A release build
// (checks/release-build.sh, from a clone holding the tag) stamps the main
// module version with the release tag; other builds report Go's pseudo-version
// or "(devel)".
func buildVersion() versionInfo {
	v := versionInfo{Version: "(devel)", StoreSchemaVersion: store.SchemaVersion}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" {
			v.Version = info.Main.Version
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				v.Commit = setting.Value
			}
		}
	}
	return v
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "--json" {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	if err := json.NewEncoder(stdout).Encode(buildVersion()); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
