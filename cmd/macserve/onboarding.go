package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/jerryfane/macserve/internal/setup/plan"
)

// onboardingCommands are the first-time setup commands. main.go dispatches
// any name listed here; new onboarding commands are added only in this
// file. checks/readonly proves that onboardingCommand, runSetup and
// everything they reach cannot change host state.
var onboardingCommands = []struct {
	name, summary, help string
	run                 func(args []string, stdout, stderr io.Writer) int
}{
	{"setup", "First-time setup of this Mac (--plan: read-only preflight)", setupHelp, runSetup},
	{"connect-github", "Create the GitHub App from a manifest and install it on one repository (sudo, after deploy-install)", connectGitHubHelp, runConnectGitHub},
	{"doctor", "Explain failures with fixed check IDs and fixes (not in this release)", doctorHelp, nil},
	{"build", "Start a build of a repository and verify its receipt (not in this release)", buildHelp, nil},
	{"upgrade", "Upgrade behind the stopped gate with verified release bytes (not in this release)", upgradeHelp, nil},
}

const setupHelp = `Usage: macserve setup --plan [--repository OWNER/NAME:ID] [--job-real-name NAME]

First-time setup of this Mac. Run it as yourself, not with sudo: the owner
evidence that qualification needs is refused under sudo.

  --plan  Read-only preflight. Checks this Mac (user, administrator, macOS,
          Apple silicon, SIP, FileVault, Xcode, Tailscale address, free port,
          free account IDs, home directory privacy, existing installation),
          prints the deploy.env setup would install and the ordered setup
          steps. Nothing is written, created or started.
  --repository OWNER/NAME:ID
          Repository pin to include in the generated deploy.env. Without it
          REPOSITORIES is left to the GitHub step.
  --job-real-name NAME
          Display name of the build account (default "macserve build").

Only --plan is available in this release. Exit status: 0 ready, 1 blocked,
2 usage.
`

const doctorHelp = `Usage: macserve doctor [--json]

Read-only diagnosis. Each result has a fixed check ID, a status and a
one-line fix, and never prints secrets. Without sudo a subset runs.

Not available in this release.
`

const buildHelp = `Usage: macserve build --repo OWNER/NAME [--sha HEAD]

Starts a build of a configured repository through the private API, waits for
it and verifies its signed receipt.

Not available in this release.
`

const upgradeHelp = `Usage: macserve upgrade [--check]

Upgrades the installed release behind the stopped gate and job-session
guard, after verifying the release bytes against the tag's SHA256SUMS and
build attestation.

Not available in this release.
`

func onboardingCommand(name string) (func(args []string, stdout, stderr io.Writer) int, bool) {
	for _, c := range onboardingCommands {
		if c.name != name {
			continue
		}
		help, run := c.help, c.run
		return func(args []string, stdout, stderr io.Writer) int {
			if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
				fmt.Fprint(stdout, help)
				return 0
			}
			if run == nil {
				fmt.Fprintf(stderr, "macserve %s: not available in this release; see macserve %s --help\n", name, name)
				return 2
			}
			return run(args, stdout, stderr)
		}, true
	}
	return nil, false
}

func writeOnboardingUsage(w io.Writer) {
	fmt.Fprint(w, "\nFirst-time setup:\n")
	for _, c := range onboardingCommands {
		fmt.Fprintf(w, "  %-14s %s\n", c.name, c.summary)
	}
}

func runSetup(args []string, stdout, stderr io.Writer) int {
	return runSetupWith(plan.SystemProbe(), args, stdout, stderr)
}

// runSetupWith runs setup against probe; tests pass a fake host. Invalid
// --repository or --job-real-name values are reported by the plan as the
// failed check config.choices (exit 1).
func runSetupWith(probe plan.Probe, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	choices := plan.DefaultChoices()
	var planOnly bool
	flags.BoolVar(&planOnly, "plan", false, "")
	flags.StringVar(&choices.Repository, "repository", "", "")
	flags.StringVar(&choices.JobRealName, "job-real-name", choices.JobRealName, "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, setupHelp)
			return 0
		}
		fmt.Fprintf(stderr, "macserve setup: %v\n", err)
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "macserve setup: unexpected arguments; see macserve setup --help")
		return 2
	}
	if probe.Elevated() {
		fmt.Fprintln(stderr, "macserve setup: run it as yourself, not with sudo; qualification refuses owner evidence gathered under sudo, and setup asks for your password once when it needs it.")
		return 2
	}
	if !planOnly {
		fmt.Fprintln(stderr, "macserve setup: only --plan is available in this release; see macserve setup --help")
		return 2
	}
	result := plan.Preflight(context.Background(), probe, choices)
	if err := plan.WritePlan(stdout, result); err != nil {
		fmt.Fprintln(stderr, "macserve setup:", err)
		return 1
	}
	if !result.Ready() {
		return 1
	}
	return 0
}
