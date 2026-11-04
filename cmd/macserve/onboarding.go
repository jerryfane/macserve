package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/jerryfane/macserve/internal/setup/plan"
)

// onboardingCommands are the first-time setup commands. main.go dispatches
// any name listed here; new onboarding commands are added only in this
// file. Names starting with "_" are internal (started by setup itself) and
// not listed in the usage. checks/readonly proves that onboardingCommand,
// runSetup (outside its apply clause), runDoctor (outside its --live
// clause), runUpgrade (outside its apply clause) and everything they reach
// cannot change host state.
var onboardingCommands = []struct {
	name, summary, help string
	run                 func(args []string, stdout, stderr io.Writer) int
}{
	{"setup", "First-time setup of this Mac (--plan: read-only preflight)", setupHelp, runSetup},
	{"connect-github", "Create the GitHub App from a manifest and install it on one repository (sudo, after deploy-install)", connectGitHubHelp, runConnectGitHub},
	{"doctor", "Diagnose this Mac with fixed check IDs and fixes (read-only without --live)", doctorHelp, runDoctor},
	{"build", "Build a commit of your repository here and verify its receipt", buildHelp, runBuild},
	{"upgrade", "Upgrade to a newer release with verified bytes (--plan: read-only)", upgradeHelp, runUpgrade},
	{"_setup-root", "", setupRootHelp, runSetupRoot},
	{"_fda-check", "", fdaCheckHelp, runFDACheck},
}

const setupHelp = `Usage: macserve setup --plan [--repository OWNER/NAME:ID] [--job-real-name NAME]
       macserve setup [--repository OWNER/NAME:ID] [--job-real-name NAME]
                      [--sha256sums SHA256SUMS | --sha256 HEX]

First-time setup of this Mac. Run it as yourself, not with sudo: the owner
evidence that qualification needs is refused under sudo.

  --plan  Read-only preflight. Checks this Mac (user, administrator, macOS,
          Apple silicon, SIP, FileVault, Xcode, Tailscale address, free port,
          free account IDs, home directory privacy, existing installation),
          prints the deploy.env setup would install and the ordered setup
          steps. Nothing is written, created or started.
  --repository OWNER/NAME:ID
          Repository pin for the generated deploy.env (numeric ID:
          gh api repos/OWNER/NAME --jq .id). Required by setup before
          install.
  --job-real-name NAME
          Display name of the build account (default "macserve build").
  --sha256sums SHA256SUMS
          The release's SHA256SUMS file (verify the release first, see
          docs/install.md); setup takes the macserve-darwin-arm64 digest
          from it. Required before install, unless --sha256 is given.
  --sha256 HEX
          The release digest of this macserve, instead of --sha256sums.
          Setup refuses to run or install a binary with another digest; it
          never takes the digest from the binary itself. After install the
          helper is the installed /Library/macserve/bin/macserve.

Without --plan, setup runs the preflight, asks you to confirm, then asks
for your password once (sudo) to start its root helper, and continues from
its ledger: install (deploy-install, services disabled), GitHub (prints
the commands to run), the Xcode system steps, and the owner actions (Full
Disk Access, one build-account login), each detected. Run it again to
resume. This release stops before qualification round 1.

Exit status: 0 ready or stopped at a resumable point, 1 blocked or
failed, 2 usage.
`

const setupRootHelp = `Usage: sudo macserve _setup-root [--upgrade] --sha256 HEX

The root helper of macserve setup (and, with --upgrade, of macserve
upgrade), which starts it; do not run it yourself. It serves a fixed set
of steps to your login only and exits when setup or upgrade disconnects
or after 15 idle minutes.
`

const fdaCheckHelp = `Usage: macserve _fda-check

Run by the transient launchd job macserve setup bootstraps: reports whether
this binary has Full Disk Access in launchd context.
`

const doctorHelp = `Usage: macserve doctor [--json] [--sha256sums SHA256SUMS | --sha256 HEX]
       sudo macserve doctor [--json] [--live] [...]

Read-only diagnosis of the installed macserve. Each result has a fixed
check ID, a status (pass, warn, fail, unknown) and a one-line fix, and
never prints secrets or raw command output. Without sudo the checks that
read root-only files report unknown; sudo runs them.

  --json        The same report as JSON (schema 1).
  --sha256sums SHA256SUMS, --sha256 HEX
                Compare the installed binary with this release digest
                instead of the one setup recorded (release.bytes).
  --live        (exactly this spelling) With sudo, also run the two checks that act: Full Disk
                Access from a transient launchd job (tcc.fda), and the
                GitHub App's installations (github.app). Without --live
                doctor writes, starts and contacts nothing.

Checks: host.macos host.arch host.sip host.filevault xcode.pins net.tailnet
release.bytes fs.protect tcc.fda session.job persistence qual.state
svc.state health github.app disk setup.ledger

Exit status: 0 nothing failed, 1 a check failed, 2 usage.
`

const buildHelp = `Usage: macserve build [--repo OWNER/NAME] [--sha SHA] [--profile ID] [--no-follow]
       macserve build --follow JOB

Submits a build of a commit to this Mac's macserve through its private API,
prints the job's logs until it finishes and verifies its signed receipt
against /Library/macserve/config/deployment-pins.json: the receipt must be
this job's, for the exact request sent, and a complete success with exit
code 0. Run it from your
repository's root: --repo defaults to the GitHub remote "origin" and --sha
to HEAD (push it first; macserve fetches the commit from GitHub). Nothing
in the repository is run on this side; .macserve.json is only checked.

The API token comes from your login keychain item "macserve API token"
(account: your user name) that setup saved; it is never printed.

  --profile ID  The profile or template to use, when more than one admits
                the repository.
  --no-follow   Print the job ID and return after submitting.
  --follow JOB  Follow a job submitted earlier.

Exit status: 0 the job succeeded and its receipt verifies, 1 it did not
(or an error), 2 usage, 3 interrupted (the job keeps running).
`

const upgradeHelp = `Usage: macserve upgrade --plan (--sha256sums SHA256SUMS | --sha256 HEX) [--tag vX.Y.Z] [--carry-proof FILE]
       macserve upgrade (--sha256sums SHA256SUMS | --sha256 HEX) [--tag vX.Y.Z] [--carry-proof FILE]

Upgrades a Mac set up by macserve setup to a newer release. Run the
downloaded new release (macserve-darwin-arm64) as yourself, not with sudo,
after verifying the release (gh attestation verify macserve-darwin-arm64
--repo jerryfane/macserve). Its digest always comes from the release, never
from the file: this binary must match the macserve-darwin-arm64 line of the
release's SHA256SUMS (or --sha256).

--plan is read-only: it compares the installed and the new release, checks
the digest, the stopped services and the build account's session, says
whether a release carry is possible and lists what the upgrade will do.
It writes, starts and contacts nothing.

Without --plan, after you type yes, sudo asks for your password once and
the setup helper (from this binary) checks everything again as root:
  - the three services booted out and no controller process (stopped
    gate; upgrade never stops services or jobs);
  - no build-account GUI session, unless the release is carried;
  - a newer release than the installed one (never the same or older), and
    no approval this setup ledger did not record.
It then records the release in the setup ledger, writes owner.pause,
removes the approval and activation anchor, replaces
/Library/macserve/bin/macserve with these bytes (atomic, digest re-checked)
and resets setup to owner-actions: run macserve setup to re-grant Full Disk
Access and requalify. An interrupted upgrade blocks setup until macserve
upgrade with the same release finishes it.

  --tag vX.Y.Z        The release you mean; refused unless this binary is it.
  --carry-proof FILE  A release-carry proof (carry-proof.json) for exactly
                      this upgrade. With a valid proof, your own approval, a
                      live build-account session and worker-quiescent, the
                      approval is carried instead: the new binary is
                      re-measured (job probe, qualify begin --carry, tool
                      evidence, qualify carry). Any failure falls back to
                      full requalification. Services stay stopped.

Exit status: 0 upgraded (or plan without failures), 1 refused or a check
failed, 2 usage.
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
		if !strings.HasPrefix(c.name, "_") {
			fmt.Fprintf(w, "  %-14s %s\n", c.name, c.summary)
		}
	}
}

// runSetup runs the read-only plan unless plan.Mode selects apply.
func runSetup(args []string, stdout, stderr io.Writer) int {
	return setupDispatch([]string{plan.Mode(args)}, args, stdout, stderr)
}

// setupDispatch runs the setup mode words[0]. checks/readonly proves it
// for the mode "plan": everything here except the apply clause.
func setupDispatch(words, args []string, stdout, stderr io.Writer) int {
	switch words[0] {
	case plan.ModeApply:
		return runSetupApply(args, stdout, stderr)
	}
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
		fmt.Fprintln(stderr, "macserve setup: this is the read-only plan and needs --plan; see macserve setup --help")
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
