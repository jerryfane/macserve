package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/setup/plan"
	"github.com/jerryfane/macserve/internal/setup/upgrade"
)

func runUpgrade(args []string, stdout, stderr io.Writer) int {
	return upgradeDispatch([]string{plan.Mode(args)}, args, stdout, stderr)
}

// upgradeDispatch runs the upgrade mode words[0]. checks/readonly proves it
// for the mode "plan": everything here except the apply clause.
func upgradeDispatch(words, args []string, stdout, stderr io.Writer) int {
	switch words[0] {
	case plan.ModeApply:
		return runUpgradeApply(args, stdout, stderr)
	}
	return runUpgradeWith(upgrade.SystemProbe(), args, stdout, stderr)
}

// upgradeFlags are macserve upgrade's flags; files are paths.
type upgradeFlags struct {
	plan                          bool
	sha256, sums, tag, carryProof string
}

var upgradeDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// parseUpgradeFlags parses and checks the flags; a non-zero exit is usage.
func parseUpgradeFlags(args []string, stdout, stderr io.Writer) (upgradeFlags, int) {
	var f upgradeFlags
	flags := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&f.plan, "plan", false, "")
	flags.StringVar(&f.sha256, "sha256", "", "")
	flags.StringVar(&f.sums, "sha256sums", "", "")
	flags.StringVar(&f.tag, "tag", "", "")
	flags.StringVar(&f.carryProof, "carry-proof", "", "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, upgradeHelp)
			return f, -1
		}
		fmt.Fprintf(stderr, "macserve upgrade: %v\n", err)
		return f, 2
	}
	switch {
	case flags.NArg() != 0:
		fmt.Fprintln(stderr, "macserve upgrade: unexpected arguments; see macserve upgrade --help")
	case (f.sha256 == "") == (f.sums == ""):
		fmt.Fprintln(stderr, "macserve upgrade: give the release digest: --sha256sums SHA256SUMS or --sha256 HEX (one of them)")
	case f.sha256 != "" && !upgradeDigest.MatchString(f.sha256):
		fmt.Fprintln(stderr, "macserve upgrade: --sha256 needs 64 lowercase hexadecimal characters")
	case f.carryProof != "" && f.sums == "":
		fmt.Fprintln(stderr, "macserve upgrade: --carry-proof needs --sha256sums: the proof must be the release's carry-proof.json, listed in its SHA256SUMS")
	case f.tag != "" && !setup.ValidRelease(f.tag):
		fmt.Fprintln(stderr, "macserve upgrade: --tag needs a release tag vMAJOR.MINOR.PATCH")
	default:
		return f, 0
	}
	return f, 2
}

// options reads the SHA256SUMS and carry-proof files with read.
func (f upgradeFlags) options(read func(path string, max int64) ([]byte, error)) (upgrade.Options, error) {
	o := upgrade.Options{SHA256: f.sha256, Tag: f.tag}
	var err error
	if f.sums != "" {
		if o.SHA256Sums, err = read(f.sums, 64<<10); err != nil {
			return o, fmt.Errorf("--sha256sums: %w", err)
		}
	}
	if f.carryProof != "" {
		if o.CarryProof, err = read(f.carryProof, setup.MaxCarryProof); err != nil {
			return o, fmt.Errorf("--carry-proof: %w", err)
		}
	}
	return o, nil
}

// runUpgradeWith runs the read-only plan against probe; tests pass a fake
// host. Exit 0: no check failed; 1: a check failed; 2: usage.
func runUpgradeWith(probe upgrade.Probe, args []string, stdout, stderr io.Writer) int {
	f, code := parseUpgradeFlags(args, stdout, stderr)
	if code != 0 {
		return max(code, 0)
	}
	if !f.plan {
		fmt.Fprintln(stderr, "macserve upgrade: this is the read-only plan and needs --plan; see macserve upgrade --help")
		return 2
	}
	o, err := f.options(probe.ReadFile)
	if err != nil {
		fmt.Fprintln(stderr, "macserve upgrade:", err)
		return 2
	}
	result := upgrade.Plan(context.Background(), probe, o)
	if err := upgrade.Write(stdout, result); err != nil {
		fmt.Fprintln(stderr, "macserve upgrade:", err)
		return 1
	}
	if !result.Ready() {
		return 1
	}
	return 0
}

// upgradeRun is `macserve upgrade` without --plan, as the owner: it shows
// the plan, asks, starts the upgrade helper from this binary and sends the
// one upgrade request. Every check is repeated by the helper as root.
type upgradeRun struct {
	probe upgrade.Probe
	in    *bufio.Reader
	out   io.Writer
	euid  int
	self  string
	start func(path, digest string) (setupSession, error)
}

func runUpgradeApply(args []string, stdout, stderr io.Writer) int {
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		fmt.Fprintln(stderr, "macserve upgrade:", err)
		return 1
	}
	u := &upgradeRun{
		probe: upgrade.SystemProbe(), in: bufio.NewReader(os.Stdin), out: stdout, euid: os.Geteuid(), self: self,
		start: func(path, digest string) (setupSession, error) { return startRootHelper(path, digest, true, stderr) },
	}
	return u.run(args, stdout, stderr)
}

func (u *upgradeRun) run(args []string, stdout, stderr io.Writer) int {
	f, code := parseUpgradeFlags(args, stdout, stderr)
	if code != 0 {
		return max(code, 0)
	}
	if f.plan {
		fmt.Fprintln(stderr, "macserve upgrade: --plan runs the read-only plan only")
		return 2
	}
	if u.euid == 0 {
		fmt.Fprintln(stderr, "macserve upgrade: run it as yourself, not with sudo; it asks for your password once when it needs it.")
		return 2
	}
	o, err := f.options(readSmallFile)
	if err != nil {
		fmt.Fprintln(stderr, "macserve upgrade:", err)
		return 2
	}
	want := o.SHA256
	if len(o.SHA256Sums) > 0 {
		if want, err = setup.ReleaseDigest(o.SHA256Sums, setup.ReleaseAsset); err != nil {
			fmt.Fprintln(stderr, "macserve upgrade: --sha256sums:", err)
			return 2
		}
	}
	// The digest comes from the release; this binary must match it before
	// sudo is asked for, and the helper re-hashes itself.
	if got, err := fileDigest(u.self); err != nil || got != want {
		fmt.Fprintf(stderr, "macserve upgrade: %s has SHA-256 %s, not the release digest %s; nothing was changed (%v)\n", u.self, got, want, err)
		return 1
	}
	result := upgrade.Plan(context.Background(), u.probe, o)
	if err := upgrade.Write(u.out, result); err != nil {
		fmt.Fprintln(stderr, "macserve upgrade:", err)
		return 1
	}
	if !result.Ready() {
		return 1
	}
	fmt.Fprint(u.out, "\nType yes to upgrade as shown (sudo asks for your password once): ")
	answer, _ := u.in.ReadString('\n')
	if strings.TrimSpace(answer) != "yes" {
		fmt.Fprintln(u.out, "Nothing was changed.")
		return 0
	}
	session, err := u.start(u.self, want)
	if err != nil {
		fmt.Fprintln(stderr, "macserve upgrade:", err)
		return 1
	}
	defer session.Close()
	resp, err := session.Call(setup.Request{Verb: setup.VerbUpgrade, SHA256: want, Tag: f.tag, Sums: string(o.SHA256Sums), Proof: string(o.CarryProof)})
	if err != nil {
		fmt.Fprintln(stderr, "macserve upgrade:", err)
		for _, item := range resp.Items {
			fmt.Fprintln(stderr, "  "+item)
		}
		return 1
	}
	fmt.Fprintf(u.out, "\n%s to %s: %s.\n", result.From, result.To, resp.Detail)
	if len(resp.Items) == 1 && resp.Items[0] == setup.EffectCarried {
		fmt.Fprintln(u.out, "The approval was carried. Services stay stopped and owner.pause stays. Re-grant Full Disk Access to /Library/macserve/bin/macserve, start the services, and remove owner.pause once health is valid (docs/install.md, Upgrading).")
		return 0
	}
	fmt.Fprintln(u.out, "Run macserve setup (as yourself) to continue: it re-checks Full Disk Access for the new binary, then guides qualification again.")
	return 0
}
