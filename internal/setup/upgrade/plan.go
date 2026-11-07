// Package upgrade is `macserve upgrade --plan`: the read-only upgrade
// plan. It reads the installed and the downloaded release, checks the
// download against the release's digest and reports what the upgrade
// would do; it writes, starts and contacts nothing (checks/readonly).
// The root helper repeats every check before it changes anything
// (internal/setup/upgrade.go).
package upgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/qualification"
	"github.com/jerryfane/macserve/internal/setup"
)

// Root is the installation the plan reads.
const Root = setup.InstallRoot

// maxBinary bounds a macserve binary (as setup's install does).
const maxBinary = 256 << 20

// Probe is every host read the plan performs: doctor's read-only reads and
// the path of this (the downloaded) binary.
type Probe struct {
	// Run runs one of doctor's read-only commands.
	Run func(ctx context.Context, argv []string) (string, error)
	// ReadFile reads at most max bytes of a file.
	ReadFile func(path string, max int64) ([]byte, error)
	// Exists reports whether path exists (lstat).
	Exists func(path string) (bool, error)
	// Self is the path of the running binary.
	Self func() (string, error)
	// Version is setup.ReleaseVersion.
	Version func(binary []byte) (string, error)
}

// Options are the command-line inputs. SHA256 and ControllerSHA256, or
// the SHA256SUMS bytes, give the release digests of macserve and of the
// macserve-controller beside it; Tag is the release the owner names;
// CarryProof is the carry-proof.json bytes, if given.
type Options struct {
	SHA256           string
	ControllerSHA256 string
	SHA256Sums       []byte
	Tag              string
	CarryProof       []byte
}

// Check statuses.
const (
	Pass = "pass"
	Warn = "warn"
	Fail = "fail"
	Info = "info"
)

// Check is one line of the plan.
type Check struct {
	ID, Status, Detail string
}

// Result is the plan: its checks and what the upgrade would do.
type Result struct {
	From, To   string
	Carry      bool
	Checks     []Check
	WillHappen []string
}

// Ready reports a plan without a failed check.
func (r Result) Ready() bool {
	for _, c := range r.Checks {
		if c.Status == Fail {
			return false
		}
	}
	return true
}

func (r *Result) add(id, status, format string, args ...any) {
	r.Checks = append(r.Checks, Check{ID: id, Status: status, Detail: fmt.Sprintf(format, args...)})
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

var services = []string{"org.macserve.worker", "org.macserve.maintenance", "org.macserve.controller"}

// Plan builds the upgrade plan.
func Plan(ctx context.Context, p Probe, o Options) Result {
	var r Result
	want, wantController := o.SHA256, o.ControllerSHA256
	if len(o.SHA256Sums) > 0 {
		var err error
		if want, err = setup.ReleaseDigest(o.SHA256Sums, setup.ReleaseAsset); err != nil {
			r.add("release.digest", Fail, "SHA256SUMS: %v", err)
			return r
		}
		if wantController, err = setup.ReleaseDigest(o.SHA256Sums, setup.ControllerReleaseAsset); err != nil {
			r.add("release.digest", Fail, "SHA256SUMS: %v", err)
			return r
		}
	}
	self, err := p.Self()
	var target []byte
	if err == nil {
		target, err = p.ReadFile(self, maxBinary)
	}
	if err != nil {
		r.add("release.digest", Fail, "cannot read this binary: %v", err)
		return r
	}
	toSHA := digest(target)
	if toSHA != want {
		r.add("release.digest", Fail, "%s has SHA-256 %s, not the release digest %s; do not install it", self, toSHA, want)
		return r
	}
	controllerPath := filepath.Join(filepath.Dir(self), deploy.ControllerBinaryName)
	controller, err := p.ReadFile(controllerPath, maxBinary)
	if err != nil {
		r.add("release.digest", Fail, "cannot read %s: %v (the release's macserve-controller must be beside this binary)", controllerPath, err)
		return r
	}
	toController := digest(controller)
	if toController != wantController {
		r.add("release.digest", Fail, "%s has SHA-256 %s, not the release digest %s; do not install it", controllerPath, toController, wantController)
		return r
	}
	r.add("release.digest", Pass, "%s and %s match the release digests %s and %s", self, controllerPath, want, wantController)
	if r.To, err = p.Version(target); err != nil {
		r.add("release.version", Fail, "this binary: %v", err)
		return r
	}
	if o.Tag != "" && o.Tag != r.To {
		r.add("release.version", Fail, "this binary is release %s, not the %s you named", r.To, o.Tag)
		return r
	}
	installedPath := Root + "/bin/macserve"
	installed, err := p.ReadFile(installedPath, maxBinary)
	if err != nil {
		r.add("release.installed", Fail, "cannot read %s: %v (is macserve installed by macserve setup?)", installedPath, err)
		return r
	}
	if r.From, err = p.Version(installed); err != nil {
		r.add("release.installed", Fail, "%s: %v", installedPath, err)
		return r
	}
	installedController := Root + "/bin/" + deploy.ControllerBinaryName
	var from qualification.CarryBinaries
	data, err := p.ReadFile(installedController, maxBinary)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Installed before the controller binary: the upgrade installs it
		// and requalifies (a carry rebinds both binaries).
	case err != nil:
		r.add("release.installed", Fail, "cannot read %s: %v", installedController, err)
		return r
	default:
		from.Controller = digest(data)
	}
	// Ledger, SHA256SUMS and proofs hold release digests; signed installed
	// bytes map to them through installed-binaries.json.
	inv, err := installedBinaries(p)
	if err == nil {
		from.Macserve, err = inv.ReleaseDigest(deploy.BinaryName, digest(installed))
	}
	// The upgrade replaces the controller first and removes
	// installed-binaries.json only after both replaces, so an interrupted
	// upgrade of this release leaves its unsigned controller beside the old
	// map. Those are this release's verified bytes, not a signed install the
	// map must vouch for; the root helper accepts them only for its own
	// pending upgrade of this release.
	resumed := inv != nil && from.Controller == toController
	if err == nil && from.Controller != "" && !resumed {
		from.Controller, err = inv.ReleaseDigest(deploy.ControllerBinaryName, from.Controller)
	}
	if err != nil {
		r.add("release.installed", Fail, "%v", err)
		return r
	}
	switch {
	case from.Controller == "":
		r.add("release.installed", Info, "%s is release %s (SHA-256 %s); %s is absent (installed before the controller binary): this upgrade installs it and requalifies", installedPath, r.From, from.Macserve, installedController)
	case resumed:
		r.add("release.installed", Info, "%s is release %s (SHA-256 %s); %s already holds this release's controller (SHA-256 %s): an upgrade to %s was interrupted, and the helper resumes only that pending upgrade", installedPath, r.From, from.Macserve, installedController, toController, r.To)
	default:
		r.add("release.installed", Info, "%s is release %s (SHA-256 %s; %s SHA-256 %s)", installedPath, r.From, from.Macserve, installedController, from.Controller)
	}
	if err := setup.CompareReleases(r.From, r.To); err != nil {
		r.add("release.version", Fail, "%v", err)
		return r
	}
	r.add("release.version", Pass, "upgrade %s to %s", r.From, r.To)
	if ok, err := p.Exists(setup.LedgerPath); err != nil || !ok {
		r.add("setup.ledger", Fail, "no native setup ledger at %s: this Mac was not set up by macserve setup, and macserve upgrade does not change it", setup.LedgerPath)
	} else {
		r.add("setup.ledger", Info, "native setup ledger present; the helper reads it under sudo and refuses an approval it did not record, a failed step or another upgrade in progress")
	}
	r.services(ctx, p)
	approved, _ := p.Exists(Root + "/config/activation-anchor.json")
	jobLive := r.jobSession(ctx, p)
	r.carry(o.CarryProof, o.SHA256Sums, from, qualification.CarryBinaries{Macserve: toSHA, Controller: toController}, approved, jobLive)
	r.WillHappen = r.steps(approved)
	return r
}

// installedBinaries reads config/installed-binaries.json; nil when absent.
func installedBinaries(p Probe) (*deploy.InstalledBinaries, error) {
	data, err := p.ReadFile(deploy.InstalledBinariesPath, 1<<16)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", deploy.InstalledBinariesPath, err)
	}
	return deploy.ParseInstalledBinaries(data)
}

// services reports the stopped gate: the helper requires every service
// booted out (launchctl print fails) and no controller-UID process.
func (r *Result) services(ctx context.Context, p Probe) {
	var loaded []string
	for _, label := range services {
		if _, err := p.Run(ctx, []string{"/bin/launchctl", "print", "system/" + label}); err == nil {
			loaded = append(loaded, label)
		}
	}
	if len(loaded) > 0 {
		r.add("svc.stopped", Fail, "loaded: %v. Stop them first: sudo /bin/launchctl bootout system/LABEL for each; macserve upgrade never stops services or jobs", loaded)
		return
	}
	r.add("svc.stopped", Pass, "the three services are not loaded; the helper also requires no controller-UID process")
}

// jobSession reports the job-session guard and returns whether the build
// account's GUI session is live.
func (r *Result) jobSession(ctx context.Context, p Probe) bool {
	data, err := p.ReadFile(Root+"/config/deploy.env", 64<<10)
	var e deploy.Environment
	if err == nil {
		e, err = deploy.ParseEnvironment(data)
	}
	if err != nil {
		r.add("session.job", Fail, "cannot read deploy.env: %v", err)
		return false
	}
	_, err = p.Run(ctx, []string{"/bin/launchctl", "print", "gui/" + strconv.FormatUint(uint64(e.JobUID), 10)})
	live := err == nil
	if live {
		r.add("session.job", Warn, "the build account %s has a live GUI session: only a release carry keeps it; otherwise log it out first", e.JobUser)
	} else {
		r.add("session.job", Pass, "the build account %s has no GUI session", e.JobUser)
	}
	return live
}

// carry reports whether a release carry is possible. A carry is taken
// only from the target release's carry-proof.json asset, listed in the
// same SHA256SUMS that gave the binary's digest; without one, full
// requalification is the default. The helper also runs qualify carry's
// own pre-check (qualification.CarryPreflight) and worker-quiescent as
// root, which the plan cannot.
func (r *Result) carry(proof, sums []byte, from, to qualification.CarryBinaries, approved, jobLive bool) {
	if len(proof) == 0 {
		r.add("release.carry", Info, "no carry proof given: full requalification (the default)")
		return
	}
	var why error
	if len(sums) == 0 {
		why = errors.New("a carry proof is accepted only with the release's SHA256SUMS (--sha256sums), which must list it")
	} else if _, err := setup.CheckCarryProof(proof, sums, r.From, r.To, from, to); err != nil {
		why = err
	} else if !approved {
		why = errors.New("no activation anchor (nothing approved to carry)")
	} else if !jobLive {
		why = errors.New("the build account's GUI session is not live (a carry re-measures the new binary in it)")
	}
	if why != nil {
		r.add("release.carry", Warn, "carry not possible (%v): full requalification instead, which needs the build account logged out", why)
		return
	}
	r.Carry = true
	r.add("release.carry", Pass, "the release's carry-proof.json passes qualify carry's proof checks; the helper also checks your approval, the anchor and worker-quiescent as root, and any later failure falls back to full requalification")
}

func (r Result) steps(approved bool) []string {
	out := []string{
		"sudo starts the upgrade helper from this binary; it repeats every check above as root",
		"record the upgrade in the setup ledger, then write owner.pause if it is absent",
	}
	if r.Carry {
		out = append(out,
			"replace "+Root+"/bin/macserve-controller, then "+Root+"/bin/macserve, with this release's binaries (each atomic, root:wheel 0755, digest re-checked)",
			"with the new binaries: job probe self-test, qualify begin --carry, the job probe, tool evidence and qualify carry --proof",
			"on success the approval is kept; services stay stopped and owner.pause stays (re-grant Full Disk Access to the new binary, start the services and remove owner.pause once health is valid, docs/install.md)",
			"on any failure: the full requalification below, and setup waits until the build account is logged out",
		)
		return out
	}
	if approved {
		out = append(out, "remove the approval and the activation anchor (the new release must be qualified again)")
	}
	return append(out,
		"replace "+Root+"/bin/macserve-controller, then "+Root+"/bin/macserve, with this release's binaries (each atomic, root:wheel 0755, digest re-checked)",
		"reset the setup ledger to owner-actions: run macserve setup to re-grant Full Disk Access and requalify (two rounds, a restart, your approval)",
	)
}

// Write writes the plan to w in one write.
func Write(w io.Writer, r Result) error {
	var b bytes.Buffer
	b.WriteString("macserve upgrade plan (read-only; nothing was changed)\n\n")
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  %-5s %-17s %s\n", c.Status, c.ID, c.Detail)
	}
	if len(r.WillHappen) > 0 && r.Ready() {
		b.WriteString("\nmacserve upgrade (without --plan) will:\n")
		for i, s := range r.WillHappen {
			fmt.Fprintf(&b, "  %d. %s\n", i+1, s)
		}
	}
	_, err := w.Write(b.Bytes())
	return err
}
