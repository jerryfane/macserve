package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// macserve upgrade (design NEW-USER-ONBOARDING.md §5, BOUNDARY-PRESERVING-
// RELEASES.md §3-§6). The owner runs the downloaded new release; the
// wizard verifies its bytes against the release's SHA256SUMS (or --sha256)
// and starts it as the upgrade helper, `sudo NEW _setup-root --upgrade
// --sha256 DIGEST`: the same root helper, lock, socket and peer-UID check
// as macserve setup, serving only the upgrade verb. As root it repeats
// every check, then, in this order:
//
//	record    the running release in the setup ledger (resumable)
//	pause     write owner.pause when it is absent
//	(full)    remove the approval and the activation anchor
//	replace   bin/macserve with its own verified bytes, atomically
//	          (root:wheel 0755), and re-hash the installed file
//	(carry)   the N3 verbs with the new binary; any failure falls back
//	          to the full path
//	finish    record the effect; the full path resets the ledger to
//	          owner-actions, so macserve setup resumes guided
//	          qualification (Full Disk Access is granted per build)
//
// Before anything changes it requires the stopped gate (the three services
// booted out, no controller-UID process and no process running the
// installed binary) and, unless the release is carried, no job GUI session.
// It never stops, signals or logs out anything itself.

// upgradeAbsent is the stopped-gate exit status of `launchctl print` for a
// service that is not loaded.
const upgradeAbsent = 113

// OwnerPauseUpgrade is the owner.pause macserve upgrade writes when none
// exists: admission stays paused until macserve setup's approval and start.
const OwnerPauseUpgrade = "macserve upgrade: the new release needs qualification; admission remains paused.\n"

// Carry timeouts: the strict rebind's full scan (≤540 s), the job probe,
// and tool evidence's 6000 s cap.
const (
	carryStepTimeout     = 10 * time.Minute
	carryEvidenceTimeout = 100 * time.Minute
)

// invalidatedFiles are what a release without carry removes, relative to
// Root (the predecessor's invalidation): the approval, its evidence and
// the activation anchor, the reviewed persistence, its attestation and the
// GUI baseline. Guided qualification writes each again.
var invalidatedFiles = []string{
	"config/activation-anchor.json",
	"config/qualification.json",
	"config/boundary-evidence.json",
	"var/broker/persistence-attestation.json",
	"var/broker/reviewed-persistence.json",
	"var/broker/gui-baseline.json",
}

// Process is one running process: its PID, effective UID and executable
// ("" when unavailable).
type Process struct {
	PID        int
	UID        uint32
	Executable string
}

func (h *Helper) installedPath() string { return filepath.Join(h.Root, "bin", "macserve") }

// checkUpgradeStart: the upgrade helper is the verified new release (not
// the installed binary), on a Mac with a native setup ledger of this owner.
func (h *Helper) checkUpgradeStart() error {
	if _, err := h.selfBytes(); err != nil {
		return err
	}
	if h.Executable == h.installedPath() {
		return fmt.Errorf("macserve upgrade runs from the downloaded new release, not from %s", h.Executable)
	}
	l, _, err := h.load()
	if err != nil {
		return err
	}
	if l == nil {
		return fmt.Errorf("no native setup ledger: %s was not set up by macserve setup, and macserve upgrade does not change it", h.Root)
	}
	return nil
}

// selfBytes reads the helper's executable and requires the verified digest.
func (h *Helper) selfBytes() ([]byte, error) {
	if !sha256Hex.MatchString(h.SHA256) {
		return nil, errors.New("expected macserve digest missing")
	}
	data, err := readBinary(h.Executable)
	if err != nil {
		return nil, err
	}
	if got := digestHex(data); got != h.SHA256 {
		return nil, fmt.Errorf("%s has SHA-256 %s, not the verified %s; nothing was changed", h.Executable, got, h.SHA256)
	}
	return data, nil
}

// installedBytes reads the installed binary with installedBinary's checks.
func (h *Helper) installedBytes() ([]byte, error) {
	if _, err := h.installedBinary(); err != nil {
		return nil, err
	}
	return readBinary(h.installedPath())
}

// upgrade serves VerbUpgrade.
func (h *Helper) upgrade(r Request) (Response, error) {
	ctx := context.Background()
	self, err := h.selfBytes()
	if err != nil {
		return Response{}, err
	}
	if r.SHA256 != h.SHA256 {
		return Response{}, errors.New("the release digest you verified is not this helper's; nothing was changed")
	}
	to, err := h.Version(self)
	if err != nil {
		return Response{}, fmt.Errorf("%s: %w", h.Executable, err)
	}
	if r.Tag != "" && r.Tag != to {
		return Response{}, fmt.Errorf("this binary is release %s, not the %s you named; nothing was changed", to, r.Tag)
	}
	l, loc, err := h.load()
	if err != nil {
		return Response{}, err
	}
	if l == nil || loc != LedgerInstalled {
		return Response{}, errors.New("no installed setup ledger; macserve upgrade needs a Mac set up by macserve setup")
	}
	e, _, err := h.installedEnv(l)
	if err != nil {
		return Response{}, err
	}
	installed, err := h.installedBytes()
	if err != nil {
		return Response{}, err
	}
	installedSHA := digestHex(installed)
	if err := h.stoppedGate(ctx, e.ControllerUID); err != nil {
		return Response{Items: h.stopCommands()}, err
	}
	rel := l.PendingRelease()
	if rel != nil {
		if rel.To != to || rel.SHA256 != h.SHA256 {
			return Response{}, fmt.Errorf("the upgrade to %s (%s) was interrupted; finish it first by running that release's macserve upgrade", rel.To, rel.SHA256)
		}
		if installedSHA != rel.FromSHA256 && installedSHA != rel.SHA256 {
			return Response{}, fmt.Errorf("%s changed during the interrupted upgrade (SHA-256 %s); reconcile by hand", h.installedPath(), installedSHA)
		}
		if installedSHA == rel.FromSHA256 && rel.CarryProofSHA256 == "" {
			if err := h.jobSessionGuard(e.JobUID); err != nil {
				return Response{}, err
			}
		}
		// An interrupted carry is not resumed: its sitting cannot be
		// trusted, so it completes as full requalification.
		abandoned := ""
		if rel.CarryProofSHA256 != "" {
			abandoned = "the carry was interrupted; full requalification instead"
		}
		return h.requalify(l, loc, self, abandoned)
	}
	if _, _, err := l.Next(); err != nil {
		return Response{}, err
	}
	if l.record(StepInstall).Status != StatusDone {
		return Response{}, errors.New("setup has not installed macserve yet; run macserve setup")
	}
	if want := l.InstalledBinary(); installedSHA != want {
		return Response{}, fmt.Errorf("%s has SHA-256 %s, not %s, the one setup recorded; nothing was changed", h.installedPath(), installedSHA, want)
	}
	from, err := h.Version(installed)
	if err != nil {
		return Response{}, fmt.Errorf("%s: %w", h.installedPath(), err)
	}
	if err := CompareReleases(from, to); err != nil {
		return Response{}, err
	}
	if err := h.ownAnchor(l); err != nil {
		return Response{}, err
	}
	boot, err := h.Boot()
	if err != nil {
		return Response{}, fmt.Errorf("boot identity: %w", err)
	}
	next := Release{Status: StatusRunning, Started: h.Now().UTC(), Boot: boot, From: from, To: to, FromSHA256: installedSHA, SHA256: h.SHA256}
	carry, abandoned := false, ""
	if r.Proof != "" {
		next.CarryProofSHA256 = digestHex([]byte(r.Proof))
		if err := h.carryPossible(ctx, l, e.JobUID, []byte(r.Proof), next); err != nil {
			abandoned = "carry not possible: " + err.Error()
		} else {
			carry = true
		}
	}
	if !carry {
		if err := h.jobSessionGuard(e.JobUID); err != nil {
			if abandoned != "" {
				err = fmt.Errorf("%s; %w", abandoned, err)
			}
			return Response{}, err
		}
	}
	if _, err := os.Lstat(h.configPath("owner.pause")); errors.Is(err, fs.ErrNotExist) {
		next.PauseWritten = true
	} else if err != nil {
		return Response{}, err
	}
	if err := l.BeginRelease(next); err != nil {
		return Response{}, err
	}
	if err := h.Store.Save(l, loc); err != nil {
		return Response{}, err
	}
	h.audit(VerbUpgrade, "release "+from+" to "+to+" recorded", nil)
	if !carry {
		return h.requalify(l, loc, self, abandoned)
	}
	return h.carry(ctx, l, loc, self, e.JobUID, []byte(r.Proof))
}

// ownAnchor refuses an approval this ledger did not record: an activation
// anchor or qualification.json without the ledger's approval, or an anchor
// other than the one the ledger recorded.
func (h *Helper) ownAnchor(l *Ledger) error {
	approved, err := h.Approved()
	if err != nil || !approved {
		return err
	}
	if !ownApproval(l) {
		return errors.New("this Mac has an approved qualification this setup ledger did not record (another ledger or tooling approved it); macserve upgrade changes nothing")
	}
	data, err := h.readConfig("activation-anchor.json", 4<<20)
	if err != nil {
		return fmt.Errorf("activation anchor: %w", err)
	}
	if digestHex(data) != l.AnchorSHA256() {
		return errors.New("the activation anchor is not the one this setup ledger recorded; macserve upgrade changes nothing")
	}
	return nil
}

// stoppedGate requires the three services booted out, no controller-UID
// process and no process running the installed binary.
func (h *Helper) stoppedGate(ctx context.Context, controllerUID uint32) error {
	var loaded []string
	for _, label := range serviceLabels {
		_, status, err := h.launchctlOutput(ctx, "print", "system/"+label)
		if err != nil {
			return err
		}
		switch status {
		case upgradeAbsent:
		case 0:
			loaded = append(loaded, label)
		default:
			return fmt.Errorf("launchctl print system/%s: exit status %d", label, status)
		}
	}
	if len(loaded) > 0 {
		return fmt.Errorf("stop macserve's services first (%s are loaded); macserve upgrade never stops services or jobs", strings.Join(loaded, ", "))
	}
	procs, err := h.Processes()
	if err != nil {
		return fmt.Errorf("process list: %w", err)
	}
	for _, p := range procs {
		if p.UID == controllerUID || p.Executable == h.installedPath() {
			return fmt.Errorf("process %d (%s, uid %d) still runs as the controller or from %s; wait for it to exit", p.PID, p.Executable, p.UID, h.installedPath())
		}
	}
	return nil
}

// stopCommands are the commands that boot the services out, for the owner.
func (h *Helper) stopCommands() []string {
	var out []string
	for _, label := range slices.Backward(serviceLabels) {
		out = append(out, "sudo /bin/launchctl bootout system/"+label)
	}
	return out
}

// jobGUILive reports a live job GUI session: the build account holds the
// console or runs a loginwindow.
func (h *Helper) jobGUILive(jobUID uint32) (bool, error) {
	console, err := h.ConsoleUID()
	if err != nil {
		return false, fmt.Errorf("console owner: %w", err)
	}
	if console == jobUID {
		return true, nil
	}
	procs, err := h.Processes()
	if err != nil {
		return false, fmt.Errorf("process list: %w", err)
	}
	for _, p := range procs {
		if p.UID == jobUID && filepath.Base(p.Executable) == "loginwindow" {
			return true, nil
		}
	}
	return false, nil
}

// jobSessionGuard refuses (never stops) a live job GUI session.
func (h *Helper) jobSessionGuard(jobUID uint32) error {
	live, err := h.jobGUILive(jobUID)
	if err != nil {
		return err
	}
	if live {
		return errors.New("the build account's GUI session is live; log it out (Apple menu > Log Out in that account) and run macserve upgrade again. macserve upgrade never logs it out")
	}
	return nil
}

// carryPossible is the read-only carry pre-check, before anything changes:
// the proof, the ledger's own approval in this boot's live session (a
// carry keeps the job GUI session logged in), and worker-quiescent with the
// installed binary.
func (h *Helper) carryPossible(ctx context.Context, l *Ledger, jobUID uint32, proof []byte, next Release) error {
	if _, err := CheckCarryProof(proof, next.From, next.FromSHA256, next.To, next.SHA256); err != nil {
		return err
	}
	if !ownApproval(l) || l.record(StepApproveAndStart).Status != StatusDone {
		return errors.New("this setup ledger has no completed approval to carry")
	}
	live, err := h.jobGUILive(jobUID)
	if err != nil {
		return err
	}
	if !live {
		return errors.New("the build account's GUI session is not live (carry re-measures the new binary in it)")
	}
	argv := []string{h.installedPath(), "worker-quiescent", "--config", h.configPath("worker.json")}
	_, status, err := h.Output(ctx, Cmd{Argv: argv, Env: []string{FixedPath}, Timeout: time.Minute})
	if err != nil || status != 0 {
		return errors.Join(fmt.Errorf("worker-quiescent found job processes outside the audited baseline (exit status %d)", status), err)
	}
	return nil
}

// writePause writes owner.pause when it is absent.
func (h *Helper) writePause() error {
	path := h.configPath("owner.pause")
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := h.Store.checkAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	return h.Store.writeFile(path, []byte(OwnerPauseUpgrade), 0o644)
}

// replaceBinary atomically replaces bin/macserve with data (root:wheel
// 0755) and re-hashes the installed file. It is a no-op when the file
// already holds data.
func (h *Helper) replaceBinary(data []byte) error {
	want := digestHex(data)
	if want != h.SHA256 {
		return errors.New("the bytes to install are not the verified release")
	}
	if got, err := h.installedBinary(); err == nil && got == want {
		return nil
	}
	if err := h.Store.checkAncestors(filepath.Dir(h.installedPath())); err != nil {
		return err
	}
	if err := h.Store.writeFile(h.installedPath(), data, 0o755); err != nil {
		return fmt.Errorf("replace %s: %w", h.installedPath(), err)
	}
	got, err := h.installedBinary()
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s has SHA-256 %s after the replace, not %s; reconcile by hand", h.installedPath(), got, want)
	}
	h.audit(VerbUpgrade, "bin/macserve replaced", nil)
	return nil
}

// invalidate removes the approval, the anchor and the round state, so
// qualification starts afresh with the new release.
func (h *Helper) invalidate() error {
	for _, rel := range invalidatedFiles {
		path := filepath.Join(h.Root, filepath.FromSlash(rel))
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := syncDir(filepath.Dir(path)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	for _, round := range []Step{StepRound1, StepRound2} {
		for _, path := range []string{h.roundPath(round), h.candidatePath(round)} {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return syncDir(h.Store.Ledger)
}

// requalify is the full path: owner.pause, the invalidation, the replace
// and the ledger reset to guided requalification.
func (h *Helper) requalify(l *Ledger, loc LedgerLocation, self []byte, abandoned string) (Response, error) {
	if err := h.writePause(); err != nil {
		return Response{}, fmt.Errorf("owner.pause: %w", err)
	}
	if err := h.invalidate(); err != nil {
		return Response{}, fmt.Errorf("remove the approval: %w", err)
	}
	if err := h.replaceBinary(self); err != nil {
		return Response{}, err
	}
	if err := l.FinishRelease(EffectRequalify, abandoned, "", h.Now()); err != nil {
		return Response{}, err
	}
	if err := h.Store.Save(l, loc); err != nil {
		return Response{}, err
	}
	h.audit(VerbUpgrade, "requalification required", nil)
	detail := "installed; qualification starts again"
	if abandoned != "" {
		detail = abandoned + "; " + detail
	}
	return Response{Done: true, Detail: detail, Items: []string{EffectRequalify}}, nil
}

// carry runs the N3 verbs with the new binary after the replace:
// the job probe self-test, qualify begin --carry (strict persistence
// rebind), the job probe, tool evidence and qualify carry. Any failure
// falls back to the full path, with the reason recorded.
func (h *Helper) carry(ctx context.Context, l *Ledger, loc LedgerLocation, self []byte, jobUID uint32, proof []byte) (Response, error) {
	fallback := func(step string, cause error) (Response, error) {
		h.audit(VerbUpgrade, "carry abandoned at "+step, cause)
		return h.requalify(l, loc, self, reason(fmt.Errorf("carry abandoned at %s: %w", step, cause)))
	}
	if err := h.writePause(); err != nil {
		return Response{}, fmt.Errorf("owner.pause: %w", err)
	}
	if err := h.replaceBinary(self); err != nil {
		return Response{}, err
	}
	proofPath := h.Store.staged("carry-proof.json")
	if err := h.Store.writePrivate(proofPath, proof); err != nil {
		return fallback("stage the proof", err)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fallback("session", err)
	}
	id := "upgrade-carry-" + hex.EncodeToString(b[:])
	bin, job := h.installedPath(), strconv.FormatUint(uint64(jobUID), 10)
	steps := []struct {
		name    string
		argv    []string
		timeout time.Duration
	}{
		{"job-probe-self-test", []string{"/bin/launchctl", "asuser", job, bin, "_qualify-job-probe", "--self-test"}, carryStepTimeout},
		{"begin-carry", []string{bin, "qualify", "begin", "--session", h.sessionDir(id), "--env", h.configPath("deploy.env"), "--owner-canary", OwnerCanary(h.Owner.Home), "--carry"}, carryStepTimeout},
		{"job-probe", []string{"/bin/launchctl", "asuser", job, bin, "_qualify-job-probe", id}, carryStepTimeout},
		{"tool-evidence", []string{bin, "_qualify-tool-evidence", id}, carryEvidenceTimeout},
		{"carry-commit", []string{bin, "qualify", "carry", "--session", h.sessionDir(id), "--proof", proofPath}, carryStepTimeout},
	}
	for _, s := range steps {
		if err := h.Exec(ctx, Cmd{Argv: s.argv, Env: []string{FixedPath}, Timeout: s.timeout}); err != nil {
			return fallback(s.name, err)
		}
	}
	anchor, err := h.readConfig("activation-anchor.json", 4<<20)
	if err != nil {
		return fallback("anchor", err)
	}
	if err := l.FinishRelease(EffectCarried, "", digestHex(anchor), h.Now()); err != nil {
		return Response{}, err
	}
	if err := h.Store.Save(l, loc); err != nil {
		return Response{}, err
	}
	h.audit(VerbUpgrade, "qualification carried", nil)
	return Response{Done: true, Detail: "installed; qualification carried (" + id + ")", Session: id, Items: []string{EffectCarried}}, nil
}
