package setup

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/jerryfane/macserve/internal/qualification"
)

// Releases (macserve upgrade). The pure checks here are shared by the
// read-only `macserve upgrade --plan` (internal/setup/upgrade) and the root
// helper's upgrade verb, which repeats every one of them as root.

// ReleaseAsset is the release binary's name in a release's SHA256SUMS.
const ReleaseAsset = "macserve-darwin-arm64"

var (
	sumsLine       = regexp.MustCompile(`^([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)$`)
	releaseVersion = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
)

// ReleaseDigest returns name's digest from a release SHA256SUMS file. Every
// line must be a shasum line, and name must appear exactly once. The digest
// always comes from the release, never from the file it describes.
func ReleaseDigest(data []byte, name string) (string, error) {
	found := ""
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		m := sumsLine.FindSubmatch(line)
		if m == nil {
			return "", fmt.Errorf("not a SHA256SUMS line: %q", line)
		}
		if string(m[2]) == name {
			if found != "" {
				return "", fmt.Errorf("%s is listed twice", name)
			}
			found = string(m[1])
		}
	}
	if found == "" {
		return "", fmt.Errorf("%s is not listed", name)
	}
	return found, nil
}

// ValidRelease reports a release tag vMAJOR.MINOR.PATCH.
func ValidRelease(v string) bool { return releaseVersion.MatchString(v) }

// ReleaseVersion is the module version Go stamped into a macserve binary:
// a release built from its tag (checks/release-build.sh, -buildvcs=true)
// carries exactly that tag. A development, pseudo-version or modified
// build is refused: macserve upgrade installs releases only.
func ReleaseVersion(binary []byte) (string, error) {
	info, err := buildinfo.Read(bytes.NewReader(binary))
	if err != nil {
		return "", fmt.Errorf("no Go build information: %w", err)
	}
	if info.Path != "github.com/jerryfane/macserve/cmd/macserve" || info.Main.Path != "github.com/jerryfane/macserve" {
		return "", fmt.Errorf("not a macserve build (%s)", info.Path)
	}
	if !ValidRelease(info.Main.Version) {
		return "", fmt.Errorf("not a release build (version %q)", info.Main.Version)
	}
	return info.Main.Version, nil
}

func releaseParts(v string) ([3]uint64, bool) {
	var parts [3]uint64
	m := releaseVersion.FindStringSubmatch(v)
	if m == nil {
		return parts, false
	}
	for i := range parts {
		n, err := strconv.ParseUint(m[i+1], 10, 32)
		if err != nil {
			return parts, false
		}
		parts[i] = n
	}
	return parts, true
}

// CompareReleases allows only a newer release: the same release and a
// downgrade are refused.
func CompareReleases(from, to string) error {
	a, okA := releaseParts(from)
	b, okB := releaseParts(to)
	if !okA || !okB {
		return fmt.Errorf("release versions %q and %q must be vMAJOR.MINOR.PATCH", from, to)
	}
	switch c := slices.Compare(a[:], b[:]); {
	case c == 0:
		return fmt.Errorf("%s is already installed; nothing to upgrade", to)
	case c > 0:
		return fmt.Errorf("%s is older than the installed %s; macserve upgrade never downgrades", to, from)
	}
	return nil
}

// MaxCarryProof bounds a carry-proof.json.
const MaxCarryProof = 64 << 10

// CarryProofAsset is the release asset the release workflow publishes
// when a release changes no boundary path; SHA256SUMS lists its digest.
const CarryProofAsset = "carry-proof.json"

// CheckCarryProof accepts a release-carry proof only as the target
// release's own carry-proof.json asset: its digest is the one the same
// SHA256SUMS lists (the file that also gave the binary's digest), it passes
// qualify carry's own proof checks (qualification.ValidateCarryProof) from
// the installed binary to the target, and it names exactly the installed
// and the target release.
func CheckCarryProof(raw, sums []byte, from, fromSHA256, to, toSHA256 string) (qualification.CarryProof, error) {
	var p qualification.CarryProof
	if len(raw) == 0 || len(raw) > MaxCarryProof {
		return p, errors.New("carry proof is empty or larger than 64 KiB")
	}
	if binary, err := ReleaseDigest(sums, ReleaseAsset); err != nil || binary != toSHA256 {
		return p, errors.Join(errors.New("a carry needs the release's SHA256SUMS, listing this binary"), err)
	}
	listed, err := ReleaseDigest(sums, CarryProofAsset)
	if err != nil {
		return p, fmt.Errorf("the release publishes no %s: %w", CarryProofAsset, err)
	}
	if digestHex(raw) != listed {
		return p, fmt.Errorf("the carry proof is not the release's %s (SHA256SUMS lists %s)", CarryProofAsset, listed)
	}
	if p, err = qualification.ValidateCarryProof(raw, fromSHA256, toSHA256); err != nil {
		return p, err
	}
	if p.From.Tag != from || p.To.Tag != to {
		return p, fmt.Errorf("carry proof is for %s to %s, not %s to %s", p.From.Tag, p.To.Tag, from, to)
	}
	return p, nil
}

// Release effects.
const (
	// EffectRequalify: the release was installed and the ledger reset to
	// guided requalification (owner-actions onward).
	EffectRequalify = "qualification-required"
	// EffectCarried: qualify carry committed the release; the approval
	// and every setup step are kept.
	EffectCarried = "qualification-carried"
)

// Release is one macserve upgrade in the setup ledger. It is running from
// before the installed binary changes until its effect is recorded; while
// it runs, setup and every other upgrade are blocked, and macserve upgrade
// with the same release resumes it.
type Release struct {
	Status   Status     `json:"status"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
	Boot     Boot       `json:"boot"`
	// From and To are the installed and the new release; FromSHA256 and
	// SHA256 their binaries (SHA256 is the release's SHA256SUMS digest).
	From       string `json:"from"`
	To         string `json:"to"`
	FromSHA256 string `json:"from_sha256"`
	SHA256     string `json:"sha256"`
	// PauseWritten: upgrade wrote owner.pause (it was absent).
	PauseWritten bool `json:"pause_written,omitempty"`
	// CarryProofSHA256 is the digest of the carry proof the owner gave.
	CarryProofSHA256 string `json:"carry_proof_sha256,omitempty"`
	Effect           string `json:"effect,omitempty"`
	// CarryAbandoned is why a carry attempted after the swap fell back to
	// full requalification.
	CarryAbandoned string `json:"carry_abandoned,omitempty"`
	// JobLogoutRequired: the upgrade did not apply the job-session guard
	// (a carry was attempted with the build account logged in) and ended
	// in requalification. macserve setup then counts no job login until it
	// has seen the build account logged out (ClearJobLogout).
	JobLogoutRequired bool `json:"job_logout_required,omitempty"`
	// Carry: every carry pre-check passed, so the job-session guard was
	// not applied and the carry verbs run (or ran) with the new binary.
	Carry bool `json:"carry,omitempty"`
	// AnchorSHA256 is the activation anchor qualify carry rewrote.
	AnchorSHA256 string `json:"anchor_sha256,omitempty"`
}

// PendingRelease returns the running upgrade, if any.
func (l *Ledger) PendingRelease() *Release {
	if n := len(l.Releases); n > 0 && l.Releases[n-1].Status == StatusRunning {
		return &l.Releases[n-1]
	}
	return nil
}

// InstalledBinary is the digest of the macserve binary this ledger
// installed: the last finished upgrade's, else the latest step input
// (install, then owner-actions, record it). A running upgrade's binary
// counts only once its effect is recorded.
func (l *Ledger) InstalledBinary() string {
	for i := len(l.Releases) - 1; i >= 0; i-- {
		if l.Releases[i].Status == StatusDone {
			return l.Releases[i].SHA256
		}
	}
	for i := len(l.Records) - 1; i >= 0; i-- {
		if d := l.Records[i].Inputs["macserve"]; d != "" {
			return d
		}
	}
	return ""
}

// AnchorSHA256 is the activation anchor this ledger recorded: the last
// carried release's, else the one qualify approve wrote.
func (l *Ledger) AnchorSHA256() string {
	if n := len(l.Releases); n > 0 && l.Releases[n-1].Effect == EffectCarried {
		return l.Releases[n-1].AnchorSHA256
	}
	if l.Approval == nil {
		return ""
	}
	return l.Approval.Approved["activation-anchor.json"]
}

// BeginRelease records a running upgrade before anything is installed.
func (l *Ledger) BeginRelease(r Release) error {
	if l.PendingRelease() != nil {
		return errors.New("another macserve upgrade is running")
	}
	if r.Status != StatusRunning || r.Finished != nil || r.Effect != "" {
		return errors.New("a new release record must be running")
	}
	l.Releases = append(l.Releases, r)
	if err := l.validate(); err != nil {
		l.Releases = l.Releases[:len(l.Releases)-1]
		return err
	}
	return nil
}

// RequalifySteps are the steps an upgrade without carry resets: Full Disk
// Access is granted to one ad-hoc signed build (docs/install.md) and
// owner-actions records that binary, then both rounds, the reboot and the
// approval are redone for the new release.
var RequalifySteps = []Step{StepOwnerActions, StepRound1, StepReboot, StepRound2, StepApproveAndStart, StepFirstBuild}

// FinishRelease records the running upgrade's effect. EffectRequalify
// resets RequalifySteps and the approval, so macserve setup resumes with
// owner-actions and the guided qualification; jobLogout records that the
// job-session guard was not applied (JobLogoutRequired).
func (l *Ledger) FinishRelease(effect, abandoned, anchor string, jobLogout bool, now time.Time) error {
	r := l.PendingRelease()
	if r == nil {
		return errors.New("no macserve upgrade is running")
	}
	saved, approval := slices.Clone(l.Records), l.Approval
	t := now.UTC()
	r.Status, r.Finished, r.Effect, r.CarryAbandoned, r.AnchorSHA256, r.JobLogoutRequired = StatusDone, &t, effect, abandoned, anchor, jobLogout
	if effect == EffectRequalify {
		for i := range l.Records {
			if slices.Contains(RequalifySteps, l.Records[i].Step) {
				l.Records[i] = Record{Step: l.Records[i].Step, Status: StatusPending}
			}
		}
		l.Approval = nil
	}
	if err := l.validate(); err != nil {
		l.Records, l.Approval = saved, approval
		r.Status, r.Finished, r.Effect, r.CarryAbandoned, r.AnchorSHA256, r.JobLogoutRequired = StatusRunning, nil, "", "", "", false
		return err
	}
	return nil
}

// JobLogoutPending reports that the last upgrade left the build account
// logged in without the job-session guard: setup must see it logged out
// before it counts a job login.
func (l *Ledger) JobLogoutPending() bool {
	n := len(l.Releases)
	return n > 0 && l.Releases[n-1].JobLogoutRequired
}

// ClearJobLogout records that setup saw the build account logged out.
func (l *Ledger) ClearJobLogout() {
	if n := len(l.Releases); n > 0 {
		l.Releases[n-1].JobLogoutRequired = false
	}
}

// validateReleases checks the upgrade history: a chain of strictly newer
// releases, each from the binary the one before installed, only the last
// one running, and a carried release only on an approved ledger.
func (l *Ledger) validateReleases() error {
	for i, r := range l.Releases {
		last := i == len(l.Releases)-1
		if r.Started.IsZero() || !r.Boot.valid() || !sha256Hex.MatchString(r.FromSHA256) || !sha256Hex.MatchString(r.SHA256) || r.FromSHA256 == r.SHA256 {
			return fmt.Errorf("setup ledger: release %d is incomplete", i)
		}
		if err := CompareReleases(r.From, r.To); err != nil {
			return fmt.Errorf("setup ledger: release %d: %w", i, err)
		}
		if i > 0 && (l.Releases[i-1].SHA256 != r.FromSHA256 || l.Releases[i-1].To != r.From) {
			return fmt.Errorf("setup ledger: release %d does not continue from release %d", i, i-1)
		}
		if (r.CarryProofSHA256 != "" && !sha256Hex.MatchString(r.CarryProofSHA256)) || (r.Carry && r.CarryProofSHA256 == "") {
			return fmt.Errorf("setup ledger: release %d has an invalid carry proof digest", i)
		}
		switch r.Status {
		case StatusRunning:
			if !last || r.Finished != nil || r.Effect != "" || r.CarryAbandoned != "" || r.AnchorSHA256 != "" || r.JobLogoutRequired {
				return fmt.Errorf("setup ledger: release %d is running out of order", i)
			}
		case StatusDone:
			if r.Finished == nil {
				return fmt.Errorf("setup ledger: release %d is done without a finish time", i)
			}
			switch r.Effect {
			case EffectRequalify:
				if r.AnchorSHA256 != "" || (r.CarryAbandoned != "" && (!text(r.CarryAbandoned, 512) || r.CarryProofSHA256 == "")) || (r.JobLogoutRequired && !r.Carry) {
					return fmt.Errorf("setup ledger: release %d requalification record is inconsistent", i)
				}
			case EffectCarried:
				if !sha256Hex.MatchString(r.AnchorSHA256) || !r.Carry || r.CarryProofSHA256 == "" || r.CarryAbandoned != "" || r.JobLogoutRequired {
					return fmt.Errorf("setup ledger: release %d carry record is incomplete", i)
				}
				if last && !ownApproval(l) {
					return fmt.Errorf("setup ledger: release %d is carried without an approval", i)
				}
			default:
				return fmt.Errorf("setup ledger: release %d has unknown effect %q", i, r.Effect)
			}
		default:
			return fmt.Errorf("setup ledger: release %d has status %q", i, r.Status)
		}
	}
	if len(l.Releases) > 0 && l.record(StepInstall).Status != StatusDone {
		return errors.New("setup ledger: a release is recorded before install")
	}
	if len(l.Releases) > 0 && l.record(StepInstall).Inputs["macserve"] != l.Releases[0].FromSHA256 {
		return errors.New("setup ledger: the first release does not continue from the installed binary")
	}
	return nil
}
