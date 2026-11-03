package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// LedgerPath is the root-owned native setup ledger. The unprivileged
// preflight only stats it: a /Library/macserve whose ledger it cannot see
// as a root-owned regular file is treated as managed by other tooling.
const (
	InstallRoot = "/Library/macserve"
	LedgerDir   = InstallRoot + "/var/setup"
	LedgerPath  = LedgerDir + "/ledger.json"
	MaxLedger   = 1 << 20
)

// Step is one ordered setup step.
type Step string

const (
	StepPreflight       Step = "preflight"
	StepGitHub          Step = "github"
	StepInstall         Step = "install"
	StepTools           Step = "tools"
	StepOwnerActions    Step = "owner-actions"
	StepRound1          Step = "round-1"
	StepReboot          Step = "reboot"
	StepRound2          Step = "round-2"
	StepApproveAndStart Step = "approve-and-start"
	StepFirstBuild      Step = "first-build"
)

// Steps is the fixed order. GitHub precedes install and round 1 because
// the App, repository pin and template are bound into the install-time
// environment, the activation anchor and the round-1 tool evidence.
var Steps = []Step{
	StepPreflight, StepGitHub, StepInstall, StepTools, StepOwnerActions,
	StepRound1, StepReboot, StepRound2, StepApproveAndStart, StepFirstBuild,
}

// StepSummaries describe each step for the plan.
var StepSummaries = map[Step]string{
	StepPreflight:       "check this Mac and choose accounts, IDs, address and port (no root)",
	StepGitHub:          "create the GitHub App from a manifest and install it on one repository (no root)",
	StepInstall:         "one sudo prompt: create accounts and /Library/macserve with deploy-install, services disabled",
	StepTools:           "accept the Xcode license, run first launch and install the Metal toolchain system-wide",
	StepOwnerActions:    "you grant Full Disk Access and log in to the build account once (detected)",
	StepRound1:          "qualification round 1, unattended",
	StepReboot:          "restart the Mac (FileVault asks for your password, not macserve)",
	StepRound2:          "qualification round 2 on the new boot, unattended",
	StepApproveAndStart: "you type approve; services start only after that",
	StepFirstBuild:      "first build of your repository and receipt check",
}

// Status of one step record.
type Status string

const (
	StatusPending Status = "pending"
	StatusRunning Status = "running"
	StatusDone    Status = "done"
	StatusFailed  Status = "failed"
)

// Boot identifies one boot of the host: kern.boottime and
// kern.bootsessionuuid. A different boot changes both.
type Boot struct {
	Time        string `json:"time"`
	SessionUUID string `json:"session_uuid"`
}

func (b Boot) valid() bool { return b.Time != "" && b.SessionUUID != "" }

// differs reports a new boot: both identifiers changed.
func (b Boot) differs(o Boot) bool { return b.Time != o.Time && b.SessionUUID != o.SessionUUID }

// Record is one step's state. Inputs maps an input name to the sha256 of
// the bytes the step consumed.
type Record struct {
	Step     Step              `json:"step"`
	Status   Status            `json:"status"`
	Started  *time.Time        `json:"started,omitempty"`
	Finished *time.Time        `json:"finished,omitempty"`
	Boot     *Boot             `json:"boot,omitempty"`
	Inputs   map[string]string `json:"inputs,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// Approval is the owner's typed approval: the digest of the summary they
// saw and the boot it was given in.
type Approval struct {
	At            time.Time `json:"at"`
	SummarySHA256 string    `json:"summary_sha256"`
	Boot          Boot      `json:"boot"`
}

// Ledger is the ordered native setup state. A failed step blocks every
// later mutation; services may start only after round 2 on a new boot and
// an approval given in the current boot.
type Ledger struct {
	Schema   int       `json:"schema"`
	Owner    string    `json:"owner"`
	OwnerUID uint32    `json:"owner_uid"`
	Created  time.Time `json:"created"`
	Records  []Record  `json:"records"`
	Approval *Approval `json:"approval,omitempty"`
}

const ledgerSchema = 1

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
var inputName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// NewLedger returns a ledger with every step pending.
func NewLedger(owner string, ownerUID uint32, now time.Time) *Ledger {
	l := &Ledger{Schema: ledgerSchema, Owner: owner, OwnerUID: ownerUID, Created: now.UTC()}
	for _, s := range Steps {
		l.Records = append(l.Records, Record{Step: s, Status: StatusPending})
	}
	return l
}

func (l *Ledger) record(s Step) (*Record, int, error) {
	for i := range l.Records {
		if l.Records[i].Step == s {
			return &l.Records[i], i, nil
		}
	}
	return nil, -1, fmt.Errorf("unknown setup step %q", s)
}

// Failed returns the failed step, if any.
func (l *Ledger) Failed() (Record, bool) {
	for _, r := range l.Records {
		if r.Status == StatusFailed {
			return r, true
		}
	}
	return Record{}, false
}

// Next returns the step setup resumes at: the first step not done. It
// fails while any step is failed, and reports done=true when all are done.
func (l *Ledger) Next() (Record, bool, error) {
	if r, failed := l.Failed(); failed {
		return r, false, fmt.Errorf("setup step %s failed (%s); later steps are blocked", r.Step, r.Error)
	}
	for _, r := range l.Records {
		if r.Status != StatusDone {
			return r, false, nil
		}
	}
	return Record{}, true, nil
}

// Begin starts step s in boot. Only the next pending step may begin; an
// interrupted (still running) step is not restarted implicitly. Round 2
// requires a boot different from round 1's.
func (l *Ledger) Begin(s Step, boot Boot, now time.Time) error {
	next, done, err := l.Next()
	if err != nil {
		return err
	}
	if done {
		return errors.New("setup is complete")
	}
	if next.Step != s {
		return fmt.Errorf("setup step %s cannot begin before %s is done", s, next.Step)
	}
	if next.Status == StatusRunning {
		return fmt.Errorf("setup step %s was interrupted; it is not restarted automatically", s)
	}
	if !boot.valid() {
		return errors.New("boot identity required")
	}
	if s == StepRound2 {
		round1, _, _ := l.record(StepRound1)
		if round1.Boot == nil || !boot.differs(*round1.Boot) {
			return errors.New("round 2 requires a new boot after round 1")
		}
	}
	r, _, _ := l.record(s)
	t := now.UTC()
	b := boot
	r.Status, r.Started, r.Boot = StatusRunning, &t, &b
	return nil
}

// Complete finishes the running step s, recording its input digests. The
// reboot step completes only in a boot different from the one it began in.
func (l *Ledger) Complete(s Step, boot Boot, inputs map[string]string, now time.Time) error {
	if _, failed := l.Failed(); failed {
		return errors.New("a failed setup step blocks later steps")
	}
	r, _, err := l.record(s)
	if err != nil {
		return err
	}
	if r.Status != StatusRunning {
		return fmt.Errorf("setup step %s is %s, not running", s, r.Status)
	}
	for name, digest := range inputs {
		if !inputName.MatchString(name) || !sha256Hex.MatchString(digest) {
			return fmt.Errorf("setup step %s: invalid input digest %q", s, name)
		}
	}
	if !boot.valid() {
		return errors.New("boot identity required")
	}
	if s == StepReboot && !boot.differs(*r.Boot) {
		return errors.New("reboot step completes only after the host restarted")
	}
	if s == StepApproveAndStart && (l.Approval == nil || l.Approval.Boot != boot) {
		return errors.New("approve-and-start completes only after approval in this boot")
	}
	t := now.UTC()
	r.Status, r.Finished = StatusDone, &t
	if s == StepReboot {
		b := boot
		r.Boot = &b
	}
	if len(inputs) > 0 {
		r.Inputs = make(map[string]string, len(inputs))
		for k, v := range inputs {
			r.Inputs[k] = v
		}
	}
	return nil
}

// Fail marks the running step s failed. Nothing later can begin.
func (l *Ledger) Fail(s Step, reason string, now time.Time) error {
	r, _, err := l.record(s)
	if err != nil {
		return err
	}
	if r.Status != StatusRunning {
		return fmt.Errorf("setup step %s is %s, not running", s, r.Status)
	}
	if reason == "" {
		reason = "unspecified failure"
	}
	t := now.UTC()
	r.Status, r.Finished, r.Error = StatusFailed, &t, reason
	return nil
}

// Approve records the owner's typed approval of the summary digest. It is
// accepted only while approve-and-start runs, after round 2 is done.
func (l *Ledger) Approve(summarySHA256 string, boot Boot, now time.Time) error {
	if _, failed := l.Failed(); failed {
		return errors.New("a failed setup step blocks approval")
	}
	if !sha256Hex.MatchString(summarySHA256) || !boot.valid() {
		return errors.New("approval needs the summary sha256 and boot identity")
	}
	round2, _, _ := l.record(StepRound2)
	step, _, _ := l.record(StepApproveAndStart)
	if round2.Status != StatusDone || step.Status != StatusRunning {
		return errors.New("approval is accepted only after round 2, during approve-and-start")
	}
	l.Approval = &Approval{At: now.UTC(), SummarySHA256: summarySHA256, Boot: boot}
	return nil
}

// AuthorizeStart allows starting the services only during approve-and-start,
// with an approval given in the current boot.
func (l *Ledger) AuthorizeStart(boot Boot) error {
	if _, failed := l.Failed(); failed {
		return errors.New("a failed setup step blocks service start")
	}
	step, _, _ := l.record(StepApproveAndStart)
	if step.Status != StatusRunning {
		return errors.New("services start only during approve-and-start")
	}
	if l.Approval == nil {
		return errors.New("services start only after you type approve")
	}
	if l.Approval.Boot != boot {
		return errors.New("approval was given in another boot; approve again")
	}
	return nil
}

// Encode returns the canonical JSON ledger.
func (l *Ledger) Encode() ([]byte, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// DecodeLedger parses a ledger strictly and checks its invariants, so a
// resumed setup continues from exactly the recorded state.
func DecodeLedger(data []byte) (*Ledger, error) {
	if len(data) == 0 || len(data) > MaxLedger {
		return nil, errors.New("setup ledger: empty or oversized")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var l Ledger
	if err := d.Decode(&l); err != nil {
		return nil, fmt.Errorf("setup ledger: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("setup ledger: trailing data")
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &l, nil
}

func (l *Ledger) validate() error {
	if l.Schema != ledgerSchema {
		return fmt.Errorf("setup ledger: unsupported schema %d", l.Schema)
	}
	if l.Owner == "" || l.OwnerUID == 0 || l.Created.IsZero() {
		return errors.New("setup ledger: owner and creation time required")
	}
	if len(l.Records) != len(Steps) {
		return errors.New("setup ledger: step list does not match this release")
	}
	// Records are in order: a done prefix, then at most one running or
	// failed step, then pending steps.
	phase := 0
	for i, r := range l.Records {
		if r.Step != Steps[i] {
			return fmt.Errorf("setup ledger: step %d is %q, want %q", i, r.Step, Steps[i])
		}
		switch r.Status {
		case StatusDone:
			if phase != 0 || r.Started == nil || r.Finished == nil || r.Boot == nil || !r.Boot.valid() {
				return fmt.Errorf("setup ledger: step %s done out of order or incomplete", r.Step)
			}
		case StatusRunning, StatusFailed:
			if phase != 0 || r.Started == nil || r.Boot == nil || !r.Boot.valid() || (r.Status == StatusFailed) != (r.Error != "") {
				return fmt.Errorf("setup ledger: step %s %s out of order or incomplete", r.Step, r.Status)
			}
			phase = 1
		case StatusPending:
			if r.Started != nil || r.Finished != nil || r.Boot != nil || r.Inputs != nil || r.Error != "" {
				return fmt.Errorf("setup ledger: pending step %s has state", r.Step)
			}
			phase = 1
		default:
			return fmt.Errorf("setup ledger: step %s has unknown status %q", r.Step, r.Status)
		}
		for name, digest := range r.Inputs {
			if !inputName.MatchString(name) || !sha256Hex.MatchString(digest) {
				return fmt.Errorf("setup ledger: step %s: invalid input digest %q", r.Step, name)
			}
		}
	}
	if l.Approval != nil {
		step := l.Records[len(l.Records)-2]
		if step.Step != StepApproveAndStart || (step.Status != StatusRunning && step.Status != StatusDone && step.Status != StatusFailed) || !sha256Hex.MatchString(l.Approval.SummarySHA256) || !l.Approval.Boot.valid() {
			return errors.New("setup ledger: approval recorded outside approve-and-start")
		}
	}
	return nil
}
