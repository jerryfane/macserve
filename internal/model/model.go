// Package model defines the persisted job and controller-owned recipe contracts.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Kind string

const (
	Build           Kind = "build"
	UnitTest        Kind = "unit_test"
	SimulatorUITest Kind = "simulator_ui_test"
)

type State string

const (
	Queued      State = "queued"
	Preparing   State = "preparing"
	Running     State = "running"
	Cancelling  State = "cancelling"
	Finalizing  State = "finalizing"
	Succeeded   State = "succeeded"
	Failed      State = "failed"
	TimedOut    State = "timed_out"
	Cancelled   State = "cancelled"
	Interrupted State = "interrupted"
	Expired     State = "expired"
)

func (s State) Terminal() bool {
	switch s {
	case Succeeded, Failed, TimedOut, Cancelled, Interrupted, Expired:
		return true
	default:
		return false
	}
}

func (s State) CanTransition(to State) bool {
	switch s {
	case Queued:
		return to == Preparing || to == Cancelled || to == Expired
	case Preparing:
		return to == Running || to == Cancelling || to == Finalizing
	case Running:
		return to == Cancelling || to == Finalizing
	case Cancelling:
		return to == Finalizing
	case Finalizing:
		return to == Succeeded || to == Failed || to == TimedOut || to == Cancelled || to == Interrupted
	default:
		return false
	}
}

type Xcode struct {
	Version string `json:"version"`
	Build   string `json:"build"`
}

type Simulator struct {
	Runtime      string `json:"runtime"`
	RuntimeBuild string `json:"runtime_build"`
	DeviceType   string `json:"device_type"`
}

type RequestContext struct {
	PullRequest int    `json:"pull_request,omitempty"`
	GateRef     string `json:"gate_ref,omitempty"`
}

type Request struct {
	Repo           string         `json:"repo"`
	SHA            string         `json:"sha"`
	Kind           Kind           `json:"kind"`
	Profile        string         `json:"profile"`
	Xcode          Xcode          `json:"xcode"`
	Simulator      *Simulator     `json:"simulator,omitempty"`
	TimeoutSeconds int            `json:"timeout_seconds,omitempty"`
	Context        RequestContext `json:"context,omitempty"`
}

// Command is trusted configuration, never a client-supplied command or shell string.
// Arguments may reference documented worker placeholders such as ${CHECKOUT}.
type Command struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
}

type GeneratedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type ArtifactRule struct {
	Path     string `json:"path"`
	Required bool   `json:"required"`
}

type Profile struct {
	ID                    string          `json:"id"`
	Version               int             `json:"version"`
	Repo                  string          `json:"repo"`
	Kind                  Kind            `json:"kind"`
	Xcode                 Xcode           `json:"xcode"`
	DeveloperDir          string          `json:"developer_dir"`
	Simulator             *Simulator      `json:"simulator,omitempty"`
	WorkDir               string          `json:"work_dir"`
	Prepare               []Command       `json:"prepare,omitempty"`
	Run                   Command         `json:"run"`
	GeneratedFiles        []GeneratedFile `json:"generated_files,omitempty"`
	Artifacts             []ArtifactRule  `json:"artifacts,omitempty"`
	RequiredTests         []string        `json:"required_tests,omitempty"`
	DefaultTimeoutSeconds int             `json:"default_timeout_seconds"`
	MaxTimeoutSeconds     int             `json:"max_timeout_seconds"`
	MemoryLimitMiB        int             `json:"memory_limit_mib"`
	// Template is set only on the admitted snapshot of a template job. Its
	// work_dir, prepare and run are derived by the worker from the template and
	// the repository's .macserve.json; configured profiles never carry it.
	Template *Template `json:"template,omitempty"`
}

// Template is a controller-owned, owner-scoped build recipe. Every repository
// of a listed GitHub account may use it by declaring its Xcode project or
// workspace and scheme in .macserve.json; the command line is fixed in code.
type Template struct {
	ID                    string   `json:"id"`
	Version               int      `json:"version"`
	Kind                  Kind     `json:"kind"`
	Owners                []string `json:"owners"`
	Xcode                 Xcode    `json:"xcode"`
	DeveloperDir          string   `json:"developer_dir"`
	DefaultTimeoutSeconds int      `json:"default_timeout_seconds"`
	MaxTimeoutSeconds     int      `json:"max_timeout_seconds"`
	MemoryLimitMiB        int      `json:"memory_limit_mib"`
}

// RepoConfig is the parsed repository-root .macserve.json. It may only name
// the work directory, project or workspace, scheme and two fixed steps.
type RepoConfig struct {
	Version         int    `json:"version"`
	WorkDir         string `json:"work_dir"`
	Project         string `json:"project,omitempty"`
	Workspace       string `json:"workspace,omitempty"`
	Scheme          string `json:"scheme"`
	XcodeGen        bool   `json:"xcodegen,omitempty"`
	ResolvePackages bool   `json:"resolve_packages,omitempty"`
}

// RepoRecipe is the worker's evidence of what a template job ran: the digest of
// the exact .macserve.json bytes, their parsed form, and the derived commands.
type RepoRecipe struct {
	ConfigSHA256 string     `json:"config_sha256"`
	Config       RepoConfig `json:"config"`
	WorkDir      string     `json:"work_dir"`
	Prepare      []Command  `json:"prepare"`
	Run          Command    `json:"run"`
}

func digestJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Digest is the qualified identity of a template: sha256 of its canonical JSON.
func (t Template) Digest() (string, error) { return digestJSON(t) }

// SnapshotDigest is the qualified identity bound to an admitted recipe snapshot:
// the profile's canonical JSON digest, or its template's digest for a template job.
func (p Profile) SnapshotDigest() (string, error) {
	if p.Template != nil {
		return p.Template.Digest()
	}
	return digestJSON(p)
}

type Admission struct {
	Request       Request `json:"request"`
	Profile       Profile `json:"profile"`
	ProfileDigest string  `json:"profile_digest"`
}

type Job struct {
	ID              string          `json:"id"`
	Principal       string          `json:"principal"`
	Request         Request         `json:"request"`
	Profile         Profile         `json:"profile"`
	ProfileDigest   string          `json:"profile_digest"`
	RequestDigest   string          `json:"request_digest"`
	State           State           `json:"state"`
	Reason          string          `json:"reason,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	Deadline        *time.Time      `json:"deadline,omitempty"`
	WorkerEpoch     string          `json:"worker_epoch,omitempty"`
	LeaseToken      string          `json:"-"`
	CancelRequested bool            `json:"cancel_requested"`
	Result          json.RawMessage `json:"result,omitempty"`
	CleanupOK       bool            `json:"cleanup_ok"`
}

type ServiceState struct {
	Paused           bool   `json:"paused"`
	PauseReason      string `json:"pause_reason,omitempty"`
	PauseMode        string `json:"pause_mode,omitempty"`
	Generation       int64  `json:"generation"`
	Quarantined      bool   `json:"quarantined"`
	QuarantineReason string `json:"quarantine_reason,omitempty"`
}

type LogRecord struct {
	Seq    int64     `json:"seq"`
	Time   time.Time `json:"time"`
	Stream string    `json:"stream"`
	Text   string    `json:"text"`
}
