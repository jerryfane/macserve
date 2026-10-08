// Package worker executes controller-approved jobs without controller credentials.
package worker

import (
	"context"
	"io"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
)

// Source describes the controller-verified uncompressed Git archive stream.
type Source struct {
	Commit    string `json:"commit"`
	Tree      string `json:"tree"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type Observation struct {
	Xcode            model.Xcode       `json:"xcode"`
	SDKVersion       string            `json:"sdk_version"`
	SDKBuild         string            `json:"sdk_build"`
	SwiftVersion     string            `json:"swift_version"`
	OSVersion        string            `json:"os_version"`
	OSBuild          string            `json:"os_build"`
	Architecture     string            `json:"architecture"`
	RuntimeVersion   string            `json:"runtime_version,omitempty"`
	RuntimeBuild     string            `json:"runtime_build,omitempty"`
	DeviceUDID       string            `json:"device_udid,omitempty"`
	GeneratedDigests map[string]string `json:"generated_digests,omitempty"`
	LockfileDigests  map[string]string `json:"lockfile_digests,omitempty"`
}

type Result struct {
	State         model.State         `json:"state"`
	Reason        string              `json:"reason,omitempty"`
	ExitCode      *int                `json:"exit_code,omitempty"`
	Signal        string              `json:"signal,omitempty"`
	CleanupOK     bool                `json:"cleanup_ok"`
	StartedAt     time.Time           `json:"started_at"`
	FinishedAt    time.Time           `json:"finished_at"`
	Source        Source              `json:"source"`
	Observation   Observation         `json:"observation"`
	Summary       *evidence.Summary   `json:"summary,omitempty"`
	Artifacts     []evidence.Artifact `json:"artifacts"`
	LogsTruncated bool                `json:"logs_truncated"`
	Commands      []ExecutedCommand   `json:"commands"`
	PeakMemoryMiB int64               `json:"peak_memory_mib"`
}

type ExecutedCommand struct {
	Executable string    `json:"executable"`
	Args       []string  `json:"args"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	ExitCode   int       `json:"exit_code"`
	Signal     string    `json:"signal,omitempty"`
}

type Command struct {
	Executable     string
	Args           []string
	Dir            string
	Env            []string
	MemoryLimitMiB int
}

type ProcessResult struct {
	ExitCode      int
	Signal        string
	PeakMemoryMiB int64
	CleanupOK     bool
}

// Runner abstracts process execution only; production uses the native runner.
type Runner interface {
	Run(context.Context, Command, io.Writer, io.Writer) (ProcessResult, error)
	// Quiesce terminates every job-UID process outside the protected GUI baseline.
	// Failure forbids evidence sealing and another lease.
	Quiesce(context.Context) error
}

// Sink streams bounded evidence to the controller. An error cancels execution,
// but never prevents local process/device/workspace cleanup.
type Sink interface {
	Log(stream, text string) error
	Stage(model.State) error
}

type Options struct {
	Root              string
	ExportRoot        string
	WorkspaceRoot     string
	JobUID            uint32
	JobGID            uint32
	OwnerUID          uint32
	ControllerUID     uint32
	HelperPath        string
	BaselinePath      string
	Runner            Runner
	CleanupTimeout    time.Duration
	MaxWorkspaceBytes int64
	MaxArtifactBytes  int64
	Now               func() time.Time
}
