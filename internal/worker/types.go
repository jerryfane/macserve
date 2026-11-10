// Package worker executes controller-approved jobs without controller credentials.
package worker

import (
	"context"
	"io"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

type Command struct {
	Executable     string
	Args           []string
	Dir            string
	Env            []string
	MemoryLimitMiB int
	// JobID names the job the command runs for: its result records the
	// command and, with concurrent jobs, its processes are the job's lane
	// (see laneTracker), which alone its memory budget charges. Empty for
	// commands outside any job.
	JobID string
	// MemoryBaseline, shared by every command of one job, holds the job-UID
	// footprint sampled immediately before the job's first command; each
	// command is charged for footprint above it. Nil samples a baseline
	// before this command alone.
	MemoryBaseline *MemoryBaseline
}

// MemoryBaseline is the job-UID footprint that preceded a job. The runner
// sets it once, when the job's first command starts.
type MemoryBaseline struct {
	sampled bool
	kib     int64
}

type ProcessResult struct {
	ExitCode int
	Signal   string
	// PeakMemoryMiB is the charged peak: the highest sampled footprint of the
	// job UID's live processes above the command's MemoryBaseline.
	PeakMemoryMiB int64
	// HostPeakMemoryMiB is set only for a command of a job running in lane
	// mode, whose PeakMemoryMiB charges its own lane's processes: the peak
	// sampled footprint of every job-UID process.
	HostPeakMemoryMiB int64
	CleanupOK         bool
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
	Root          string
	ExportRoot    string
	WorkspaceRoot string
	JobUID        uint32
	JobGID        uint32
	// JobUser is the job account's short name, set as USER and LOGNAME for job
	// commands. New resolves it from JobUID (see jobAccountName).
	JobUser           string
	OwnerUID          uint32
	ControllerUID     uint32
	HelperPath        string
	BaselinePath      string
	PersistencePath   string
	Runner            Runner
	CleanupTimeout    time.Duration
	MaxWorkspaceBytes int64
	MaxArtifactBytes  int64
	// Lanes is how many jobs Execute runs at once (max_concurrent_jobs,
	// 1..model.MaxConcurrentJobs; 0 means 1). With 1 every job owns the
	// whole job account, as before lanes existed.
	Lanes int
	// PlistJSON converts property list bytes to JSON for an ios_archive
	// job's root-side signing manifest (bundle Info.plist and requested
	// entitlements). New defaults it to /usr/bin/plutil run by the worker
	// itself, never by the job runner (see plutilJSON).
	PlistJSON PlistDecoder
	Now       func() time.Time
}
