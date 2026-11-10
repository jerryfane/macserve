package worker

import (
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
)

// This file is class C in BOUNDARY.json: the job report types only. Types
// that drive execution (Command, Runner, Options, ...) stay in types.go.

// Source describes the controller-verified uncompressed Git archive stream.
type Source struct {
	Commit    string `json:"commit"`
	Tree      string `json:"tree"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type Observation struct {
	Xcode          model.Xcode `json:"xcode"`
	SDKVersion     string      `json:"sdk_version"`
	SDKBuild       string      `json:"sdk_build"`
	SwiftVersion   string      `json:"swift_version"`
	OSVersion      string      `json:"os_version"`
	OSBuild        string      `json:"os_build"`
	Architecture   string      `json:"architecture"`
	RuntimeVersion string      `json:"runtime_version,omitempty"`
	RuntimeBuild   string      `json:"runtime_build,omitempty"`
	DeviceUDID     string      `json:"device_udid,omitempty"`
	// SimulatorBootAttempts is how many devices the job created to get one
	// booted: 1, or 2 after the one infrastructure retry. Zero without a
	// simulator.
	SimulatorBootAttempts int               `json:"simulator_boot_attempts,omitempty"`
	GeneratedDigests      map[string]string `json:"generated_digests,omitempty"`
	LockfileDigests       map[string]string `json:"lockfile_digests,omitempty"`
	// MetalToolchain is what `xcodebuild -showComponent MetalToolchain`
	// reported for the job; see observeMetalToolchain.
	MetalToolchain *MetalToolchain `json:"metal_toolchain,omitempty"`
	// Recipe is set for template jobs only: the .macserve.json digest, its
	// parsed form and the commands derived from it.
	Recipe *model.RepoRecipe `json:"recipe,omitempty"`
	// Flutter is set for Flutter template jobs only; see
	// observeFlutterToolchain.
	Flutter *FlutterObservation `json:"flutter,omitempty"`
}

// FlutterObservation is a Flutter job's observed toolchain: the framework and
// Dart SDK versions `flutter --version --machine` reported for its SDK clone,
// the first line of `ruby -v` and `pod --version`.
type FlutterObservation struct {
	FrameworkVersion string `json:"framework_version"`
	DartSDKVersion   string `json:"dart_sdk_version"`
	Ruby             string `json:"ruby"`
	CocoaPods        string `json:"cocoapods"`
}

// MetalToolchain records the per-job Metal toolchain probe. Status and
// BuildVersion are the tool's "Status:" and "Build Version:" lines; Error is
// set instead when the probe failed. Neither outcome fails the job.
type MetalToolchain struct {
	Status       string `json:"status,omitempty"`
	BuildVersion string `json:"build_version,omitempty"`
	Error        string `json:"error,omitempty"`
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
	// HostPeakMemoryMiB is the peak footprint of every non-baseline job-UID
	// process while the job ran, siblings included; PeakMemoryMiB is the
	// job's own charge (its lane's processes when lanes run concurrently).
	HostPeakMemoryMiB int64        `json:"host_peak_memory_mib,omitempty"`
	Concurrency       *Concurrency `json:"concurrency,omitempty"`
}

// Attribution names how the broker decided which job-UID processes were the
// job's. AttributionAccount is the single-job rule: every non-baseline
// job-UID process. AttributionLineage labels command-root descendants and
// the job's simulator subtrees (see laneTracker).
const (
	AttributionAccount = "account/v1"
	AttributionLineage = "lineage+device/v1"
)

// Idle verdicts: IdleClean means the job's cleanup ended with the full
// job-account quiesce and admission (no other job was live); IdleNotRequired
// means siblings were live, the job's own processes and simulator were
// removed and no unattributed process remained; IdleDeferred means an
// unattributed process remained, so the job's cleanup is unverified until
// the worker is idle.
const (
	IdleClean       = "clean"
	IdleNotRequired = "not_required"
	IdleDeferred    = "deferred"
)

// Concurrency is the job's lane record. OverlappedJobs lists every job that
// executed in the worker while this one did, with the overlap in whole
// seconds.
type Concurrency struct {
	Lane                int       `json:"lane"`
	MaxLanes            int       `json:"max_lanes"`
	OverlappedJobs      []Overlap `json:"overlapped_jobs"`
	Attribution         string    `json:"attribution"`
	UnattributedResidue int       `json:"unattributed_residue"`
	IdleVerdict         string    `json:"idle_verdict"`
}

type Overlap struct {
	JobID   string `json:"job_id"`
	Seconds int64  `json:"overlap_seconds"`
}

type ExecutedCommand struct {
	Executable string    `json:"executable"`
	Args       []string  `json:"args"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	ExitCode   int       `json:"exit_code"`
	Signal     string    `json:"signal,omitempty"`
}
