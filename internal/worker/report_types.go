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
}

type ExecutedCommand struct {
	Executable string    `json:"executable"`
	Args       []string  `json:"args"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	ExitCode   int       `json:"exit_code"`
	Signal     string    `json:"signal,omitempty"`
}
