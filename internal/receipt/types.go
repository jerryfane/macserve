// Package receipt signs controller-verified execution evidence using RFC 8785 and Ed25519.
package receipt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

const MaxReceiptBytes = 32768
const maxManifestBytes = 64 << 20

type ServiceIdentity struct {
	ID           string `json:"id"`
	HostID       string `json:"host_id"`
	Version      string `json:"version"`
	BinarySHA256 string `json:"binary_sha256"`
}
type Repository struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}
type Approval struct {
	Intake    string `json:"intake"`
	Identity  string `json:"identity"`
	AttemptID string `json:"attempt_id"`
}
type Options struct {
	Root       string
	KeyID      string
	PrivateKey ed25519.PrivateKey
	Service    ServiceIdentity
	Repository func(context.Context, model.Job) (Repository, error)
	Approval   func(context.Context, model.Job) (Approval, error)
	Now        func() time.Time
}
type Expected struct {
	RepositoryID                      int64
	Repo, SHA, Profile, ProfileDigest string
	Kind                              model.Kind
	Xcode                             model.Xcode
	Simulator                         *model.Simulator
	RequiredTests                     []string
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Encoding  string `json:"encoding"`
	Value     string `json:"value"`
}
type Envelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature Signature       `json:"signature"`
}

// Details contains the unabridged recipe, actual command records, parsed cases,
// digest maps, and artifact manifests. Compact receipts commit to these bytes.
type Details struct {
	Profile model.Profile `json:"profile"`
	Result  worker.Result `json:"result"`
}
type ManifestReference struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	URL       string `json:"url"`
}
type TestEvidence struct {
	Status           string   `json:"status"`
	ParserVersion    string   `json:"parser_version,omitempty"`
	Tests            int      `json:"tests"`
	Passed           int      `json:"passed"`
	Failed           int      `json:"failed"`
	Skipped          int      `json:"skipped"`
	ExpectedFailures int      `json:"expected_failures"`
	Required         []string `json:"required"`
	ExecutedRequired []string `json:"executed_required"`
	XCResultSHA256   string   `json:"xcresult_sha256,omitempty"`
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
}
type ResourcePolicy struct {
	TimeoutSeconds  int   `json:"timeout_seconds"`
	MemoryLimitMiB  int   `json:"memory_limit_mib"`
	PeakMemoryMiB   int64 `json:"peak_memory_mib"`
	CleanupRequired bool  `json:"cleanup_required"`
	CleanupOK       bool  `json:"cleanup_ok"`
}
type EvidenceDigests struct {
	Commands  string `json:"commands"`
	Artifacts string `json:"artifacts"`
	Generated string `json:"generated"`
	Lockfiles string `json:"lockfiles"`
	TestCases string `json:"test_cases"`
}

// Payload core fields are retained verbatim in a compact receipt. Complete is
// the signer's evidence assertion, not a replacement for the verifier's policy.
type Payload struct {
	Schema         int                 `json:"schema"`
	JobID          string              `json:"job_id"`
	AttemptID      string              `json:"attempt_id"`
	InputDigest    string              `json:"input_digest"`
	Service        ServiceIdentity     `json:"service"`
	Repository     Repository          `json:"repository"`
	Approval       Approval            `json:"approval"`
	Request        model.Request       `json:"request"`
	RequestDigest  string              `json:"request_digest"`
	ProfileDigest  string              `json:"profile_digest"`
	ProfileVersion int                 `json:"profile_version"`
	Source         worker.Source       `json:"source"`
	Observation    Observation         `json:"observation"`
	State          model.State         `json:"state"`
	Reason         string              `json:"reason,omitempty"`
	ExitCode       *int                `json:"exit_code,omitempty"`
	Signal         string              `json:"signal,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
	StartedAt      time.Time           `json:"started_at"`
	FinishedAt     time.Time           `json:"finished_at"`
	Deadline       *time.Time          `json:"deadline,omitempty"`
	SealedAt       time.Time           `json:"sealed_at"`
	WorkerEpoch    string              `json:"worker_epoch"`
	Resources      ResourcePolicy      `json:"resources"`
	Tests          TestEvidence        `json:"tests"`
	Logs           []evidence.Artifact `json:"logs"`
	LogsTruncated  bool                `json:"logs_truncated"`
	Digests        EvidenceDigests     `json:"digests"`
	CommandCount   int                 `json:"command_count"`
	ArtifactCount  int                 `json:"artifact_count"`
	Complete       bool                `json:"complete"`
	Missing        []string            `json:"missing"`
	Details        *Details            `json:"details,omitempty"`
	Manifest       *ManifestReference  `json:"manifest,omitempty"`
}

type Signer struct {
	mu      sync.Mutex
	options Options
	root    *os.Root
	closed  bool
}
