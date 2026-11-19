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

// payloadSchema 2 adds the job's lane record (Payload.Concurrency, required)
// and the job account's peak footprint (ResourcePolicy.HostPeakMemoryMiB);
// the signer seals only schema 2. Schema-1 receipts, sealed before lanes,
// carry neither and still verify and validate under the single-job rules.
const (
	payloadSchema       = 2
	legacyPayloadSchema = 1
)

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
	// Products returns the producer binding of a consumer job's receipt:
	// the keyholder's own record of the producer's sealed products (nil
	// when the receipt binds none). Nil means no receipt binds products.
	Products func(context.Context, model.Job) (*Products, error)
	Now      func() time.Time
}
type Expected struct {
	RepositoryID                      int64
	Repo, SHA, Profile, ProfileDigest string
	Kind                              model.Kind
	Xcode                             model.Xcode
	Simulator                         *model.Simulator
	RequiredTests                     []string
	// Release is an ios_archive job's admitted release; nil for other kinds.
	Release *model.ReleaseRequest
	// BuildForTesting is the admitted request's build-for-testing flag.
	BuildForTesting bool
	// Products is the admitted request's test products reference: set
	// exactly for a consumer job, whose receipt binds that producer.
	Products *model.ProductsRef
	// RetryIterations is the admitted template's retry_failed_tests
	// iterations (model.Profile.RetryIterations); 0 without retries.
	RetryIterations int
}

// SelectorsRepoConfig is the only Products.SelectorsSource today: the
// consumer's selectors are its shard's in the commit's .macserve.json.
const SelectorsRepoConfig = "repo_config"

// Products binds a consumer job's receipt to the producer whose sealed test
// products it ran, from the keyholder's own record of the producer's
// signing (never the controller's): the producer's job ID, the SHA-256 of
// its verified seal and its recipe digest, the source tree both jobs
// computed, the products' SHA-256 the consumer verified and imported, the
// .xctestrun it ran, and where the consumer's test selectors came from.
type Products struct {
	ProducerJobID        string `json:"producer_job_id"`
	ProducerSealSHA256   string `json:"producer_seal_sha256"`
	ProducerRecipeDigest string `json:"producer_recipe_digest"`
	SourceTree           string `json:"source_tree"`
	ProductsSHA256       string `json:"products_sha256"`
	Xctestrun            string `json:"xctestrun"`
	SelectorsSource      string `json:"selectors_source"`
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
	Status           string `json:"status"`
	ParserVersion    string `json:"parser_version,omitempty"`
	Tests            int    `json:"tests"`
	Passed           int    `json:"passed"`
	Failed           int    `json:"failed"`
	Skipped          int    `json:"skipped"`
	ExpectedFailures int    `json:"expected_failures"`
	// RetryIterations is the job's retry opt-in (its template's
	// retry_failed_tests iterations); Retried counts the cases that passed
	// on retry, Superseded their failed attempts (Tests is Passed + Failed
	// + Skipped + ExpectedFailures + Superseded) and RetriedTests names the
	// first PublishedRetried of those cases' distinct IDs. All are omitted
	// when zero, so a receipt of a job without retries keeps its bytes.
	RetryIterations  int      `json:"retry_iterations,omitempty"`
	Retried          int      `json:"retried,omitempty"`
	Superseded       int      `json:"superseded,omitempty"`
	RetriedTests     []string `json:"retried_tests,omitempty"`
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
	// RepoConfigSHA256 is the sha256 of a template job's .macserve.json bytes;
	// the derived commands are in the details manifest's result observation.
	RepoConfigSHA256 string `json:"repo_config_sha256,omitempty"`
	// Flutter is a Flutter template job's observed Flutter, Dart, Ruby and
	// CocoaPods versions; other jobs' receipts omit it.
	Flutter worker.FlutterObservation `json:"flutter,omitzero"`
}
type ResourcePolicy struct {
	TimeoutSeconds int   `json:"timeout_seconds"`
	MemoryLimitMiB int   `json:"memory_limit_mib"`
	PeakMemoryMiB  int64 `json:"peak_memory_mib"`
	// HostPeakMemoryMiB (schema 2) is the job account's peak footprint while
	// the job ran, sibling lanes included; PeakMemoryMiB is the job's own
	// charge. It is zero, and omitted, when the worker reported none (a
	// pre-lane worker) and in every schema-1 receipt, so a schema-1 manifest
	// sealed before lanes republishes byte for byte.
	HostPeakMemoryMiB int64 `json:"host_peak_memory_mib,omitempty"`
	CleanupRequired   bool  `json:"cleanup_required"`
	CleanupOK         bool  `json:"cleanup_ok"`
}

// Concurrency (schema 2) is the job's lane record from the worker that ran
// it: its 1-based lane of the worker's MaxLanes; the jobs that executed in
// the worker while it did, bounded for publication (OverlapCount of them,
// the PublishedOverlaps longest in OverlappedJobs, and OverlapsSHA256 over
// the worker's complete list, which the full manifest's result carries); the
// rule that attributed job-account processes to it (worker.Attribution*); how
// many unattributed processes it observed; and the idle verdict its cleanup
// ended with (worker.Idle*).
type Concurrency struct {
	Lane                int       `json:"lane"`
	MaxLanes            int       `json:"max_lanes"`
	OverlapCount        int       `json:"overlap_count"`
	OverlappedJobs      []Overlap `json:"overlapped_jobs"`
	OverlapsSHA256      string    `json:"overlaps_sha256"`
	Attribution         string    `json:"attribution"`
	UnattributedResidue int       `json:"unattributed_residue"`
	IdleVerdict         string    `json:"idle_verdict"`
}

// PublishedOverlaps bounds Concurrency.OverlappedJobs, so a long job beside a
// replenished queue still fits the compact receipt's publication limit.
const PublishedOverlaps = 8

// PublishedRetried bounds TestEvidence.RetriedTests (and the GitHub check
// summary that names them), so a flaky suite still fits the compact
// receipt's publication limit; Retried keeps the full count.
const PublishedRetried = 8

// MaxRetriedTestName bounds each RetriedTests name in bytes; a longer case
// ID is cut there.
const MaxRetriedTestName = 200

type Overlap struct {
	JobID   string `json:"job_id"`
	Seconds int64  `json:"overlap_seconds"`
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
// Concurrency is required in schema 2 and absent in schema 1.
type Payload struct {
	Schema      int             `json:"schema"`
	JobID       string          `json:"job_id"`
	AttemptID   string          `json:"attempt_id"`
	InputDigest string          `json:"input_digest"`
	Service     ServiceIdentity `json:"service"`
	Repository  Repository      `json:"repository"`
	Approval    Approval        `json:"approval"`
	Request     model.Request   `json:"request"`
	// Release, ReleaseProvenance and SigningManifestSHA256 are an ios_archive
	// job's admitted release, its admission-time default-branch binding, and
	// the SHA-256 of its signing-manifest.json artifact; other receipts omit
	// all three.
	Release               *model.ReleaseRequest    `json:"release,omitzero"`
	ReleaseProvenance     *model.ReleaseProvenance `json:"release_provenance,omitzero"`
	SigningManifestSHA256 string                   `json:"signing_manifest_sha256,omitzero"`
	// Products is a consumer job's producer binding (see Products); other
	// receipts omit it.
	Products       *Products           `json:"products,omitzero"`
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
	Concurrency    *Concurrency        `json:"concurrency,omitempty"`
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
