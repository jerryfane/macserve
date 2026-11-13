// Package model defines the persisted job and controller-owned recipe contracts.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

type Kind string

const (
	Build           Kind = "build"
	UnitTest        Kind = "unit_test"
	SimulatorUITest Kind = "simulator_ui_test"
	// SimulatorScript builds the scheme for the job's simulator and runs one
	// repository script on it; the files it writes under the job's output
	// directory are its artifacts. It has no test evidence.
	SimulatorScript Kind = "simulator_script"
	// IOSArchive archives the scheme unsigned for iOS devices (Release,
	// CODE_SIGNING_ALLOWED=NO) at the request's release version. A trusted
	// worker step seals the .xcarchive and its signing manifest as the job's
	// artifacts; signing and upload are not part of the job. It has no
	// simulator and no test evidence.
	IOSArchive Kind = "ios_archive"
)

// Known reports whether k is one of the five job kinds.
func (k Kind) Known() bool {
	return k == Build || k == IOSArchive || k.UsesSimulator()
}

// Tests reports whether jobs of kind k run xcodebuild tests: they carry
// xcresult test evidence and required tests.
func (k Kind) Tests() bool {
	return k == UnitTest || k == SimulatorUITest
}

// UsesSimulator reports whether jobs of kind k run on a pinned simulator.
func (k Kind) UsesSimulator() bool {
	return k.Tests() || k == SimulatorScript
}

// Exclusive reports whether a job of kind k runs only while no other job
// is active, and keeps every other job from starting while it runs: a
// simulator_script job runs arbitrary repository shell in the shared job
// account, and an ios_archive job's evidence requires the job account
// stopped. A simulator_script job whose template opts in
// (Template.Concurrent) is not exclusive; Job.Exclusive decides for a job.
func (k Kind) Exclusive() bool {
	return k == SimulatorScript || k == IOSArchive
}

// MaxConcurrentJobs bounds the max_concurrent_jobs setting of the worker
// and the controller; 1 is the single-job service.
const MaxConcurrentJobs = 6

// MaxTimeoutSeconds is the largest job timeout a recipe of kind k may allow.
func (k Kind) MaxTimeoutSeconds() int {
	switch k {
	case SimulatorScript, SimulatorUITest:
		return 7200
	case IOSArchive:
		return 5400
	}
	return 3600
}

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
	Repo      string     `json:"repo"`
	SHA       string     `json:"sha"`
	Kind      Kind       `json:"kind"`
	Profile   string     `json:"profile"`
	Xcode     Xcode      `json:"xcode"`
	Simulator *Simulator `json:"simulator,omitempty"`
	Shard     string     `json:"shard,omitempty"` // test and script templates only: the .macserve.json shard to run
	// Flutter names a Flutter template job's Flutter version: it must equal
	// the template's pin exactly and is refused for any other recipe.
	Flutter *FlutterRequest `json:"flutter,omitempty"`
	// Release is an ios_archive job's version and Dart defines; it is
	// required for that kind and refused for every other.
	Release        *ReleaseRequest `json:"release,omitempty"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"`
	Context        RequestContext  `json:"context,omitempty"`
}

// ReleaseRequest is an ios_archive job's release: the marketing version
// (CFBundleShortVersionString) and build number (CFBundleVersion) the archive
// is built at and its manifest binds, and, for a Flutter template only, the
// --dart-define values the release is compiled with. Dart defines are
// non-secret app configuration by contract: they are stored in the job
// record and the signed receipt.
type ReleaseRequest struct {
	BuildName   string            `json:"build_name"`
	BuildNumber string            `json:"build_number"`
	DartDefines map[string]string `json:"dart_defines,omitempty"`
}

// ReleaseProvenance is the server-derived default-branch binding of an
// ios_archive job: the numeric repository ID, its default branch and that
// branch's head, which the job's commit equals, resolved at admission
// through the controller's GitHub App (Source ProvenanceGitHubApp). A
// qualification tool run records its pinned source instead (Source
// ProvenanceQualification); no receipt carries that.
type ReleaseProvenance struct {
	RepositoryID  int64     `json:"repository_id"`
	DefaultBranch string    `json:"default_branch"`
	HeadSHA       string    `json:"head_sha"`
	ResolvedAt    time.Time `json:"resolved_at"`
	Source        string    `json:"source"`
}

const (
	ProvenanceGitHubApp     = "github_app"
	ProvenanceQualification = "qualification"
)

// ValidBranch reports whether name is a default-branch name a release is
// bound to: 1 to 255 bytes of ASCII letters, digits, '.', '_', '-' and '/'
// within git's check-ref-format rules (no empty or '.'-leading component, no
// "..", no component ending ".lock", no trailing '.').
func ValidBranch(name string) bool {
	if len(name) == 0 || len(name) > 255 || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '/') {
			return false
		}
	}
	for part := range strings.SplitSeq(name, "/") {
		if part == "" || part[0] == '.' || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
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
	// work_dir, prepare, run and required tests are derived by the worker from
	// the template and the repository's .macserve.json; configured profiles
	// never carry it.
	Template *Template `json:"template,omitempty"`
	// Shard is the admitted request's shard on a test or script template job
	// snapshot; configured profiles never carry it.
	Shard string `json:"shard,omitempty"`
	// Release is the admitted request's release on an ios_archive template
	// job snapshot, from which its recipe derives; configured profiles never
	// carry it.
	Release *ReleaseRequest `json:"release,omitempty"`
}

// Concurrent reports whether p is the snapshot of a simulator_script
// template job whose template opts in to running beside other jobs.
func (p Profile) Concurrent() bool {
	return p.Kind == SimulatorScript && p.Template != nil && p.Template.Concurrent
}

// Template is a controller-owned, owner-scoped recipe. Every repository of a
// listed GitHub account may use it by declaring its Xcode project or workspace
// and scheme, and for a test or script template its shards, in .macserve.json;
// the command line is fixed in code. A test or script template pins one to
// four simulators; a build or ios_archive template pins none. A template with
// a Flutter pin serves only repositories with a flutter section, and only
// those.
type Template struct {
	ID                    string      `json:"id"`
	Version               int         `json:"version"`
	Kind                  Kind        `json:"kind"`
	Owners                []string    `json:"owners"`
	Xcode                 Xcode       `json:"xcode"`
	DeveloperDir          string      `json:"developer_dir"`
	Simulators            []Simulator `json:"simulators,omitempty"`
	DefaultTimeoutSeconds int         `json:"default_timeout_seconds"`
	MaxTimeoutSeconds     int         `json:"max_timeout_seconds"`
	MemoryLimitMiB        int         `json:"memory_limit_mib"`
	Flutter               *FlutterPin `json:"flutter,omitempty"`
	// Concurrent lets a simulator_script template's jobs run beside other
	// jobs, as test jobs do, instead of alone (Job.Exclusive). Only script
	// templates may set it. It is omitted when false, so a template without
	// it keeps its digest.
	Concurrent bool `json:"concurrent,omitempty"`
}

// FlutterPin is a Flutter template's exact tool identity: the Flutter SDK
// version and its release archive's sha256, the portable Ruby archive's
// sha256, the CocoaPods version every Podfile.lock must name and the sha256
// of the gem lockfile its gem tree was installed from. The root-owned tool
// paths derive from it (profiles.FlutterToolPaths).
type FlutterPin struct {
	Version          string `json:"version"`
	SDKSHA256        string `json:"sdk_sha256"`
	RubySHA256       string `json:"ruby_sha256"`
	CocoaPodsVersion string `json:"cocoapods_version"`
	GemsSHA256       string `json:"gems_sha256"`
}

// FlutterRequest is a job request's Flutter selection.
type FlutterRequest struct {
	Version string `json:"version"`
}

// RepoConfig is the parsed repository-root .macserve.json. It may only name
// the work directory, project or workspace, scheme, two fixed steps, the test
// shards of the test templates, the script shards of script templates and
// the Flutter app of Flutter templates.
type RepoConfig struct {
	Version         int            `json:"version"`
	WorkDir         string         `json:"work_dir"`
	Project         string         `json:"project,omitempty"`
	Workspace       string         `json:"workspace,omitempty"`
	Scheme          string         `json:"scheme"`
	XcodeGen        bool           `json:"xcodegen,omitempty"`
	ResolvePackages bool           `json:"resolve_packages,omitempty"`
	UITest          *TestShards    `json:"ui_test,omitempty"`
	UnitTest        *TestShards    `json:"unit_test,omitempty"`
	Script          *ScriptShards  `json:"script,omitempty"`
	Flutter         *FlutterConfig `json:"flutter,omitempty"`
}

// FlutterConfig names a Flutter repository's app directory, relative to the
// checkout root, whose ios/ directory is the work directory, and up to eight
// Ruby scripts, relative to the checkout root, that prepare runs with the
// pinned Ruby after the Flutter iOS configuration.
type FlutterConfig struct {
	AppDir      string   `json:"app_dir"`
	PrepareRuby []string `json:"prepare_ruby,omitempty"`
}

// TestShards maps each shard name to its -only-testing selectors,
// Target/Class or Target/Class/method. Build derivation ignores them.
type TestShards struct {
	Shards map[string][]string `json:"shards"`
}

// ScriptShards maps each shard name of a script template to the script it
// runs. Other kinds ignore them.
type ScriptShards struct {
	Shards map[string]ScriptShard `json:"shards"`
}

// ScriptShard names a script by its path relative to the work directory; the
// worker runs it with /bin/bash.
type ScriptShard struct {
	Run string `json:"run"`
}

// RepoRecipe is the worker's evidence of what a template job ran: the digest of
// the exact .macserve.json bytes, their parsed form, the derived commands and,
// for a test or script template, the shard (and a test template's required
// tests).
type RepoRecipe struct {
	ConfigSHA256  string     `json:"config_sha256"`
	Config        RepoConfig `json:"config"`
	WorkDir       string     `json:"work_dir"`
	Prepare       []Command  `json:"prepare"`
	Run           Command    `json:"run"`
	Shard         string     `json:"shard,omitempty"`
	RequiredTests []string   `json:"required_tests,omitempty"`
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
	// ReleaseProvenance is set by the admitting controller, never by a
	// client, for an ios_archive job only.
	ReleaseProvenance *ReleaseProvenance `json:"release_provenance,omitempty"`
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
	// Lane is the 1-based concurrency lane the controller assigned when it
	// claimed the job; 0 for a job never claimed, or claimed before lanes.
	Lane int `json:"lane,omitempty"`
	// ReleaseProvenance is an ios_archive job's admission-time
	// default-branch binding; other jobs have none.
	ReleaseProvenance *ReleaseProvenance `json:"release_provenance,omitempty"`
	// CancelReason is why cancellation was first requested, recorded with
	// the request. Jobs never cancelled, and jobs cancelled before schema
	// version 6, have none. It is job-record metadata only: receipts never
	// carry it.
	CancelReason *CancelReason `json:"cancel_reason,omitempty"`
}

// Exclusive reports whether job runs only while no other job is active and
// keeps every other job from starting while it runs: a job of an exclusive
// kind (Kind.Exclusive), unless it is a simulator_script job whose template
// opts in to concurrency (Profile.Concurrent).
func (j Job) Exclusive() bool {
	return j.Request.Kind.Exclusive() && !(j.Request.Kind == SimulatorScript && j.Profile.Concurrent())
}

// CancelSource names what requested a job's cancellation.
type CancelSource string

const (
	// CancelClient is POST /v1/jobs/<id>/cancel by an API principal.
	CancelClient CancelSource = "client"
	// CancelAdminPause is PUT /v1/admin/pause with mode cancel_active.
	CancelAdminPause CancelSource = "admin_pause"
	// CancelDeadline is the controller enforcing the job's deadline.
	CancelDeadline CancelSource = "deadline"
	// CancelHostReadiness is the readiness gate requiring cancellation; its
	// blockers are recorded.
	CancelHostReadiness CancelSource = "host_readiness"
	// CancelGateError is the readiness gate failing to evaluate.
	CancelGateError CancelSource = "gate_error"
	// CancelLogLimit is the job exceeding its log evidence limit.
	CancelLogLimit CancelSource = "log_limit"
	// CancelShutdown is the controller stopping with the job active.
	CancelShutdown CancelSource = "controller_shutdown"
	// CancelGitHub is GitHub intake superseding or blocking the job's run.
	CancelGitHub CancelSource = "github"
)

func (s CancelSource) Valid() bool {
	switch s {
	case CancelClient, CancelAdminPause, CancelDeadline, CancelHostReadiness, CancelGateError, CancelLogLimit, CancelShutdown, CancelGitHub:
		return true
	}
	return false
}

// CancelReason is the machine-readable cause of a cancellation request.
// Principal is set for client and admin_pause requests, Blockers for
// host_readiness; Detail is bounded free text. At is when the request was
// recorded.
type CancelReason struct {
	Source    CancelSource `json:"source"`
	Principal string       `json:"principal,omitempty"`
	Blockers  []string     `json:"blockers,omitempty"`
	At        time.Time    `json:"at"`
	Detail    string       `json:"detail,omitempty"`
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
