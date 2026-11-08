package keyholder

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

// RefusalError is the keyholder's reasoned refusal; the caller cannot
// obtain the token or receipt without different inputs or policy.
type RefusalError struct{ Reason string }

func (e *RefusalError) Error() string { return "keyholder refused: " + e.Reason }

func refusal(format string, args ...any) error {
	return &RefusalError{Reason: fmt.Sprintf(format, args...)}
}

// GitHub is the keyholder's own GitHub App client: the only holder of the
// App key, used to mint tokens, list owner-policy repositories and check
// release provenance.
type GitHub interface {
	InstallationToken(ctx context.Context, repo string) (githubapi.InstallationToken, error)
	InstallationRepositories(ctx context.Context, owner string) ([]githubapi.Repository, error)
	DefaultBranchHead(ctx context.Context, repo string) (githubapi.BranchHead, error)
	CommitTree(ctx context.Context, repo, sha string) (string, error)
}

// ReceiptSigner is the receipt signer the keyholder owns (receipt.Signer).
type ReceiptSigner interface {
	Seal(ctx context.Context, job model.Job, result worker.Result) (json.RawMessage, error)
	Manifest(ctx context.Context, jobID, digest string) (json.RawMessage, error)
	Prune(ctx context.Context, retained func(string) (bool, error)) error
}

// Policy is the root-owned repository policy tokens are minted for: exact
// repositories pinned to numeric IDs and approved owner logins
// (controller.json receipt.repositories and receipt.owners). OwnerIDs pins
// the numeric account ID of each owner an owner-form pull policy names
// (github.policies[].owner_id): only those owners' repositories are listed,
// and a token for one of their repositories requires the pinned owner ID.
type Policy struct {
	Repositories map[string]int64
	Owners       []string
	OwnerIDs     map[string]int64
}

// Allows reports whether repo is a canonical repository the policy names.
func (p Policy) Allows(repo string) bool {
	if !repositoryPattern.MatchString(repo) {
		return false
	}
	if p.Repositories[repo] > 0 {
		return true
	}
	owner, _, _ := strings.Cut(repo, "/")
	return slices.Contains(p.Owners, owner)
}

// Options configures an Engine. GitHub is nil when no App is configured:
// then no token is minted and no release receipt is signed.
type Options struct {
	Signer   ReceiptSigner
	SealKeys map[string]ed25519.PublicKey
	Policy   Policy
	GitHub   GitHub
	// ReleaseScope loads the root-owned release scope on every release
	// decision, so an owner edit applies without a restart.
	ReleaseScope func() (ReleaseScope, error)
	// ReleaseDir holds the provenance verified for each sealed release, so
	// a retried seal of the same job and seal is signed identically.
	ReleaseDir string
	Now        func() time.Time
}

// Engine makes the keyholder's decisions; Server exposes it to the
// controller.
type Engine struct {
	options Options
	release *os.Root
	mu      sync.Mutex
}

// NewEngine validates options and opens the private release directory.
func NewEngine(o Options) (*Engine, error) {
	if o.Signer == nil || len(o.SealKeys) == 0 || o.ReleaseScope == nil || o.ReleaseDir == "" {
		return nil, errors.New("keyholder engine: signer, seal keys, release scope and release directory are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(o.ReleaseDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(o.ReleaseDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("keyholder release directory must be private")
	}
	root, err := os.OpenRoot(o.ReleaseDir)
	if err != nil {
		return nil, err
	}
	return &Engine{options: o, release: root}, nil
}

// Close releases the release directory and the receipt signer, which
// clears its key.
func (e *Engine) Close() error {
	err := e.release.Close()
	if closer, ok := e.options.Signer.(io.Closer); ok {
		err = errors.Join(err, closer.Close())
	}
	return err
}

// Token mints a short-lived installation token for repo, only when the
// root-owned policy names it. A repository pinned by ID must have that ID;
// otherwise a repository of an owner-form policy owner must belong to the
// pinned owner account ID, so a renamed or re-registered login never mints.
func (e *Engine) Token(ctx context.Context, repo string) (githubapi.InstallationToken, error) {
	if !e.options.Policy.Allows(repo) {
		return githubapi.InstallationToken{}, refusal("repository %q is outside the root-owned token policy", repo)
	}
	if e.options.GitHub == nil {
		return githubapi.InstallationToken{}, refusal("no GitHub App is configured")
	}
	token, err := e.options.GitHub.InstallationToken(ctx, repo)
	if err != nil {
		return githubapi.InstallationToken{}, err
	}
	owner, _, _ := strings.Cut(repo, "/")
	if pinned := e.options.Policy.Repositories[repo]; pinned > 0 {
		if token.RepositoryID != pinned {
			return githubapi.InstallationToken{}, refusal("repository %s ID %d is not the pinned %d", repo, token.RepositoryID, pinned)
		}
	} else if pin := e.options.Policy.OwnerIDs[owner]; pin > 0 && token.OwnerID != pin {
		return githubapi.InstallationToken{}, refusal("repository %s owner ID %d is not the pinned %d", repo, token.OwnerID, pin)
	}
	return token, nil
}

// Repositories lists the installation repositories of owner, only when an
// owner-form pull policy pins its account ID: those whose owner is that
// login and that account ID, at most githubapi.MaxInstallationRepositories.
// The installation-wide listing token never leaves the keyholder.
func (e *Engine) Repositories(ctx context.Context, owner string) ([]githubapi.Repository, error) {
	pin := e.options.Policy.OwnerIDs[owner]
	if pin <= 0 || !slices.Contains(e.options.Policy.Owners, owner) {
		return nil, refusal("owner %q has no owner-form pull policy", owner)
	}
	if e.options.GitHub == nil {
		return nil, refusal("no GitHub App is configured")
	}
	listed, err := e.options.GitHub.InstallationRepositories(ctx, owner)
	if err != nil {
		return nil, err
	}
	if len(listed) > githubapi.MaxInstallationRepositories {
		return nil, refusal("owner %s lists more than %d repositories", owner, githubapi.MaxInstallationRepositories)
	}
	repos := make([]githubapi.Repository, 0, len(listed))
	for _, r := range listed {
		name := strings.ToLower(r.FullName)
		if r.Owner.ID == pin && strings.EqualFold(r.Owner.Login, owner) && strings.HasPrefix(name, owner+"/") && repositoryPattern.MatchString(name) {
			repos = append(repos, r)
		}
	}
	return repos, nil
}

// SealRequest is the controller's receipt request: the job record, the
// worker's exact result and its build seal, the controller-normalized
// result the receipt describes and the admission approval. The keyholder
// signs only what the seal binds; the approval and normalization are
// controller statements, checked for consistency with the seal.
type SealRequest struct {
	Job      model.Job          `json:"job"`
	Worker   worker.Result      `json:"worker"`
	Result   worker.Result      `json:"result"`
	Seal     buildseal.Envelope `json:"seal"`
	Approval receipt.Approval   `json:"approval"`
}

type approvalKey struct{}

// ApprovalFromContext returns the approval of the receipt being sealed; the
// keyholder's receipt.Signer Approval option is this function.
func ApprovalFromContext(ctx context.Context, _ model.Job) (receipt.Approval, error) {
	a, ok := ctx.Value(approvalKey{}).(receipt.Approval)
	if !ok || a.Intake == "" || a.Identity == "" || a.AttemptID == "" {
		return receipt.Approval{}, refusal("receipt approval is missing")
	}
	return a, nil
}

var jobIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Seal re-validates a receipt request against the root worker's seal and,
// for a succeeded ios_archive job, the release scope and the keyholder's own
// GitHub check, then signs the receipt.
func (e *Engine) Seal(ctx context.Context, req SealRequest) (json.RawMessage, error) {
	job := req.Job
	if !jobIDPattern.MatchString(job.ID) {
		return nil, refusal("job id")
	}
	seal, err := buildseal.Verify(req.Seal, e.options.SealKeys)
	if err != nil {
		return nil, refusal("worker seal: %v", err)
	}
	if err := bindSeal(job, req.Worker, seal); err != nil {
		return nil, err
	}
	if err := checkNormalized(job, req.Worker, req.Result); err != nil {
		return nil, err
	}
	if req.Result.State == model.Succeeded && (seal.Resolution == nil || seal.State != model.Succeeded) {
		return nil, refusal("a success receipt needs the worker's registry resolution and success seal")
	}
	// Controller-supplied release provenance never reaches a receipt: a
	// succeeded ios_archive job carries only the keyholder's own.
	job.ReleaseProvenance = nil
	if job.Request.Kind == model.IOSArchive && req.Result.State == model.Succeeded {
		provenance, err := e.verifyRelease(ctx, job, seal, req.Seal.SealDigest(), req.Result)
		if err != nil {
			return nil, err
		}
		job.ReleaseProvenance = provenance
	}
	raw, err := e.options.Signer.Seal(context.WithValue(ctx, approvalKey{}, req.Approval), job, req.Result)
	if errors.Is(err, receipt.ErrInvalid) {
		// Evidence the signer will never sign as presented: definitive.
		return nil, refusal("receipt: %v", err)
	}
	return raw, err
}

// bindSeal checks that the seal is the worker's report of exactly this job
// record and worker result.
func bindSeal(job model.Job, result worker.Result, seal buildseal.Seal) error {
	if seal.JobID != job.ID || seal.WorkerEpoch != job.WorkerEpoch || !reflect.DeepEqual(seal.Request, job.Request) || seal.RequestDigest != job.RequestDigest {
		return refusal("worker seal is for another job, epoch or request")
	}
	snapshot, err := buildseal.Digest(job.Profile)
	if err != nil || snapshot != seal.SnapshotDigest {
		return refusal("worker seal binds another profile snapshot")
	}
	if r := seal.Resolution; r != nil && (r.ProfileID != job.Request.Profile || r.ProfileID != job.Profile.ID || r.ProfileVersion != job.Profile.Version || r.ProfileDigest != job.ProfileDigest) {
		return refusal("job profile identity differs from the worker's registry resolution")
	}
	digest, err := buildseal.Digest(result)
	if err != nil || digest != seal.ResultDigest || result.State != seal.State || result.Source != seal.Source {
		return refusal("worker result differs from its seal")
	}
	return nil
}

// checkNormalized allows exactly the controller's completion normalization
// of a worker result: dropping unverified artifacts and shortening artifact
// expiry, marking logs truncated, the parsed test summary of a test job and
// downgrading the state with a reason. Everything else is the worker's.
func checkNormalized(job model.Job, w, r worker.Result) error {
	same := w.Source == r.Source && w.StartedAt.Equal(r.StartedAt) && w.FinishedAt.Equal(r.FinishedAt) && sameExit(w.ExitCode, r.ExitCode) && w.Signal == r.Signal && w.CleanupOK == r.CleanupOK && w.PeakMemoryMiB == r.PeakMemoryMiB && reflect.DeepEqual(w.Observation, r.Observation) && reflect.DeepEqual(w.Commands, r.Commands)
	if !same || w.LogsTruncated && !r.LogsTruncated || !r.State.Terminal() {
		return refusal("normalized result changes the worker's execution evidence")
	}
	if !job.Request.Kind.Tests() && r.Summary != nil {
		return refusal("a test summary for a job that runs no tests")
	}
	if r.State == model.Succeeded && (w.State != model.Succeeded || r.Reason != w.Reason) {
		return refusal("normalized result claims a success the worker did not report")
	}
	next := 0
	for _, a := range r.Artifacts {
		found := false
		for ; next < len(w.Artifacts); next++ {
			if sameArtifact(w.Artifacts[next], a) {
				found = true
				next++
				break
			}
		}
		if !found {
			return refusal("normalized artifact %q is not the worker's", a.Name)
		}
	}
	return nil
}

func sameExit(a, b *int) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

func sameArtifact(w, r evidence.Artifact) bool {
	return w.ID == r.ID && w.Name == r.Name && w.MediaType == r.MediaType && w.SizeBytes == r.SizeBytes && w.SHA256 == r.SHA256 && !r.ExpiresAt.After(w.ExpiresAt)
}

func artifactDigest(artifacts []evidence.Artifact, name string) string {
	for _, a := range artifacts {
		if a.Name == name {
			return a.SHA256
		}
	}
	return ""
}

// verifyRelease decides a succeeded ios_archive receipt: the worker's sealed
// build must match the root-owned release scope exactly (version labels
// aside), and the keyholder's own GitHub check must find the scoped
// repository ID, the job's commit at the default-branch head and that
// commit's tree equal to the tree the worker computed from the bytes it
// built. The verified provenance is recorded per job and seal.
func (e *Engine) verifyRelease(ctx context.Context, job model.Job, seal buildseal.Seal, sealDigest string, result worker.Result) (*model.ReleaseProvenance, error) {
	if e.options.GitHub == nil {
		return nil, refusal("release receipts need the keyholder's GitHub App")
	}
	scope, err := e.options.ReleaseScope()
	if err != nil {
		return nil, refusal("release scope: %v", err)
	}
	entry, ok := scope.Repositories[job.Request.Repo]
	if !ok {
		return nil, refusal("repository %s has no release scope", job.Request.Repo)
	}
	r := seal.Resolution
	if err := entry.Check(r.ProfileID, r.ProfileVersion, r.ProfileDigest, r.Xcode, r.Flutter, seal.Request.Release); err != nil {
		return nil, refusal("release scope: %v", err)
	}
	if !sha40.MatchString(seal.SourceTree) || seal.Source.Commit != job.Request.SHA {
		return nil, refusal("the worker computed no source tree for the job's commit")
	}
	if seal.SigningManifestSHA256 == "" || seal.SigningManifestSHA256 != artifactDigest(result.Artifacts, profiles.SigningManifestArtifact) || seal.ArchiveSHA256 == "" || seal.ArchiveSHA256 != artifactDigest(result.Artifacts, profiles.ArchiveArtifact) {
		return nil, refusal("archive and signing manifest digests differ from the worker's seal")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	name := job.ID + "-" + sealDigest + ".json"
	if prior, err := e.loadProvenance(name); err == nil {
		return prior, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	head, err := e.options.GitHub.DefaultBranchHead(ctx, job.Request.Repo)
	if err != nil {
		return nil, fmt.Errorf("default-branch head: %w", err)
	}
	if head.RepositoryID != entry.RepositoryID {
		return nil, refusal("repository %s ID %d is not the release scope's %d", job.Request.Repo, head.RepositoryID, entry.RepositoryID)
	}
	if !strings.EqualFold(head.SHA, job.Request.SHA) || !model.ValidBranch(head.Branch) {
		return nil, refusal("commit %s is not the head %s of default branch %s", job.Request.SHA, head.SHA, head.Branch)
	}
	tree, err := e.options.GitHub.CommitTree(ctx, job.Request.Repo, job.Request.SHA)
	if err != nil {
		return nil, fmt.Errorf("commit tree: %w", err)
	}
	if tree != seal.SourceTree {
		return nil, refusal("commit tree %s is not the tree %s the worker computed from the source it built", tree, seal.SourceTree)
	}
	provenance := &model.ReleaseProvenance{RepositoryID: head.RepositoryID, DefaultBranch: head.Branch, HeadSHA: strings.ToLower(head.SHA), ResolvedAt: e.options.Now().UTC(), Source: model.ProvenanceGitHubApp}
	if err := e.saveProvenance(name, provenance); err != nil {
		return nil, err
	}
	return provenance, nil
}

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (e *Engine) loadProvenance(name string) (*model.ReleaseProvenance, error) {
	f, err := e.release.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, err
	}
	var p model.ReleaseProvenance
	if err := decodeStrict(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (e *Engine) saveProvenance(name string, p *model.ReleaseProvenance) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := ".pending-" + hex.EncodeToString(nonce[:])
	f, err := e.release.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer e.release.Remove(tmp)
	_, err = io.Copy(f, bytes.NewReader(raw))
	err = errors.Join(err, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	if err := e.release.Rename(tmp, name); err != nil {
		return err
	}
	dir, err := e.release.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Manifest returns a job's immutable full receipt manifest.
func (e *Engine) Manifest(ctx context.Context, jobID, digest string) (json.RawMessage, error) {
	return e.options.Signer.Manifest(ctx, jobID, digest)
}

// ReceiptJobs lists the job IDs the keyholder holds receipt manifests or
// provenance for.
func (e *Engine) ReceiptJobs(ctx context.Context) ([]string, error) {
	seen := map[string]bool{}
	if err := e.options.Signer.Prune(ctx, func(id string) (bool, error) { seen[id] = true; return true, nil }); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

// Forget removes the receipt manifests and release provenance of jobs the
// controller no longer retains.
func (e *Engine) Forget(ctx context.Context, jobIDs []string) error {
	drop := make(map[string]bool, len(jobIDs))
	for _, id := range jobIDs {
		if !jobIDPattern.MatchString(id) {
			return refusal("job id")
		}
		drop[id] = true
	}
	if err := e.options.Signer.Prune(ctx, func(id string) (bool, error) { return !drop[id], nil }); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	dir, err := e.release.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		stem, ok := strings.CutSuffix(name, ".json")
		index := strings.LastIndex(stem, "-")
		if !ok || index <= 0 || !drop[stem[:index]] {
			continue
		}
		if err := e.release.Remove(name); err != nil {
			return err
		}
	}
	return dir.Sync()
}
