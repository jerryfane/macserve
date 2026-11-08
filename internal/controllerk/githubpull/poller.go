// Package githubpull reconciles GitHub PR heads into the controller's existing
// durable queue. GitHub publication is an outbox, never an execution path.
package githubpull

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubwire"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
)

type Options struct {
	Store    *store.Store
	Profiles *profiles.Registry
	Client   *githubapi.Client
	Policies []githubwire.Policy
	// VerifyReceipt checks a job's signed receipt against the run's
	// repository ID, the store-bound identity its check is published for.
	VerifyReceipt func(job model.Job, repositoryID int64, receipt json.RawMessage) error
	Now           func() time.Time
	PollInterval  time.Duration
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var profilePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var ErrIneligible = errors.New("GitHub head is superseded or no longer eligible")

// commentLookupError is remote lookup failure, never durable admission failure.
type commentLookupError struct{ err error }

func (e *commentLookupError) Error() string { return e.err.Error() }
func (e *commentLookupError) Unwrap() error { return e.err }

// Poller polls repository-form policies by name and owner-form policies by
// the App installation's repository listing of each owner. An owner-form
// policy is expanded per poll cycle into an effective policy per listed
// repository (target): its numeric repository ID, current name and allowed
// bases, carrying the owner identity that binds its runs.
type Poller struct {
	options  Options
	policies map[string]githubwire.Policy
	owners   map[string]githubwire.Policy
	pinned   map[int64]bool
	recipes  map[string]model.Profile
	tmpls    map[string]model.Template
	mu       sync.Mutex
	// Guarded by mu (held by Poll): the current name of each repository ID
	// the owner listings cover (replaced by every complete cycle), and each
	// owner-form head's parsed .macserve.json (key: repository ID, SHA; nil
	// when missing or invalid), kept while the head is still observed. The
	// template is selected from it against the governing policy on every use.
	discovered map[int64]string
	configs    map[string]*model.RepoConfig
}

func New(options Options) (*Poller, error) {
	if options.Store == nil || options.Profiles == nil || options.Client == nil || options.Client.AppID() <= 0 || options.VerifyReceipt == nil || options.PollInterval < 0 {
		return nil, errors.New("invalid GitHub pull configuration")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.PollInterval == 0 {
		options.PollInterval = 45 * time.Second
	}
	p := &Poller{options: options, policies: make(map[string]githubwire.Policy), owners: make(map[string]githubwire.Policy), pinned: make(map[int64]bool), recipes: make(map[string]model.Profile), tmpls: make(map[string]model.Template), discovered: make(map[int64]string), configs: make(map[string]*model.RepoConfig)}
	for _, profile := range options.Profiles.List() {
		p.recipes[profile.ID] = profile
	}
	for _, template := range options.Profiles.Templates() {
		p.tmpls[template.ID] = template
	}
	for _, original := range options.Policies {
		if err := original.CheckForm(); err != nil {
			return nil, err
		}
		policy := original
		policy.Repository = strings.ToLower(policy.Repository)
		if policy.PolicyRevision <= 0 || len(policy.AuthorIDs) == 0 || len(policy.Profiles) == 0 || policy.ActionsBotID < 0 || policy.ActionsAppID < 0 || policy.ActionsBotID == 0 && policy.ActionsAppID != 0 {
			return nil, errors.New("invalid GitHub repository policy")
		}
		for _, id := range policy.AuthorIDs {
			if id <= 0 {
				return nil, errors.New("invalid PR author identity")
			}
		}
		for _, branch := range policy.BaseBranches {
			if strings.TrimSpace(branch) != branch || branch == "" || strings.ContainsAny(branch, "\x00\r\n") {
				return nil, errors.New("invalid base branch policy")
			}
		}
		policy.AuthorIDs = slices.Clone(policy.AuthorIDs)
		policy.BaseBranches = slices.Clone(policy.BaseBranches)
		policy.Profiles = slices.Clone(policy.Profiles)
		if policy.OwnerScoped() {
			if err := p.ownerPolicy(policy); err != nil {
				return nil, err
			}
			p.owners[policy.Owner] = policy
			continue
		}
		if policy.RepositoryID <= 0 || p.pinned[policy.RepositoryID] || len(policy.BaseBranches) == 0 {
			return nil, errors.New("invalid GitHub repository policy")
		}
		if _, ok := p.policies[policy.Repository]; ok {
			return nil, errors.New("duplicate GitHub repository policy")
		}
		seen := make(map[string]bool)
		for _, id := range policy.Profiles {
			_, ok := p.recipe(policy, id)
			if !ok || !profilePattern.MatchString(id) || seen[id] {
				return nil, errors.New("invalid GitHub profile policy")
			}
			seen[id] = true
		}
		p.policies[policy.Repository] = policy
		p.pinned[policy.RepositoryID] = true
	}
	if err := options.Store.InitializeGitHub(context.Background()); err != nil {
		return nil, err
	}
	return p, nil
}

// ownerPolicy validates an owner-form policy: a canonical owner login and its
// numeric account ID, allowed bases, no Actions comment intake (pull mode
// only) and profiles that are distinct org templates of that owner which a
// pull request can run without a shard (no simulator test or archive kinds).
func (p *Poller) ownerPolicy(policy githubwire.Policy) error {
	if !githubapi.ValidOwner(policy.Owner) || policy.OwnerID <= 0 || policy.OwnerID > 9007199254740991 {
		return errors.New("invalid GitHub owner policy")
	}
	if _, ok := p.owners[policy.Owner]; ok {
		return errors.New("duplicate GitHub owner policy")
	}
	if len(policy.BaseBranches) == 0 && !policy.DefaultBranch || policy.ActionsBotID != 0 || policy.ActionsAppID != 0 {
		return errors.New("invalid GitHub owner policy")
	}
	seen := make(map[string]bool)
	for _, id := range policy.Profiles {
		template, ok := p.tmpls[id]
		if !ok || !profilePattern.MatchString(id) || seen[id] || template.Kind == model.IOSArchive || template.Kind.UsesSimulator() || !slices.Contains(template.Owners, policy.Owner) {
			return errors.New("invalid GitHub profile policy")
		}
		seen[id] = true
	}
	return nil
}

// target is the effective policy configured for repository, or false when
// the configured policy does not govern it. A repository-form policy governs
// only its pinned ID under its configured name. An owner-form policy governs
// a repository whose owner is its login and pinned account ID and which no
// repository-form policy pins, under the repository's current name; the
// repository's default branch is an allowed base when DefaultBranch is set.
func (p *Poller) target(policy githubwire.Policy, repository githubapi.Repository) (githubwire.Policy, bool) {
	name := strings.ToLower(repository.FullName)
	if !policy.OwnerScoped() {
		return policy, repository.ID == policy.RepositoryID && name == policy.Repository
	}
	owner, _, _ := strings.Cut(name, "/")
	if repository.ID <= 0 || p.pinned[repository.ID] || owner != policy.Owner || !strings.EqualFold(repository.Owner.Login, policy.Owner) || repository.Owner.ID != policy.OwnerID || !controllerconfig.ValidRepository(name) {
		return githubwire.Policy{}, false
	}
	if _, ok := p.policies[name]; ok {
		return githubwire.Policy{}, false
	}
	effective := policy
	effective.RepositoryID, effective.Repository = repository.ID, name
	effective.BaseBranches = slices.Clone(policy.BaseBranches)
	if policy.DefaultBranch && model.ValidBranch(repository.DefaultBranch) && !slices.Contains(effective.BaseBranches, repository.DefaultBranch) {
		effective.BaseBranches = append(effective.BaseBranches, repository.DefaultBranch)
	}
	return effective, true
}

// runPolicy is the configured policy a stored run was admitted under, with
// the run's repository identity: a repository-form policy of its name and
// ID, else the owner-form policy of its name's owner. Allowed bases are not
// known without a repository read (verifyRepository).
func (p *Poller) runPolicy(run store.GitHubRun) (githubwire.Policy, bool) {
	if policy, ok := p.policies[run.Repository]; ok {
		return policy, policy.RepositoryID == run.RepositoryID
	}
	owner, _, _ := strings.Cut(run.Repository, "/")
	policy, ok := p.owners[owner]
	if !ok {
		return githubwire.Policy{}, false
	}
	policy.RepositoryID, policy.Repository = run.RepositoryID, run.Repository
	return policy, true
}

func (p *Poller) Run(ctx context.Context) error {
	for {
		err := p.Poll(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		delay := p.options.PollInterval
		var remote *githubapi.Error
		if errors.As(err, &remote) && remote.RetryAfter > delay {
			delay = remote.RetryAfter
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Poll serializes this handle while SQLite serializes admissions/publications
// across reopened or independently running handles.
func (p *Poller) Poll(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var failures []error
	for _, policy := range p.policies {
		if err := p.pollRepository(ctx, policy); err != nil {
			failures = append(failures, err)
		}
	}
	failures = append(failures, p.pollOwners(ctx)...)
	if err := p.publish(ctx); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// rateLimited reports a GitHub refusal that asks the client to wait; the
// client then refuses further calls locally until the delay passes.
func rateLimited(err error) bool {
	var remote *githubapi.Error
	return errors.As(err, &remote) && remote.RetryAfter > 0
}

// pollOwners lists each owner-form policy owner's installation repositories
// once per cycle and polls every repository the policy governs. A rate limit
// ends the cycle. When every listing completed, repositories that left the
// listings (transferred to an unlisted owner, uninstalled, deleted) lose their
// current runs and any unfinished job, and template selections of heads not
// observed in the cycle are dropped.
func (p *Poller) pollOwners(ctx context.Context) []error {
	if len(p.owners) == 0 {
		return nil
	}
	var failures []error
	seen := make(map[int64]string)
	observed := make(map[string]bool)
	complete := true
	for _, owner := range slices.Sorted(maps.Keys(p.owners)) {
		policy := p.owners[owner]
		repositories, err := p.options.Client.InstallationRepositories(ctx, owner)
		if err == nil && len(repositories) > githubapi.MaxInstallationRepositories {
			err = errors.New("GitHub owner listing exceeds its bound")
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("GitHub owner %s: %w", owner, err))
			if rateLimited(err) {
				return failures
			}
			complete = false
			continue
		}
		for _, repository := range repositories {
			effective, ok := p.target(policy, repository)
			if _, dup := seen[effective.RepositoryID]; !ok || dup {
				continue
			}
			seen[effective.RepositoryID] = effective.Repository
			if err := p.pollOwnerRepository(ctx, effective, observed); err != nil {
				failures = append(failures, fmt.Errorf("GitHub repository %s: %w", effective.Repository, err))
				if rateLimited(err) {
					return failures
				}
			}
		}
	}
	if !complete {
		maps.Copy(p.discovered, seen)
		return failures
	}
	for key := range p.configs {
		if !observed[key] {
			delete(p.configs, key)
		}
	}
	// Departures are reconciled from durable runs, not from this process's
	// memory: a restart between a repository's admission and its departure
	// must still end its jobs.
	tracked, err := p.options.Store.GitHubTrackedRepositories(ctx)
	if err != nil {
		failures = append(failures, err)
	}
	for id, names := range tracked {
		if _, ok := seen[id]; ok || !p.ownerGoverned(id, names) {
			continue
		}
		if err := p.retire(ctx, id); err != nil {
			failures = append(failures, err)
		}
	}
	p.discovered = seen
	return failures
}

// ownerGoverned reports whether stored runs of repository ID id, admitted
// under names, belong to an owner-form policy's reconciliation: the ID is not
// pinned by a repository-form policy and some name is of an owner-form owner
// and not a repository-form policy's name.
func (p *Poller) ownerGoverned(id int64, names []string) bool {
	if p.pinned[id] {
		return false
	}
	for _, name := range names {
		owner, _, _ := strings.Cut(name, "/")
		if _, ok := p.owners[owner]; !ok {
			continue
		}
		if _, ok := p.policies[name]; !ok {
			return true
		}
	}
	return false
}

// retire ends a departed owner-form repository's current runs: its unfinished
// jobs are cancelled and its run snapshot is emptied for retention.
func (p *Poller) retire(ctx context.Context, repositoryID int64) error {
	now := p.options.Now().UTC()
	runs, err := p.options.Store.GitHubActiveRuns(ctx, repositoryID)
	if err != nil {
		return err
	}
	for _, run := range runs {
		if run.JobID == "" {
			continue
		}
		job, err := p.options.Store.Get(ctx, run.JobID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if job.State.Terminal() {
			continue
		}
		if _, err = p.options.Store.Cancel(ctx, job.ID, "GitHub repository left its owner policy", model.CancelReason{Source: model.CancelGitHub, Detail: ErrIneligible.Error()}, now); err != nil {
			return err
		}
	}
	return p.options.Store.MaintainGitHub(ctx, repositoryID, map[string]bool{}, now)
}

func eligible(policy githubwire.Policy, pull githubapi.PullRequest) bool {
	return pull.Number > 0 && pull.State == "open" && shaPattern.MatchString(pull.HeadSHA) && pull.HeadRepositoryID == policy.RepositoryID && slices.Contains(policy.AuthorIDs, pull.AuthorID) && slices.Contains(policy.BaseBranches, pull.BaseRef)
}

// recipe returns the admitted recipe snapshot that profile id names for the
// policy repository: an explicit profile of that repository, or a template
// whose owners include the repository owner while the repository has no
// explicit profile of the template's kind. A pull request never selects an
// ios_archive template: a release archive is admitted only at the default
// branch's head through the private API.
func (p *Poller) recipe(policy githubwire.Policy, id string) (model.Profile, bool) {
	if profile, ok := p.recipes[id]; ok {
		return profile, !policy.OwnerScoped() && profile.Repo == policy.Repository
	}
	template, ok := p.tmpls[id]
	if !ok || template.Kind == model.IOSArchive {
		return model.Profile{}, false
	}
	owner, _, _ := strings.Cut(policy.Repository, "/")
	if !slices.Contains(template.Owners, owner) {
		return model.Profile{}, false
	}
	for _, explicit := range p.recipes {
		if explicit.Repo == policy.Repository && explicit.Kind == template.Kind {
			return model.Profile{}, false
		}
	}
	return profiles.TemplateSnapshot(template, policy.Repository), true
}

// selectProfile is the first owner-form policy template whose snapshot the
// head's .macserve.json derives a recipe for, exactly as the worker will; ""
// when the file is missing, invalid or admits none. A head's file is
// immutable within its repository, so the parsed file is cached while the
// head is observed; the selection itself always uses the governing policy,
// which a transfer or rename may change.
func (p *Poller) selectProfile(ctx context.Context, policy githubwire.Policy, sha string, observed map[string]bool) (string, error) {
	key := strconv.FormatInt(policy.RepositoryID, 10) + "/" + sha
	observed[key] = true
	config, cached := p.configs[key]
	if !cached {
		data, found, err := p.options.Client.RegularFile(ctx, policy.Repository, sha, profiles.RepoConfigFile, profiles.MaxRepoConfigBytes)
		if err != nil {
			return "", err
		}
		if found {
			if parsed, err := profiles.ParseRepoConfig(data); err == nil {
				config = &parsed
			}
		}
		p.configs[key] = config
	}
	if config == nil {
		return "", nil
	}
	for _, id := range policy.Profiles {
		snapshot, ok := p.recipe(policy, id)
		if !ok {
			continue
		}
		if _, err := profiles.Derive(snapshot, *config); err == nil {
			return id, nil
		}
	}
	return "", nil
}

func (p *Poller) admission(policy githubwire.Policy, pull githubapi.PullRequest, profileID string) (store.GitHubAdmission, error) {
	profile, ok := p.recipe(policy, profileID)
	if !ok || !slices.Contains(policy.Profiles, profileID) {
		return store.GitHubAdmission{}, ErrIneligible
	}
	admission, err := p.options.Profiles.Resolve(model.Request{Repo: policy.Repository, SHA: pull.HeadSHA, Kind: profile.Kind, Profile: profile.ID, Xcode: profile.Xcode, Simulator: profile.Simulator, Flutter: profiles.RequestFlutter(profile), Context: model.RequestContext{PullRequest: pull.Number}})
	if err != nil {
		return store.GitHubAdmission{}, err
	}
	runtime := ""
	if profile.Simulator != nil {
		runtime = profile.Simulator.RuntimeBuild
	}
	// JSON length-prefixing prevents ambiguity between arbitrary configured pins.
	fields := []any{policy.RepositoryID, pull.HeadSHA, profile.ID, admission.ProfileDigest, profile.Xcode.Build, runtime, policy.PolicyRevision}
	if policy.OwnerScoped() {
		// An owner-form run binds its policy identity (owner login and
		// account ID) and the repository name its job fetches: a transfer
		// or rename admits a new run instead of continuing a stale one.
		fields = append(fields, "owner", policy.Owner, policy.OwnerID, policy.Repository)
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return store.GitHubAdmission{}, err
	}
	digest := sha256.Sum256(data)
	return store.GitHubAdmission{Run: store.GitHubRun{Key: hex.EncodeToString(digest[:]), RepositoryID: policy.RepositoryID, Repository: policy.Repository, SHA: pull.HeadSHA, Profile: profile.ID, PolicyRevision: policy.PolicyRevision}, Admission: admission, PullRequest: pull.Number, Mode: "ensure"}, nil
}

// verifyRepository reads the policy repository by name and returns its
// current effective policy, ErrIneligible when the configured policy no
// longer governs it under that name and ID.
func (p *Poller) verifyRepository(ctx context.Context, policy githubwire.Policy) (githubwire.Policy, error) {
	repository, err := p.options.Client.Repository(ctx, policy.Repository)
	if err != nil {
		return githubwire.Policy{}, err
	}
	configured := policy
	if policy.OwnerScoped() {
		configured = p.owners[policy.Owner]
	}
	current, ok := p.target(configured, repository)
	if !ok || current.RepositoryID != policy.RepositoryID || current.Repository != policy.Repository {
		return githubwire.Policy{}, ErrIneligible
	}
	return current, nil
}

// pollOwnerRepository enrolls the eligible heads of one owner-form
// repository. Pull mode only: no machine comments are read, and heads that
// are ineligible or that no template admits get no run and no check.
func (p *Poller) pollOwnerRepository(ctx context.Context, policy githubwire.Policy, observed map[string]bool) error {
	cursor, pulls, reconcile, now, err := p.pulls(ctx, policy)
	if err != nil {
		return err
	}
	var failures []error
	currentKeys := make(map[string]bool)
	for _, pull := range pulls {
		if !shaPattern.MatchString(pull.HeadSHA) {
			continue
		}
		allowed := eligible(policy, pull)
		if err = p.options.Store.ObserveGitHubHead(ctx, policy.RepositoryID, pull.Number, pull.HeadSHA, allowed, now); err != nil {
			return err
		}
		if !allowed {
			continue
		}
		profile, err := p.selectProfile(ctx, policy, pull.HeadSHA, observed)
		if err != nil {
			return err
		}
		if profile == "" {
			continue
		}
		input, err := p.admission(policy, pull, profile)
		if err != nil {
			return err
		}
		currentKeys[input.Run.Key] = true
		if _, err = p.options.Store.AdmitGitHub(ctx, input, now); err != nil {
			failures = append(failures, err)
		}
	}
	more, err := p.maintain(ctx, policy, reconcile, currentKeys, now)
	if err != nil {
		return err
	}
	failures = append(failures, more...)
	if err = p.options.Store.SaveGitHubCursor(ctx, policy.RepositoryID, cursor); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// pulls returns the repository's open pull requests, from a conditional list
// (the durable snapshot on 304) or a full list every 15 minutes; the cursor
// recording the list's ETag and full time; and whether the list was full and
// fresh, which reconciles current publications.
func (p *Poller) pulls(ctx context.Context, policy githubwire.Policy) (store.GitHubCursor, []githubapi.PullRequest, bool, time.Time, error) {
	cursor, err := p.options.Store.GitHubCursor(ctx, policy.RepositoryID)
	if err != nil {
		return cursor, nil, false, time.Time{}, err
	}
	now := p.options.Now().UTC()
	etag := cursor.ETag
	full := cursor.FullAt.IsZero() || now.Sub(cursor.FullAt) >= 15*time.Minute
	if full {
		etag = ""
	}
	pulls, next, unchanged, err := p.options.Client.ListPulls(ctx, policy.Repository, etag)
	if err != nil {
		return cursor, nil, false, now, err
	}
	if unchanged {
		if len(cursor.Pulls) == 0 {
			return cursor, nil, false, now, errors.New("GitHub conditional response has no durable snapshot")
		}
		if err = json.Unmarshal(cursor.Pulls, &pulls); err != nil {
			return cursor, nil, false, now, err
		}
	} else {
		cursor.Pulls, err = json.Marshal(pulls)
		if err != nil {
			return cursor, nil, false, now, err
		}
		cursor.ETag = next
	}
	if full && !unchanged {
		cursor.FullAt = now
	}
	return cursor, pulls, full && !unchanged, now, nil
}

// maintain replaces the repository's current-run snapshot, repairs current
// publications after a full list and revalidates active jobs even after a
// 304: list caching must not prolong execution of a closed, forked or
// superseded head. err is a store failure that ends the repository's poll.
func (p *Poller) maintain(ctx context.Context, policy githubwire.Policy, reconcile bool, currentKeys map[string]bool, now time.Time) (failures []error, err error) {
	if err = p.options.Store.MaintainGitHub(ctx, policy.RepositoryID, currentKeys, now); err != nil {
		return nil, err
	}
	if reconcile {
		if err = p.options.Store.ReconcileGitHubPublications(ctx, policy.RepositoryID); err != nil {
			failures = append(failures, err)
		}
	}
	runs, err := p.options.Store.GitHubActiveRuns(ctx, policy.RepositoryID)
	if err != nil {
		return nil, err
	}
	for _, run := range runs {
		if run.JobID == "" {
			continue
		}
		job, err := p.options.Store.Get(ctx, run.JobID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if job.State.Terminal() {
			continue
		}
		// A run admitted under another name of this repository ID (renamed or
		// transferred since) fetches a name that no longer governs it.
		err = ErrIneligible
		if run.Repository == policy.Repository {
			err = p.checkDispatch(ctx, job)
		}
		if errors.Is(err, ErrIneligible) {
			_, err = p.options.Store.Cancel(ctx, job.ID, "GitHub head superseded or ineligible", model.CancelReason{Source: model.CancelGitHub, Detail: err.Error()}, now)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	return failures, nil
}

func (p *Poller) pollRepository(ctx context.Context, policy githubwire.Policy) error {
	if _, err := p.verifyRepository(ctx, policy); err != nil {
		return err
	}
	cursor, pulls, reconcile, now, err := p.pulls(ctx, policy)
	if err != nil {
		return err
	}
	var failures []error
	eligibleHeads := make(map[string]bool)
	currentKeys := make(map[string]bool)
	for _, pull := range pulls {
		if eligible(policy, pull) {
			eligibleHeads[pull.HeadSHA] = true
		}
	}
	for _, pull := range pulls {
		allowed := eligible(policy, pull)
		if !shaPattern.MatchString(pull.HeadSHA) {
			continue
		}
		if err = p.options.Store.ObserveGitHubHead(ctx, policy.RepositoryID, pull.Number, pull.HeadSHA, allowed, now); err != nil {
			return err
		}
		if !allowed && eligibleHeads[pull.HeadSHA] {
			continue
		}
		for _, profile := range policy.Profiles {
			input, err := p.admission(policy, pull, profile)
			if err != nil {
				return err
			}
			currentKeys[input.Run.Key] = allowed
			if allowed {
				_, err = p.options.Store.AdmitGitHub(ctx, input, now)
			} else {
				err = p.options.Store.BlockGitHub(ctx, input.Run, "PR head does not satisfy repository admission policy", now)
			}
			if err != nil {
				failures = append(failures, err)
			}
		}
	}
	more, err := p.maintain(ctx, policy, reconcile, currentKeys, now)
	if err != nil {
		return err
	}
	failures = append(failures, more...)
	// Bootstrap deliberately excludes old machine requests. Persist the lower
	// bound before fetching so failures/restarts cannot slide it past requests.
	if cursor.CommentsSince.IsZero() {
		cursor.CommentsSince = now.Add(-24 * time.Hour)
	}
	if cursor.CommentsPage == 0 {
		cursor.CommentsPage = 1
		cursor.CommentsScanAt = now
		// Complete pages, not a bounded aggregate scan, are checkpointed. Only
		// finishing the scan advances its fixed time watermark; ongoing arrivals
		// are then covered by the next scan and its overlap.
	}
	if err = p.options.Store.SaveGitHubCursor(ctx, policy.RepositoryID, cursor); err != nil {
		return err
	}
	comments, nextPage, err := p.options.Client.CommentsPage(ctx, policy.Repository, cursor.CommentsSince.Add(-2*time.Minute), cursor.CommentsPage)
	if err != nil {
		return errors.Join(append(failures, err)...)
	}
	commentsOK := true
	// Deterministic oldest-first admission also makes bounded reruns fair when
	// API pagination or timestamps put the same overlap window in another order.
	slices.SortFunc(comments, func(a, b githubapi.Comment) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	for _, comment := range comments {
		if err = p.acceptComment(ctx, policy, comment, now); err != nil {
			var lookup *commentLookupError
			if errors.As(err, &lookup) {
				// Skip even transient lookup failures: one bad issue/PR must not
				// pin intake. The normal overlap may revisit it; no retry is owed.
				log.Printf("GitHub comment skipped: repository=%s comment=%d pull=%d lookup: %v", policy.Repository, comment.ID, comment.PullRequest, lookup)
				failures = append(failures, err)
				continue
			}
			if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrCorrelationLimit) || errors.Is(err, store.ErrRerunLimit) || errors.Is(err, ErrIneligible) {
				continue
			}
			commentsOK = false
			failures = append(failures, err)
			break
		}
	}
	if commentsOK {
		cursor.CommentsPage = nextPage
		if nextPage == 0 {
			cursor.CommentsSince = cursor.CommentsScanAt
			cursor.CommentsScanAt = time.Time{}
		}
	}
	// Failed comment admissions retain their cursor; previously accepted requests
	// remain idempotent when the overlap window is retried.
	if err = p.options.Store.SaveGitHubCursor(ctx, policy.RepositoryID, cursor); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (p *Poller) acceptComment(ctx context.Context, policy githubwire.Policy, comment githubapi.Comment, now time.Time) error {
	if policy.ActionsBotID == 0 || comment.AuthorID != policy.ActionsBotID || comment.AppID != 0 && (policy.ActionsAppID == 0 || comment.AppID != policy.ActionsAppID) || comment.ID <= 0 || comment.PullRequest <= 0 || comment.CreatedAt.IsZero() || !comment.CreatedAt.Equal(comment.UpdatedAt) {
		return nil
	}
	request, err := githubwire.ParseRequest(comment.Body)
	if err != nil {
		return nil
	}
	if !slices.Contains(policy.Profiles, request.Profile) {
		return nil
	}
	pull, err := p.options.Client.Pull(ctx, policy.Repository, comment.PullRequest)
	if err != nil {
		return &commentLookupError{err: err}
	}
	if !eligible(policy, pull) || pull.Number != comment.PullRequest || pull.HeadSHA != request.SHA {
		return ErrIneligible
	}
	input, err := p.admission(policy, pull, request.Profile)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(comment.Body))
	input.Mode = request.Mode
	input.Request = &store.GitHubRequest{CommentID: comment.ID, RequestID: request.RequestID, BodySHA256: hex.EncodeToString(digest[:])}
	_, err = p.options.Store.AdmitGitHub(ctx, input, now)
	return err
}

func (p *Poller) BeforeDispatch(ctx context.Context, job model.Job) error {
	// Preparation has a finite budget. A transient API outage must not turn an
	// eligible queued head into a permanent authorization rejection.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := p.checkDispatch(ctx, job)
		if err == nil || errors.Is(err, ErrIneligible) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		delay := p.options.PollInterval
		var remote *githubapi.Error
		if errors.As(err, &remote) {
			if remote.Status < 500 && remote.Status != 429 && remote.RetryAfter <= 0 {
				return err
			}
			delay = max(delay, remote.RetryAfter)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// checkDispatch is deliberately one-shot: active-job polling must never wait
// on the preparation retry loop.
func (p *Poller) checkDispatch(ctx context.Context, job model.Job) error {
	run, err := p.options.Store.GitHubByJob(ctx, job.ID)
	if errors.Is(err, store.ErrNotFound) && !strings.HasPrefix(job.Principal, "github:") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("GitHub provenance unavailable: %w", err)
	}
	policy, ok := p.runPolicy(run)
	if !ok || run.PolicyRevision != policy.PolicyRevision || run.Blocked != "" || !slices.Contains(policy.Profiles, run.Profile) {
		return ErrIneligible
	}
	if policy, err = p.verifyRepository(ctx, policy); err != nil {
		return err
	}
	for _, number := range run.PullRequests {
		pull, err := p.options.Client.Pull(ctx, run.Repository, number)
		if err != nil {
			return err
		}
		if eligible(policy, pull) && pull.Number == number && pull.HeadSHA == job.Request.SHA {
			input, err := p.admission(policy, pull, job.Request.Profile)
			if err != nil {
				return err
			}
			if input.Run.Key == run.Key && input.Admission.ProfileDigest == job.ProfileDigest {
				return nil
			}
		}
	}
	return ErrIneligible
}

func (p *Poller) Approval(ctx context.Context, job model.Job) (receipt.Approval, error) {
	run, err := p.options.Store.GitHubByJob(ctx, job.ID)
	if errors.Is(err, store.ErrNotFound) && !strings.HasPrefix(job.Principal, "github:") {
		return receipt.Approval{Intake: "private_api", Identity: job.Principal, AttemptID: job.ID}, nil
	}
	if err != nil {
		return receipt.Approval{}, err
	}
	return receipt.Approval{Intake: "github_pull", Identity: fmt.Sprintf("repository:%d/policy:%d/run:%s", run.RepositoryID, run.PolicyRevision, run.Key), AttemptID: run.AttemptID}, nil
}
