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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/store"
)

type Policy struct {
	RepositoryID   int64    `json:"repository_id"`
	Repository     string   `json:"repository"`
	AuthorIDs      []int64  `json:"author_ids"`
	BaseBranches   []string `json:"base_branches"`
	Profiles       []string `json:"profiles"`
	PolicyRevision int      `json:"policy_revision"`
	ActionsBotID   int64    `json:"actions_bot_id"`
	ActionsAppID   int64    `json:"actions_app_id"`
}

type Options struct {
	Store         *store.Store
	Profiles      *profiles.Registry
	Client        *githubapi.Client
	Policies      []Policy
	VerifyReceipt func(model.Job, json.RawMessage) error
	Now           func() time.Time
	PollInterval  time.Duration
}

type Packet struct {
	Schema        int             `json:"schema"`
	JobID         string          `json:"job_id"`
	AttemptID     string          `json:"attempt_id"`
	Requests      []Correlation   `json:"requests"`
	Receipt       json.RawMessage `json:"receipt,omitempty"`
	ReceiptDigest string          `json:"receipt_digest,omitempty"`
}

type Correlation struct {
	CommentID  int64  `json:"comment_id"`
	RequestID  string `json:"request_id"`
	BodySHA256 string `json:"body_sha256"`
}

type Request struct{ SHA, Profile, RequestID, Mode string }

var requestPattern = regexp.MustCompile(`^/mac-evidence sha=([0-9a-f]{40}) profile=([A-Za-z0-9][A-Za-z0-9_.-]{0,127}) request=(actions:([1-9][0-9]{0,18}):([1-9][0-9]{0,18})) mode=(ensure|rerun)$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var profilePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var ErrIneligible = errors.New("GitHub head is superseded or no longer eligible")

func ParseRequest(body string) (Request, error) {
	m := requestPattern.FindStringSubmatch(body)
	if m == nil {
		return Request{}, errors.New("invalid machine request")
	}
	for _, s := range m[4:6] {
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return Request{}, errors.New("invalid machine request identity")
		}
	}
	return Request{SHA: m[1], Profile: m[2], RequestID: m[3], Mode: m[6]}, nil
}

type Poller struct {
	options  Options
	policies map[string]Policy
	recipes  map[string]model.Profile
	mu       sync.Mutex
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
	p := &Poller{options: options, policies: make(map[string]Policy), recipes: make(map[string]model.Profile)}
	for _, profile := range options.Profiles.List() {
		p.recipes[profile.ID] = profile
	}
	ids := make(map[int64]bool)
	for _, original := range options.Policies {
		policy := original
		policy.Repository = strings.ToLower(policy.Repository)
		if policy.RepositoryID <= 0 || ids[policy.RepositoryID] || policy.PolicyRevision <= 0 || len(policy.AuthorIDs) == 0 || len(policy.BaseBranches) == 0 || len(policy.Profiles) == 0 || policy.ActionsBotID < 0 || policy.ActionsAppID < 0 || policy.ActionsBotID == 0 && policy.ActionsAppID != 0 {
			return nil, errors.New("invalid GitHub repository policy")
		}
		if _, ok := p.policies[policy.Repository]; ok {
			return nil, errors.New("duplicate GitHub repository policy")
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
		seen := make(map[string]bool)
		for _, id := range policy.Profiles {
			profile, ok := p.recipes[id]
			if !ok || profile.Repo != policy.Repository || !profilePattern.MatchString(id) || seen[id] {
				return nil, errors.New("invalid GitHub profile policy")
			}
			seen[id] = true
		}
		policy.AuthorIDs = slices.Clone(policy.AuthorIDs)
		policy.BaseBranches = slices.Clone(policy.BaseBranches)
		policy.Profiles = slices.Clone(policy.Profiles)
		p.policies[policy.Repository] = policy
		ids[policy.RepositoryID] = true
	}
	if err := options.Store.InitializeGitHub(context.Background()); err != nil {
		return nil, err
	}
	return p, nil
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
	if err := p.publish(ctx); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func eligible(policy Policy, pull githubapi.PullRequest) bool {
	return pull.Number > 0 && pull.State == "open" && shaPattern.MatchString(pull.HeadSHA) && pull.HeadRepositoryID == policy.RepositoryID && slices.Contains(policy.AuthorIDs, pull.AuthorID) && slices.Contains(policy.BaseBranches, pull.BaseRef)
}

func (p *Poller) admission(policy Policy, pull githubapi.PullRequest, profileID string) (store.GitHubAdmission, error) {
	profile, ok := p.recipes[profileID]
	if !ok || !slices.Contains(policy.Profiles, profileID) {
		return store.GitHubAdmission{}, ErrIneligible
	}
	admission, err := p.options.Profiles.Resolve(model.Request{Repo: policy.Repository, SHA: pull.HeadSHA, Kind: profile.Kind, Profile: profile.ID, Xcode: profile.Xcode, Simulator: profile.Simulator, Context: model.RequestContext{PullRequest: pull.Number}})
	if err != nil {
		return store.GitHubAdmission{}, err
	}
	runtime := ""
	if profile.Simulator != nil {
		runtime = profile.Simulator.RuntimeBuild
	}
	// JSON length-prefixing prevents ambiguity between arbitrary configured pins.
	data, err := json.Marshal([]any{policy.RepositoryID, pull.HeadSHA, profile.ID, admission.ProfileDigest, profile.Xcode.Build, runtime, policy.PolicyRevision})
	if err != nil {
		return store.GitHubAdmission{}, err
	}
	digest := sha256.Sum256(data)
	return store.GitHubAdmission{Run: store.GitHubRun{Key: hex.EncodeToString(digest[:]), RepositoryID: policy.RepositoryID, Repository: policy.Repository, SHA: pull.HeadSHA, Profile: profile.ID, PolicyRevision: policy.PolicyRevision}, Admission: admission, PullRequest: pull.Number, Mode: "ensure"}, nil
}

func (p *Poller) verifyRepository(ctx context.Context, policy Policy) error {
	repository, err := p.options.Client.Repository(ctx, policy.Repository)
	if err != nil {
		return err
	}
	if repository.ID != policy.RepositoryID || !strings.EqualFold(repository.FullName, policy.Repository) {
		return ErrIneligible
	}
	return nil
}

func (p *Poller) pollRepository(ctx context.Context, policy Policy) error {
	if err := p.verifyRepository(ctx, policy); err != nil {
		return err
	}
	cursor, err := p.options.Store.GitHubCursor(ctx, policy.RepositoryID)
	if err != nil {
		return err
	}
	now := p.options.Now().UTC()
	etag := cursor.ETag
	full := cursor.FullAt.IsZero() || now.Sub(cursor.FullAt) >= 15*time.Minute
	if full {
		etag = ""
	}
	pulls, next, unchanged, err := p.options.Client.ListPulls(ctx, policy.Repository, etag)
	if err != nil {
		return err
	}
	if unchanged {
		if len(cursor.Pulls) == 0 {
			return errors.New("GitHub conditional response has no durable snapshot")
		}
		if err = json.Unmarshal(cursor.Pulls, &pulls); err != nil {
			return err
		}
	} else {
		cursor.Pulls, err = json.Marshal(pulls)
		if err != nil {
			return err
		}
		cursor.ETag = next
	}
	if full && !unchanged {
		cursor.FullAt = now
	}
	var failures []error
	eligibleHeads := make(map[string]bool)
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
	// Revalidate active jobs even after a 304: list caching must not prolong
	// execution of a closed, forked or superseded head.
	runs, err := p.options.Store.GitHubRuns(ctx, policy.RepositoryID)
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
		err = p.BeforeDispatch(ctx, job)
		if errors.Is(err, ErrIneligible) {
			_, err = p.options.Store.Cancel(ctx, job.ID, "GitHub head superseded or ineligible", now)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	since := cursor.CommentsSince
	if !since.IsZero() {
		since = since.Add(-2 * time.Minute)
	}
	comments, err := p.options.Client.Comments(ctx, policy.Repository, since)
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
			if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrCorrelationLimit) || errors.Is(err, store.ErrRerunLimit) || errors.Is(err, ErrIneligible) {
				continue
			}
			commentsOK = false
			failures = append(failures, err)
		}
	}
	if commentsOK {
		cursor.CommentsSince = now
	}
	if full && !unchanged {
		if err = p.options.Store.ReconcileGitHubPublications(ctx, policy.RepositoryID); err != nil {
			failures = append(failures, err)
		}
	}
	// Failed comment admissions retain their cursor; previously accepted requests
	// remain idempotent when the overlap window is retried.
	if err = p.options.Store.SaveGitHubCursor(ctx, policy.RepositoryID, cursor); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (p *Poller) acceptComment(ctx context.Context, policy Policy, comment githubapi.Comment, now time.Time) error {
	if policy.ActionsBotID == 0 || comment.AuthorID != policy.ActionsBotID || comment.AppID != 0 && (policy.ActionsAppID == 0 || comment.AppID != policy.ActionsAppID) || comment.ID <= 0 || comment.PullRequest <= 0 || comment.CreatedAt.IsZero() || !comment.CreatedAt.Equal(comment.UpdatedAt) {
		return nil
	}
	request, err := ParseRequest(comment.Body)
	if err != nil {
		return nil
	}
	if !slices.Contains(policy.Profiles, request.Profile) {
		return nil
	}
	pull, err := p.options.Client.Pull(ctx, policy.Repository, comment.PullRequest)
	if err != nil {
		return err
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
	run, err := p.options.Store.GitHubByJob(ctx, job.ID)
	if errors.Is(err, store.ErrNotFound) && !strings.HasPrefix(job.Principal, "github:") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("GitHub provenance unavailable: %w", err)
	}
	policy, ok := p.policies[run.Repository]
	if !ok || run.PolicyRevision != policy.PolicyRevision || run.RepositoryID != policy.RepositoryID || run.Blocked != "" || !slices.Contains(policy.Profiles, run.Profile) {
		return ErrIneligible
	}
	if err = p.verifyRepository(ctx, policy); err != nil {
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
