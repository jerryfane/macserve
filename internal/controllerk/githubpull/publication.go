package githubpull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubwire"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/receipt"
)

// publicationBudget bounds both the publications one pass makes and the runs
// one poll heals (HealGitHubPublications): each a check list and a create or
// update on GitHub.
const publicationBudget = 10

// heal makes publication work of runs that should have a check but never got
// one, logging each run it marks. A run the publisher would refuse (refusal)
// is never healed: it would spend the budget, and its fresh-priority
// publication slot, every poll without ever getting a check.
func (p *Poller) heal(ctx context.Context) error {
	keys, err := p.options.Store.HealGitHubPublications(ctx, publicationBudget, func(run store.GitHubRun) bool {
		reason, err := p.refusal(run)
		return err == nil && reason == ""
	})
	for _, key := range keys {
		log.Printf("GitHub publication healed: run=%s has no check; publishing it", key)
	}
	return err
}

func (p *Poller) publish(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var failures []error
	for range publicationBudget {
		publication, err := p.options.Store.NextGitHubPublication(ctx, p.options.Now().UTC())
		if errors.Is(err, store.ErrNotFound) {
			break
		}
		if err != nil {
			return errors.Join(append(failures, err)...)
		}
		checkID, err := p.publishOne(ctx, publication.Run)
		var retryAt time.Time
		if err != nil {
			failures = append(failures, err)
			// An ineligible head with no job never gains authority from a check.
			// Its best-effort rejection must not create endless fork-driven work;
			// a missing required check remains nonpassing.
			if publication.Run.JobID != "" || publication.Run.Blocked == "" {
				delay := 15 * time.Second * time.Duration(1<<min(publication.Failures, 8))
				if delay > time.Hour {
					delay = time.Hour
				}
				var remote *githubapi.Error
				if errors.As(err, &remote) && remote.RetryAfter > delay {
					delay = remote.RetryAfter
				}
				retryAt = p.options.Now().UTC().Add(delay)
			}
		}
		// Publication completion is local bookkeeping even when the remote call's
		// deadline elapsed. Losing this commit is safe: external_id reconciles it.
		commitCtx, commitCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		commitErr := p.options.Store.FinishGitHubPublication(commitCtx, publication, checkID, retryAt)
		commitCancel()
		if commitErr != nil {
			return errors.Join(append(failures, commitErr)...)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return errors.Join(failures...)
}

func (p *Poller) checkInput(ctx context.Context, run store.GitHubRun) (githubapi.CheckInput, error) {
	packet := githubwire.Packet{Schema: 1, JobID: run.JobID, AttemptID: run.AttemptID, Requests: make([]githubwire.Correlation, 0)}
	input := githubapi.CheckInput{Name: p.CheckName(run), HeadSHA: run.SHA, ExternalID: run.JobID, Status: "queued", Output: githubapi.CheckOutput{Title: "Mac evidence queued", Summary: "Waiting for controller execution; no signed result yet."}}
	if run.JobID == "" {
		input.ExternalID = "denied:" + run.Key
		if run.Skipped != "" && run.Blocked == "" {
			input.ExternalID = "skipped:" + run.Key
		} else if run.Skipped == "" && run.Blocked == "" && run.Awaits != "" {
			// Waiting for its build-for-testing producer (store.AwaitGitHub):
			// admitted by the poll after the producer succeeds.
			input.ExternalID = "waiting:" + run.Key
			producer, err := p.options.Store.GitHubRun(ctx, run.Awaits)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return input, err
			}
			input.Output.Title = "Waiting for build"
			input.Output.Summary = "This shard runs from the test products its build produces for this head; a poll after that build succeeds starts it. No job has run, so this check is not evidence."
			if producer.JobID != "" {
				input.Output.Title = "Waiting for build " + producer.JobID
			}
		} else if run.Skipped == "" && run.Blocked == "" {
			// Waiting (store.AdmitGitHub): admitted when the queue has space,
			// by a later poll in the pull request list's order.
			input.ExternalID = "waiting:" + run.Key
			input.Output.Title = "Waiting for queue space"
			input.Output.Summary = "The controller's queue is at its limit of unfinished jobs (per repository or in total); a later poll starts this run when a job ends. No job has run, so this check is not evidence."
		}
	}
	var job model.Job
	if run.JobID != "" {
		var err error
		job, err = p.options.Store.Get(ctx, run.JobID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return input, err
		}
		if errors.Is(err, store.ErrNotFound) {
			run.Blocked = "Execution evidence is no longer retained"
		}
		requests, err := p.options.Store.GitHubRequests(ctx, run.JobID)
		if err != nil {
			return input, err
		}
		for _, request := range requests {
			packet.Requests = append(packet.Requests, githubwire.Correlation{CommentID: request.CommentID, RequestID: request.RequestID, BodySHA256: request.BodySHA256})
		}
	}
	if run.Blocked != "" {
		input.Status = "completed"
		input.Conclusion = "action_required"
		input.Output.Title = "Mac evidence requires action"
		input.Output.Summary = run.Blocked
	} else if run.JobID == "" && run.Skipped != "" {
		// matrix_skip_paths or an entry's skip_paths: neutral passes branch
		// protection without claiming evidence.
		input.Status = "completed"
		input.Conclusion = "neutral"
		input.Output.Title = "Not run: docs/version-only change"
		input.Output.Summary = run.Skipped
	} else if job.State.Terminal() {
		input.Status = "completed"
		input.CompletedAt = job.FinishedAt
		input.Output.Title = "Mac evidence " + string(job.State)
		input.Output.Summary = "Controller execution is terminal. Only verified signed evidence may report success."
		switch job.State {
		case model.Cancelled:
			input.Conclusion = "cancelled"
		case model.TimedOut:
			input.Conclusion = "timed_out"
		case model.Expired:
			input.Conclusion = "action_required"
		default:
			input.Conclusion = "failure"
		}
		var completion struct {
			Receipt json.RawMessage `json:"receipt"`
		}
		if len(job.Result) > 0 && json.Unmarshal(job.Result, &completion) == nil && len(completion.Receipt) > 0 && len(completion.Receipt) <= 32768 {
			digest, err := receipt.PublicDigest(completion.Receipt)
			if err == nil {
				packet.Receipt = completion.Receipt
				packet.ReceiptDigest = digest
			} else {
				// Never redact or re-sign committed evidence. Legacy full receipts
				// remain private and need a new execution to publish a compact core.
				input.Conclusion = "action_required"
				input.Output.Summary = "Receipt is not safe for public publication; rerun execution to produce compact signed evidence."
			}
		}
		if job.State == model.Succeeded {
			input.Conclusion = "action_required"
			if len(packet.Receipt) > 0 && p.options.VerifyReceipt(job, run.RepositoryID, packet.Receipt) == nil {
				// The verifier proves the signature/policy; the publisher independently
				// binds its durable request-to-attempt mapping to those signed identities.
				var envelope struct {
					Payload struct {
						JobID     string               `json:"job_id"`
						AttemptID string               `json:"attempt_id"`
						Tests     receipt.TestEvidence `json:"tests"`
					} `json:"payload"`
				}
				if json.Unmarshal(packet.Receipt, &envelope) == nil && envelope.Payload.JobID == job.ID && envelope.Payload.AttemptID == run.AttemptID {
					input.Conclusion = "success"
					input.Output.Summary = "Complete signed execution evidence verified by the controller." + retriedSummary(envelope.Payload.Tests)
				}
			}
			if input.Conclusion != "success" {
				if input.Output.Summary == "Controller execution is terminal. Only verified signed evidence may report success." {
					input.Output.Summary = "Execution reported success but complete signed evidence could not be verified."
				}
			}
		}
	} else if job.State != "" && job.State != model.Queued {
		input.Status = "in_progress"
		input.StartedAt = job.StartedAt
		input.Output.Title = "Mac evidence " + string(job.State)
		input.Output.Summary = "Controller execution is in progress; this is unsigned live status, not evidence."
	}
	if input.Status == "completed" && input.CompletedAt == nil {
		now := p.options.Now().UTC()
		input.CompletedAt = &now
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(packet); err != nil {
		return input, err
	}
	data := bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
	if len(data) > 60000 {
		return input, errors.New("GitHub evidence output exceeds publication bound")
	}
	input.Output.Text = string(data)
	return input, nil
}

// retriedSummary is the check summary's note of a verified receipt's tests
// that passed on retry: their count and the receipt's bounded names
// (receipt.PublishedRetried), or nothing when none did.
func retriedSummary(t receipt.TestEvidence) string {
	if t.Retried == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\n%d test(s) failed and then passed on retry:", t.Retried)
	for _, name := range t.RetriedTests {
		fmt.Fprintf(&b, "\n- `%s`", strings.ReplaceAll(name, "`", "'"))
	}
	if more := t.Retried - len(t.RetriedTests); more > 0 {
		fmt.Fprintf(&b, "\n- and %d more (see the receipt's test cases)", more)
	}
	return b.String()
}

// CheckName is run's check name under its configured policy, which names a
// tiered matrix entry's check by its tier (githubwire.CheckName). The
// publisher publishes only a run its policy still admits under the same key,
// which binds the tier, so the name never changes during the run's life.
func (p *Poller) CheckName(run store.GitHubRun) string {
	policy, _ := p.runPolicy(run)
	return githubwire.CheckName(run.Profile, policy.Tier(run.Profile, run.Shard), run.Shard)
}

// skipped logs why publishOne neither created nor updated run's check.
func (p *Poller) skipped(run store.GitHubRun, reason string) {
	log.Printf("GitHub publication skipped: repository=%s head=%s check=%s run=%s job=%s check_id=%d: %s", run.Repository, run.SHA, p.CheckName(run), run.Key, run.JobID, run.CheckID, reason)
}

// refusal is why the publisher never publishes run's check under the
// configured policies, "" when it does. Every reason is permanent for this
// process's configuration and the poll's owner listings.
func (p *Poller) refusal(run store.GitHubRun) (string, error) {
	// A retired recipe/policy must never recreate an older same-name check
	// after the current requirement has been enrolled. Its receipt stays local.
	policy, ok := p.runPolicy(run)
	if !ok {
		return "no configured policy governs the run's repository", nil
	}
	if policy.PolicyRevision != run.PolicyRevision {
		return fmt.Sprintf("policy revision %d is not the run's %d", policy.PolicyRevision, run.PolicyRevision), nil
	}
	// Nor is an owner-form run published under a name its repository no
	// longer has (renamed, transferred or departed since the last listing).
	if policy.OwnerScoped() && p.discovered[run.RepositoryID] != run.Repository {
		return "the owner listing no longer has the repository under this name", nil
	}
	current, err := p.admission(policy, githubapi.PullRequest{Number: 1, HeadSHA: run.SHA}, run.Profile, run.Shard, nil)
	if errors.Is(err, ErrIneligible) {
		return "the policy no longer admits the run's profile and shard", nil
	}
	if err != nil {
		return "", err
	}
	if current.Run.Key != run.Key {
		return "the policy now admits run " + current.Run.Key + " instead (pins, recipe or timeout changed)", nil
	}
	return "", nil
}

func (p *Poller) publishOne(ctx context.Context, run store.GitHubRun) (int64, error) {
	reason, err := p.refusal(run)
	if err != nil {
		return 0, err
	}
	if reason != "" {
		p.skipped(run, reason)
		return run.CheckID, nil
	}
	input, err := p.checkInput(ctx, run)
	if err != nil {
		return 0, err
	}
	// Always reconcile the exact external ID first. The previous process may
	// have created a check successfully and died before persisting its ID.
	checks, err := p.options.Client.Checks(ctx, run.Repository, run.SHA)
	if err != nil {
		return 0, err
	}
	id := int64(0)
	for _, check := range checks {
		if check.Name == input.Name && check.HeadSHA == run.SHA && check.AppID == p.options.Client.AppID() && check.ExternalID == input.ExternalID && check.ID > id {
			id = check.ID
		}
	}
	if id == 0 && run.CheckID > 0 {
		check, err := p.options.Client.Check(ctx, run.Repository, run.CheckID)
		if err != nil {
			var remote *githubapi.Error
			if !errors.As(err, &remote) || remote.Status != 404 {
				return 0, err
			}
		} else {
			if check.Name != input.Name || check.HeadSHA != run.SHA || check.AppID != p.options.Client.AppID() {
				return 0, errors.New("durable GitHub check identity changed")
			}
			// #198: GitHub never moves a completed check back to queued or
			// in_progress, so a new attempt (rerun, retry) after a completed
			// one publishes a new check of the same name; the superseded one
			// stays as is. A crash after the create is reconciled above by
			// the new attempt's external_id, never by creating a second one.
			if check.Status != "completed" || check.ExternalID == input.ExternalID {
				id = check.ID
			}
		}
	}
	var check githubapi.Check
	if id == 0 {
		check, err = p.options.Client.CreateCheck(ctx, run.Repository, input)
	} else {
		input.HeadSHA = ""
		check, err = p.options.Client.UpdateCheck(ctx, run.Repository, id, input)
	}
	if err != nil {
		return 0, err
	}
	if check.ID <= 0 || check.AppID != p.options.Client.AppID() || check.Name != input.Name || check.HeadSHA != run.SHA || check.ExternalID != input.ExternalID {
		return 0, fmt.Errorf("GitHub check response failed identity verification")
	}
	return check.ID, nil
}
