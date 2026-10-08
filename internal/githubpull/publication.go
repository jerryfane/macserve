package githubpull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/store"
)

func (p *Poller) publish(ctx context.Context) error {
	var failures []error
	for range 100 {
		publication, err := p.options.Store.NextGitHubPublication(ctx, p.options.Now().UTC())
		if errors.Is(err, store.ErrNotFound) {
			break
		}
		if err != nil {
			return errors.Join(append(failures, err)...)
		}
		callCtx, cancel := context.WithTimeout(ctx, time.Minute)
		checkID, err := p.publishOne(callCtx, publication.Run)
		cancel()
		var retryAt time.Time
		if err != nil {
			failures = append(failures, err)
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
	packet := Packet{Schema: 1, JobID: run.JobID, AttemptID: run.AttemptID, Requests: make([]Correlation, 0)}
	input := githubapi.CheckInput{Name: "mac-evidence/" + run.Profile, HeadSHA: run.SHA, ExternalID: run.JobID, Status: "queued", Output: githubapi.CheckOutput{Title: "Mac evidence queued", Summary: "Waiting for controller execution; no signed result yet."}}
	if run.JobID == "" {
		input.ExternalID = "denied:" + run.Key
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
			packet.Requests = append(packet.Requests, Correlation{CommentID: request.CommentID, RequestID: request.RequestID, BodySHA256: request.BodySHA256})
		}
	}
	if run.Blocked != "" {
		input.Status = "completed"
		input.Conclusion = "action_required"
		input.Output.Title = "Mac evidence requires action"
		input.Output.Summary = run.Blocked
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
			digest, err := receipt.Digest(completion.Receipt)
			if err == nil {
				packet.Receipt = completion.Receipt
				packet.ReceiptDigest = digest
			}
		}
		if job.State == model.Succeeded {
			input.Conclusion = "action_required"
			if len(packet.Receipt) > 0 && p.options.VerifyReceipt(job, packet.Receipt) == nil {
				// The verifier proves the signature/policy; the publisher independently
				// binds its durable request-to-attempt mapping to those signed identities.
				var envelope struct {
					Payload struct {
						JobID     string `json:"job_id"`
						AttemptID string `json:"attempt_id"`
					} `json:"payload"`
				}
				if json.Unmarshal(packet.Receipt, &envelope) == nil && envelope.Payload.JobID == job.ID && envelope.Payload.AttemptID == run.AttemptID {
					input.Conclusion = "success"
					input.Output.Summary = "Complete signed execution evidence verified by the controller."
				}
			}
			if input.Conclusion != "success" {
				input.Output.Summary = "Execution reported success but complete signed evidence could not be verified."
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

func (p *Poller) publishOne(ctx context.Context, run store.GitHubRun) (int64, error) {
	// A retired recipe/policy must never recreate an older same-name check
	// after the current requirement has been enrolled. Its receipt stays local.
	policy, ok := p.policies[run.Repository]
	if !ok || policy.RepositoryID != run.RepositoryID || policy.PolicyRevision != run.PolicyRevision {
		return run.CheckID, nil
	}
	current, err := p.admission(policy, githubapi.PullRequest{Number: 1, HeadSHA: run.SHA}, run.Profile)
	if errors.Is(err, ErrIneligible) {
		return run.CheckID, nil
	}
	if err != nil {
		return 0, err
	}
	if current.Run.Key != run.Key {
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
			id = check.ID
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
