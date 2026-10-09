// Package waiter requests exact-head Mac evidence using a workflow's GitHub token.
// It never checks out PR code or cancels the shared Mac job.
package waiter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubpull"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/receipt"
)

var (
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Options struct {
	Client                *githubapi.Client
	Repo                  string
	RepositoryID          int64
	PullRequest           int
	Profile               string
	RequestID             string
	Mode                  string
	AppID                 int64
	Expected              receipt.Expected
	Keys                  map[string]ed25519.PublicKey
	Timeout, PollInterval time.Duration
}

type Result struct {
	JobID         string               `json:"job_id"`
	CheckURL      string               `json:"check_url"`
	ReceiptDigest string               `json:"receipt_digest"`
	Tests         receipt.TestEvidence `json:"tests"`
}

type acceptance struct {
	checkID          int64
	jobID, attemptID string
}

// Run posts one immutable machine request and waits for its current attempt's
// signed result. The timeout includes API requests and server-directed backoff.
func Run(ctx context.Context, options Options) (Result, error) {
	if err := prepare(&options); err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	result, err := run(ctx, options)
	if err != nil && ctx.Err() != nil {
		return Result{}, fmt.Errorf("Mac evidence wait ended without verified success: %w", ctx.Err())
	}
	return result, err
}

func prepare(o *Options) error {
	if o.Client == nil || o.Client.AppID() != 0 {
		return errors.New("waiter requires a GitHub token client")
	}
	if o.Repo == "" || o.RepositoryID <= 0 || o.PullRequest <= 0 || o.AppID <= 0 {
		return errors.New("invalid waiter repository, PR, or App identity")
	}
	if o.Mode == "" {
		o.Mode = "ensure"
	}
	if _, err := githubpull.ParseRequest(fmt.Sprintf("/mac-evidence sha=%s profile=%s request=%s mode=%s", strings.Repeat("0", 40), o.Profile, o.RequestID, o.Mode)); err != nil {
		return errors.New("invalid machine evidence request")
	}
	o.Repo = strings.ToLower(o.Repo)
	if (o.Expected.RepositoryID != 0 && o.Expected.RepositoryID != o.RepositoryID) || (o.Expected.Repo != "" && !strings.EqualFold(o.Expected.Repo, o.Repo)) || (o.Expected.Profile != "" && o.Expected.Profile != o.Profile) {
		return errors.New("expected receipt identity contradicts waiter request")
	}
	o.Expected.RepositoryID = o.RepositoryID
	o.Expected.Repo = o.Repo
	o.Expected.Profile = o.Profile
	if !digestPattern.MatchString(o.Expected.ProfileDigest) || o.Expected.Xcode.Version == "" || o.Expected.Xcode.Build == "" {
		return errors.New("waiter requires pinned recipe digest and Xcode version/build")
	}
	switch o.Expected.Kind {
	case model.Build, model.UnitTest:
	case model.SimulatorUITest:
		if o.Expected.Simulator == nil {
			return errors.New("UI evidence requires pinned simulator identity")
		}
	default:
		return errors.New("waiter requires a pinned job kind")
	}
	if s := o.Expected.Simulator; s != nil && (s.Runtime == "" || s.RuntimeBuild == "" || s.DeviceType == "") {
		return errors.New("waiter requires complete simulator pins")
	}
	if len(o.Keys) == 0 {
		return errors.New("waiter requires out-of-band pinned Ed25519 keys")
	}
	for id, key := range o.Keys {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return errors.New("invalid pinned Ed25519 key")
		}
	}
	if o.Timeout < 0 || o.PollInterval < 0 {
		return errors.New("waiter timeout and poll interval must be positive")
	}
	if o.Timeout == 0 {
		o.Timeout = 90 * time.Minute
	}
	if o.PollInterval == 0 {
		o.PollInterval = 15 * time.Second
	}
	return nil
}

func run(ctx context.Context, o Options) (Result, error) {
	repository, err := call(ctx, false, func() (githubapi.Repository, error) { return o.Client.Repository(ctx, o.Repo) })
	if err != nil {
		return Result{}, fmt.Errorf("read repository identity: %w", err)
	}
	if repository.ID != o.RepositoryID || !strings.EqualFold(repository.FullName, o.Repo) {
		return Result{}, errors.New("GitHub repository does not match pinned identity")
	}
	pull, err := currentPull(ctx, o)
	if err != nil {
		return Result{}, err
	}
	if o.Expected.SHA != "" && o.Expected.SHA != pull.HeadSHA {
		return Result{}, errors.New("PR head superseded the expected SHA")
	}
	o.Expected.SHA = pull.HeadSHA
	body := fmt.Sprintf("/mac-evidence sha=%s profile=%s request=%s mode=%s", pull.HeadSHA, o.Profile, o.RequestID, o.Mode)
	comment, err := call(ctx, true, func() (githubapi.Comment, error) {
		return o.Client.CreateComment(ctx, o.Repo, o.PullRequest, body)
	})
	if err != nil {
		return Result{}, fmt.Errorf("post machine evidence request: %w", err)
	}
	if comment.ID <= 0 || comment.Body != body || comment.PullRequest != o.PullRequest || comment.CreatedAt.IsZero() || !comment.CreatedAt.Equal(comment.UpdatedAt) {
		return Result{}, errors.New("GitHub did not return the immutable machine request")
	}
	bodySum := sha256.Sum256([]byte(body))
	correlation := githubpull.Correlation{CommentID: comment.ID, RequestID: o.RequestID, BodySHA256: hex.EncodeToString(bodySum[:])}
	var accepted acceptance
	for {
		if err := checkHead(ctx, o); err != nil {
			return Result{}, err
		}
		checks, err := call(ctx, false, func() ([]githubapi.Check, error) { return o.Client.Checks(ctx, o.Repo, o.Expected.SHA) })
		if err != nil {
			return Result{}, fmt.Errorf("list evidence checks: %w", err)
		}
		// A newer same-name service check supersedes an older one, even when the
		// older check already carries a matching successful receipt.
		var chosen githubapi.Check
		for _, check := range checks {
			if matchesCheck(check, o) && check.ID > chosen.ID {
				chosen = check
			}
		}
		if accepted.checkID != 0 && chosen.ID != accepted.checkID {
			return Result{}, errors.New("accepted evidence check was superseded or removed")
		}
		if chosen.ID != 0 {
			check, err := call(ctx, false, func() (githubapi.Check, error) { return o.Client.Check(ctx, o.Repo, chosen.ID) })
			if err != nil {
				return Result{}, fmt.Errorf("read evidence check: %w", err)
			}
			if check.ID != chosen.ID || !matchesCheck(check, o) {
				return Result{}, errors.New("evidence check identity changed during retrieval")
			}
			packet, matched, err := matchPacket(check, correlation)
			if err != nil {
				return Result{}, err
			}
			if accepted.checkID != 0 && (!matched || accepted.jobID != packet.JobID || accepted.attemptID != packet.AttemptID) {
				return Result{}, errors.New("accepted evidence attempt was superseded")
			}
			if matched {
				accepted = acceptance{checkID: check.ID, jobID: packet.JobID, attemptID: packet.AttemptID}
				switch check.Status {
				case "queued", "in_progress":
					if check.Conclusion != "" {
						return Result{}, errors.New("unfinished evidence check has a conclusion")
					}
				case "completed":
					if check.Conclusion != "success" {
						return Result{}, errors.New("Mac evidence attempt completed without success")
					}
					result, err := verify(check, packet, o)
					if err != nil {
						return Result{}, err
					}
					if err := checkHead(ctx, o); err != nil {
						return Result{}, err
					}
					if err := ctx.Err(); err != nil {
						return Result{}, err
					}
					return result, nil
				default:
					return Result{}, errors.New("unrecognized evidence check status")
				}
			}
		}
		if err := sleep(ctx, o.PollInterval); err != nil {
			return Result{}, err
		}
	}
}

func currentPull(ctx context.Context, o Options) (githubapi.PullRequest, error) {
	pull, err := call(ctx, false, func() (githubapi.PullRequest, error) { return o.Client.Pull(ctx, o.Repo, o.PullRequest) })
	if err != nil {
		return githubapi.PullRequest{}, fmt.Errorf("read current PR head: %w", err)
	}
	if pull.Number != o.PullRequest || pull.State != "open" || pull.HeadRepositoryID != o.RepositoryID || !shaPattern.MatchString(pull.HeadSHA) {
		return githubapi.PullRequest{}, errors.New("PR is not an open, same-repository exact head")
	}
	return pull, nil
}

func checkHead(ctx context.Context, o Options) error {
	pull, err := currentPull(ctx, o)
	if err != nil {
		return err
	}
	if pull.HeadSHA != o.Expected.SHA {
		return errors.New("PR head superseded the requested evidence")
	}
	return nil
}

func matchesCheck(check githubapi.Check, o Options) bool {
	return check.ID > 0 && check.Name == "mac-evidence/"+o.Profile && check.AppID == o.AppID && check.HeadSHA == o.Expected.SHA
}

func matchPacket(check githubapi.Check, expected githubpull.Correlation) (githubpull.Packet, bool, error) {
	var packet githubpull.Packet
	if check.Output.Text == "" {
		return packet, false, nil
	}
	if len(check.Output.Text) > 60000 {
		return packet, false, errors.New("evidence publication exceeds its size bound")
	}
	decoder := json.NewDecoder(strings.NewReader(check.Output.Text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&packet); err != nil {
		return packet, false, errors.New("invalid structured evidence publication")
	}
	if err := decoder.Decode(new(any)); err != io.EOF || packet.Schema != 1 || len(packet.Requests) > 128 {
		return packet, false, errors.New("invalid evidence publication schema")
	}
	matched := false
	for _, request := range packet.Requests {
		if request.CommentID != expected.CommentID {
			continue
		}
		if matched || request.RequestID != expected.RequestID || request.BodySHA256 != expected.BodySHA256 {
			return packet, false, errors.New("evidence acceptance contradicts immutable request correlation")
		}
		matched = true
	}
	if matched && (packet.JobID == "" || packet.AttemptID == "" || packet.JobID != check.ExternalID) {
		return packet, false, errors.New("evidence acceptance does not match the current check job")
	}
	return packet, matched, nil
}

func verify(check githubapi.Check, packet githubpull.Packet, o Options) (Result, error) {
	if len(packet.Receipt) == 0 || len(packet.Receipt) > 32768 || bytes.Equal(bytes.TrimSpace(packet.Receipt), []byte("null")) {
		return Result{}, errors.New("successful check lacks bounded signed evidence")
	}
	payload, err := receipt.Verify(packet.Receipt, o.Keys)
	if err != nil {
		return Result{}, fmt.Errorf("verify signed Mac evidence: %w", err)
	}
	if payload.JobID != packet.JobID || payload.AttemptID != packet.AttemptID {
		return Result{}, errors.New("signed evidence belongs to another job or attempt")
	}
	if err := receipt.ValidateSuccess(payload, o.Expected); err != nil {
		return Result{}, fmt.Errorf("Mac evidence does not satisfy pinned policy: %w", err)
	}
	digest, err := receipt.Digest(packet.Receipt)
	if err != nil {
		return Result{}, fmt.Errorf("digest signed Mac evidence: %w", err)
	}
	if digest != packet.ReceiptDigest {
		return Result{}, errors.New("published receipt digest does not match signed evidence")
	}
	return Result{JobID: packet.JobID, CheckURL: check.HTMLURL, ReceiptDigest: digest, Tests: payload.Tests}, nil
}

// Explicit rate-limit rejection is safe to retry for comment creation. Other
// mutation failures have an unknown outcome and must not post a duplicate.
func call[T any](ctx context.Context, mutation bool, request func() (T, error)) (T, error) {
	for {
		value, err := request()
		var apiErr *githubapi.Error
		if err == nil || !errors.As(err, &apiErr) || apiErr.RetryAfter <= 0 || (mutation && apiErr.Status != 403 && apiErr.Status != 429) {
			return value, err
		}
		if err := sleep(ctx, apiErr.RetryAfter); err != nil {
			var zero T
			return zero, err
		}
	}
}

func sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
