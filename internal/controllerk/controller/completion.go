package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"path"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

func completionDigest(result worker.Result) (string, error) {
	bytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(bytes)
	return hex.EncodeToString(digest[:]), nil
}

// refusedAdmission records a completion the worker reports as its refusal
// of the job before it ran, for a cause of the service's own
// (protocol.Completion.AdmissionRefused), as the controller's cancellation
// worker_admission before complete judges it: the job ends cancelled, not
// failed, and pull mode reruns its head (#119). A refusal by a draining
// worker (protocol.AdmissionWorkerDraining) instead returns the job, still
// preparing and not cancelled, to the queue untouched (#214). Only a failed
// result with cleanup_ok qualifies; any other completion is judged as it is,
// and a replay of a terminal job's completion is left to complete. An
// unknown refusal is invalid. retired reports that the lease was ended here
// and its epoch fenced (drainRefused): the completion needs no judgement by
// complete, and the worker is told its epoch is retired.
func (c *Controller) refusedAdmission(ctx context.Context, job model.Job, completion protocol.Completion) (retired bool, err error) {
	refusal, result := completion.AdmissionRefused, completion.Result
	if !refusal.Valid() {
		return false, store.ErrInvalid
	}
	if refusal == "" || result.State != model.Failed || !result.CleanupOK || job.State.Terminal() {
		return false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// job is the record the request's epoch and lease authenticated
	// (requestJob) before its body was read. The refusal acts only on that
	// lease: the job may since have returned to the queue and been claimed
	// again under a new lease, which a delayed request must never end.
	a := c.execution(job.ID)
	if a == nil || !a.offered || a.job.LeaseToken != job.LeaseToken || a.job.WorkerEpoch != job.WorkerEpoch {
		return false, store.ErrLease
	}
	current, err := c.options.Store.Get(ctx, job.ID)
	if err != nil {
		return false, err
	}
	if current.LeaseToken != job.LeaseToken || current.WorkerEpoch != job.WorkerEpoch {
		return false, store.ErrLease
	}
	if refusal == protocol.AdmissionWorkerDraining {
		return c.drainRefused(ctx, a, current, result.Reason)
	}
	_, err = c.cancelJob(ctx, current, "worker refused admission: "+string(refusal), model.CancelReason{Source: model.CancelWorkerAdmission, Detail: result.Reason}, c.options.Now())
	if err == nil {
		// The cancel reason keeps 512 bytes of the worker's reason; its whole
		// reason (at most 4 KiB) names what refused the job, such as the
		// processes of an unverifiable relaunch (#206).
		log.Printf("controller recorded worker admission refusal: job=%s refusal=%s reason=%q", job.ID, refusal, result.Reason)
	}
	return false, err
}

// requeuedDraining is the reason of a job a draining worker refused before
// it started, returned to the queue.
const requeuedDraining = "returned to queue: the worker refused it before it started while draining"

// errRefusalPending answers a second delivery of a drain refusal while
// another request is ending the same lease: retryable (409), and its source
// is left to the request that owns it. A retry after the lease ended is
// refused as gone (410), which the worker treats as delivered.
var errRefusalPending = fmt.Errorf("%w: another request is ending the lease for its drain refusal", store.ErrConflict)

// drainRefused returns current, delivered as a and refused by the worker
// before it started because the worker drains (worker.ErrDrainRefusal), to
// the queue (returnToQueue): same job, attempt and check run. Its epoch is
// fenced with the requeue, so it is claimed again only under the epoch the
// worker registers after its idle check passes. A job no longer preparing
// (the worker reported it running) or whose cancellation was requested is
// left to complete, as is one whose requeue a racing transition refused.
// retired reports that the lease was ended here, which fenced its epoch
// (requeued, or ended for a source it could not remove). Callers hold c.mu,
// which is released around the source removal.
func (c *Controller) drainRefused(ctx context.Context, a *execution, current model.Job, reason string) (retired bool, err error) {
	if current.State != model.Preparing || current.CancelRequested {
		return false, nil
	}
	outcome, err := c.returnToQueue(ctx, a, current, requeuedDraining, c.options.Now(), true)
	switch outcome {
	case returnRequeued:
		log.Printf("controller returned job refused by a draining worker to the queue: job=%s lane=%d reason=%q", current.ID, current.Lane, reason)
		return true, nil
	case returnEnded:
		return true, nil
	case returnBusy:
		return false, errRefusalPending
	}
	if errors.Is(err, store.ErrTransition) {
		log.Printf("controller drain refusal requeue refused, judging the completion: job=%s: %v", current.ID, err)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// The lease ended otherwise while its source was removed.
	return false, store.ErrLease
}

// stalledJob records a completion the worker reports as its own end of the
// job because the run command's output stopped for its stall limit
// (protocol.Completion.Stalled) as the controller's cancellation stalled
// before complete judges it: the job ends cancelled by the service, and pull
// mode reruns its head once (store's serviceEnded; #201). A job already
// terminal, or already cancelled for another cause, keeps its record.
func (c *Controller) stalledJob(ctx context.Context, job model.Job, completion protocol.Completion) error {
	if !completion.Stalled || job.State.Terminal() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if a := c.execution(job.ID); a == nil || !a.offered {
		return store.ErrLease
	}
	current, err := c.options.Store.Get(ctx, job.ID)
	if err != nil {
		return err
	}
	_, err = c.cancelJob(ctx, current, "worker ended the job: stalled", model.CancelReason{Source: model.CancelStalled, Detail: completion.Result.Reason}, c.options.Now())
	return err
}

func (c *Controller) complete(ctx context.Context, job model.Job, result worker.Result, seal buildseal.Envelope) error {
	ctx, cancel := context.WithTimeout(ctx, c.options.DeliveryTimeout)
	defer cancel()
	if result.State != model.Succeeded && result.State != model.Failed && result.State != model.Cancelled && result.State != model.TimedOut || len(result.Reason) > 4096 {
		return store.ErrInvalid
	}
	digest, err := completionDigest(result)
	if err != nil {
		return err
	}
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	job, err = c.options.Store.Get(ctx, job.ID)
	if err != nil {
		return err
	}
	if job.State.Terminal() {
		if len(job.Result) == 0 {
			return store.ErrLease
		}
		var prior Completion
		if err := json.Unmarshal(job.Result, &prior); err != nil {
			return err
		}
		if prior.InputDigest != digest {
			return store.ErrConflict
		}
		return nil
	}
	c.mu.Lock()
	a := c.execution(job.ID)
	if a == nil || !a.offered {
		c.mu.Unlock()
		return store.ErrLease
	}
	if a.finalizingSince.IsZero() {
		a.finalizingSince = c.options.Now()
	}
	// A held completion's deadline is judged when it was held.
	heldAt := a.heldAt
	source := a.source.Source
	c.mu.Unlock()
	normalized, err := c.verifyResult(ctx, job, result, source)
	if err != nil {
		return err
	}
	// Source cleanup is controller-owned uncertainty. Keep the worker's result
	// and cleanup proof intact; independent durable debt closes admission until
	// a protected removal retry succeeds.
	_ = c.removeSource(job.ID)
	for range 2 {
		c.mu.Lock()
		current, err := c.options.Store.Get(ctx, job.ID)
		if err == nil && current.State.Terminal() {
			err = store.ErrLease
		}
		if err == nil && current.State != model.Finalizing {
			err = c.options.Store.Transition(ctx, job.ID, job.LeaseToken, current.State, model.Finalizing, "", c.options.Now())
		}
		c.mu.Unlock()
		if err != nil {
			return err
		}
		judged := c.options.Now()
		if !heldAt.IsZero() {
			judged = heldAt
		}
		normalizeCancellation(&normalized, current, judged)
		completion := Completion{InputDigest: digest, Result: normalized}
		if len(seal.Seal) > 0 {
			completion.Seal = &seal
		}
		if c.options.Seal != nil {
			receipt, err := c.receipt(ctx, current, &normalized, Sealing{Worker: result, Seal: seal})
			if err != nil {
				return err
			}
			if len(receipt) > 0 && !json.Valid(receipt) {
				return errors.New("seal returned invalid receipt JSON")
			}
			completion.Result, completion.Receipt = normalized, receipt
		}
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(completion); err != nil {
			return err
		}
		c.mu.Lock()
		err = c.options.Store.Finish(ctx, job.ID, job.LeaseToken, normalized.State, encoded.Bytes(), normalized.CleanupOK, normalized.Reason, c.options.Now())
		if err == nil {
			delete(c.productsRefused, job.ID)
		}
		if a := c.execution(job.ID); err == nil && a != nil {
			a.cancel()
			c.release(a)
			c.workerIdle = false
			// Failed cleanup fences new claims for this epoch; sibling lanes
			// finish on their own leases while the worker drains.
			if !normalized.CleanupOK {
				c.epoch = ""
			}
		}
		c.mu.Unlock()
		if err == nil {
			return nil
		}
		// The API may persist cancellation while the seal hook is running. Store's
		// transactional predicate wins; never retain a success receipt in that race.
		if !errors.Is(err, store.ErrTransition) || normalized.State != model.Succeeded {
			return err
		}
	}
	return store.ErrTransition
}

// receipt obtains the receipt of result. A definitive refusal of a success
// receipt downgrades result to Failed with the refusal as its reason and
// asks for that receipt instead; a definitive refusal of an unsuccessful
// receipt (the worker's seal itself refused) completes without one. Either
// way the job reaches a terminal state with the worker's cleanup proof, so a
// refusal neither loses the cleanup nor holds the queue until a deadline.
// Other errors are retryable and leave the job finalizing.
func (c *Controller) receipt(ctx context.Context, job model.Job, result *worker.Result, sealing Sealing) (json.RawMessage, error) {
	raw, err := c.options.Seal(ctx, job, *result, sealing)
	if errors.Is(err, ErrReceiptRefused) && result.State == model.Succeeded {
		result.State, result.Reason = model.Failed, err.Error()
		if len(result.Reason) > 4096 {
			result.Reason = result.Reason[:4096]
		}
		raw, err = c.options.Seal(ctx, job, *result, sealing)
	}
	if errors.Is(err, ErrReceiptRefused) {
		return nil, nil
	}
	return raw, err
}

func normalizeCancellation(result *worker.Result, job model.Job, now time.Time) {
	if !result.CleanupOK {
		result.State = model.Failed
		if result.Reason == "" {
			result.Reason = "worker cleanup was not confirmed"
		}
		return
	}
	if job.Deadline != nil && !now.Before(*job.Deadline) {
		result.State = model.TimedOut
		result.Reason = "job deadline exceeded"
	} else if job.CancelRequested && job.CancelReason != nil && job.CancelReason.Source == model.CancelStalled {
		// The worker's own reason names the stall limit.
		result.State = model.Cancelled
		if !strings.HasPrefix(result.Reason, "stalled") {
			result.Reason = "stalled"
		}
		result.Reason, _, _ = strings.Cut(result.Reason, "\n")
	} else if job.CancelRequested {
		result.State = model.Cancelled
		result.Reason = "cancellation requested"
	}
}

func (c *Controller) verifyResult(ctx context.Context, job model.Job, result worker.Result, source worker.Source) (worker.Result, error) {
	suppliedSuccess := result.State == model.Succeeded
	result.Summary = nil
	var problems []string
	reject := func(reason string) { problems = append(problems, reason) }
	if result.Source != source || result.Source.Commit != job.Request.SHA {
		reject("source descriptor mismatch")
	}
	if result.StartedAt.IsZero() || result.FinishedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) || result.StartedAt.Before(*job.StartedAt) || result.FinishedAt.After(c.options.Now().Add(time.Minute)) {
		reject("invalid execution timestamps")
	}
	// The worker's lane record names the lane this controller assigned.
	if l := result.Concurrency; l != nil && job.Lane > 0 && l.Lane != job.Lane {
		reject("lane record mismatch")
	}
	manifest, err := c.uploaded(job.ID)
	if err != nil {
		return result, err
	}
	uploadedByName := make(map[string]evidence.Artifact, len(manifest))
	for _, artifact := range manifest {
		uploadedByName[artifact.Name] = artifact
	}
	if len(result.Artifacts) > maxArtifacts {
		return result, evidence.ErrArtifactLimit
	}
	names := make(map[string]evidence.Artifact, len(result.Artifacts))
	var total int64
	verified := make([]evidence.Artifact, 0, len(result.Artifacts))
	for _, artifact := range result.Artifacts {
		if !validArtifact(artifact) {
			reject("invalid artifact manifest")
			continue
		}
		if _, exists := names[artifact.Name]; exists {
			reject("duplicate artifact name")
			continue
		}
		total += artifact.SizeBytes
		if total > maxArtifactBytes {
			return result, evidence.ErrArtifactLimit
		}
		if uploaded, found := uploadedByName[artifact.Name]; !found || uploaded != artifact {
			if productsArtifact(job, artifact) && c.productsRefused[job.ID] {
				reject("test products: the products pool has no room: pinned test products of current heads and unfinished shards fill it")
			} else {
				reject("artifact not uploaded")
			}
			continue
		}
		file, err := c.openJobArtifact(job, artifact)
		if err != nil {
			reject("artifact bytes unavailable")
			continue
		}
		err = verifyBytes(contextReader{ctx: ctx, reader: file}, artifact.SizeBytes, artifact.SHA256)
		file.Close()
		if err != nil {
			reject("artifact bytes do not match manifest")
			continue
		}
		names[artifact.Name] = artifact
		verified = append(verified, artifactExpiry(artifact, c.options.Now()))
	}
	result.Artifacts = verified
	truncated, err := c.options.Store.LogsTruncated(ctx, job.ID)
	if err != nil {
		return result, err
	}
	result.LogsTruncated = result.LogsTruncated || truncated
	if result.LogsTruncated {
		reject("log evidence truncated")
	}
	// A template job's executed recipe and required tests (a test template's
	// shard selectors) are the derivation from its reported repository
	// configuration; a profile job's are its snapshot.
	profile, recipeErr := profiles.Effective(job.Profile, result.Observation.Recipe)
	if recipeErr != nil {
		profile = job.Profile
	}
	if job.Request.Kind.Tests() {
		tests, hasTests := names["evidence/tests.json"]
		archive, hasArchive := names["results.xcresult.tar.gz"]
		if !hasTests || !hasArchive {
			reject("test evidence missing")
		} else if tests.SizeBytes > 32<<20 {
			reject("test JSON exceeds parser limit")
		} else {
			file, err := c.openArtifact(job.ID, tests.ID)
			if err != nil {
				return result, err
			}
			raw, readErr := io.ReadAll(io.LimitReader(file, (32<<20)+1))
			file.Close()
			summary, parseErr := evidence.ParseTests(raw, profile.RequiredTests, job.Profile.RetryIterations())
			summary.XCResultSHA256 = archive.SHA256
			result.Summary = &summary
			if readErr != nil || parseErr != nil || summary.ParseStatus != "parsed" || summary.Tests == 0 || summary.Failed != 0 {
				reject("test evidence did not prove success")
			}
		}
	}
	if suppliedSuccess {
		if result.ExitCode == nil || *result.ExitCode != 0 || result.Signal != "" || !result.CleanupOK {
			reject("exit status or cleanup did not prove success")
		}
		if err := errors.Join(verifyObservation(job, result.Observation), recipeErr); err != nil {
			reject(err.Error())
		}
		for _, name := range []string{"evidence/stdout.log", "evidence/stderr.log"} {
			if _, ok := names[name]; !ok {
				reject("raw log evidence missing")
			}
		}
		for _, rule := range profile.Artifacts {
			if !rule.Required {
				continue
			}
			found := false
			for name := range names {
				match, _ := path.Match(rule.Path, name)
				directoryMatch, _ := path.Match(rule.Path, strings.TrimSuffix(name, ".tar.gz"))
				if match || directoryMatch {
					found = true
					break
				}
			}
			if !found {
				reject("required profile artifact missing")
			}
		}
	}
	if !result.CleanupOK {
		result.State = model.Failed
		result.Reason = "worker cleanup was not confirmed"
	} else if suppliedSuccess && len(problems) > 0 {
		result.State = model.Failed
		result.Reason = strings.Join(problems, "; ")
		if len(result.Reason) > 4096 {
			result.Reason = result.Reason[:4096]
		}
	}
	return result, nil
}

func verifyObservation(job model.Job, o worker.Observation) error {
	if o.Xcode != job.Profile.Xcode || o.Architecture != "arm64" || o.SDKVersion == "" || o.SDKBuild == "" || o.SwiftVersion == "" || o.OSVersion == "" || o.OSBuild == "" {
		return errors.New("toolchain observation does not match approved pins")
	}
	if simulator := job.Profile.Simulator; simulator != nil {
		identifier := simulator.Runtime[strings.LastIndex(simulator.Runtime, ".")+1:]
		_, version, _ := strings.Cut(identifier, "-")
		if o.RuntimeBuild != simulator.RuntimeBuild || o.RuntimeVersion != strings.ReplaceAll(version, "-", ".") || o.DeviceUDID == "" {
			return errors.New("simulator observation does not match approved pins")
		}
	}
	if len(o.GeneratedDigests) != len(job.Profile.GeneratedFiles) {
		return errors.New("generated file digest manifest mismatch")
	}
	for _, generated := range job.Profile.GeneratedFiles {
		digest := sha256.Sum256([]byte(generated.Content))
		if o.GeneratedDigests[generated.Path] != hex.EncodeToString(digest[:]) {
			return errors.New("generated file digest mismatch")
		}
	}
	// A consumer ran only after the worker verified and imported the
	// request's test products; no other job imports any.
	if ref := job.Request.Products; ref == nil && o.ImportedProducts != "" || ref != nil && o.ImportedProducts != ref.SHA256 {
		return errors.New("imported test products do not match the request")
	}
	return nil
}
