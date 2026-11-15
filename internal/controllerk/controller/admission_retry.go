package controller

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// maxAdmissionRetries bounds how often a job the worker refused
// inconclusively returns to the queue (#154). The refusal after the last
// retry cancels it as worker_admission, naming the retries in its detail.
const maxAdmissionRetries = 3

// admissionRetryBackoff holds a job back from claims after its first
// admission retry; each further retry doubles it (2, 4 and 8 minutes), so a
// host loaded enough to cut an inspection short gets time to settle, and the
// same job is not offered again at once.
const admissionRetryBackoff = 2 * time.Minute

// maxAdmissionRetryCause bounds the refusal reason quoted in a retry's
// job reason.
const maxAdmissionRetryCause = 512

// admissionRetry is a job returned to the queue after inconclusive admission
// refusals: count retries so far, and the claim it is held back from until
// next. It lives in the controller's memory only (the store has no field for
// it): a restarted controller forgets both, so the job is claimable at once
// and gets maxAdmissionRetries retries again.
type admissionRetry struct {
	count int
	next  time.Time
}

// inconclusiveRefusal reports whether the worker refused a job before
// anything of it ran because an admission inspection ran out of its own time
// on a loaded host (protocol.AdmissionACLCensusUnavailable): cleanup_ok, idle
// verdict not_required and no evidence. Such a refusal observed nothing about
// the job or the account, so the job can be offered again. Any other refusal
// is real and cancels the job.
func inconclusiveRefusal(refusal protocol.AdmissionRefusal, result worker.Result) bool {
	return refusal == protocol.AdmissionACLCensusUnavailable && result.State == model.Failed && result.CleanupOK &&
		result.Concurrency != nil && result.Concurrency.IdleVerdict == worker.IdleNotRequired && len(result.Artifacts) == 0
}

// admissionRetryReason is the job reason of a job returned to the queue for
// its retry-th admission retry after cause, held back until next.
func admissionRetryReason(retry int, cause string, next time.Time) string {
	cause = strings.ToValidUTF8(cause, "\uFFFD")
	if len(cause) > maxAdmissionRetryCause {
		// Cutting may split a rune; dropping its invalid tail keeps UTF-8.
		cause = strings.ToValidUTF8(cause[:maxAdmissionRetryCause], "")
	}
	return fmt.Sprintf("admission retry %d/%d after %s, next at %s", retry, maxAdmissionRetries, cause, next.UTC().Format(time.RFC3339))
}

// requeueRefused returns a's job, whose lease the worker refused
// inconclusively before anything of it ran, to the queue for its retry-th
// admission retry: its source is removed and the store requeues it as it
// does an undelivered lease (requeueUndelivered), and claims pass it over
// until its backoff ends (heldAdmissions). It reports false when the job
// could not return to the queue (its source could not be removed, the lease
// ended meanwhile, or its cancellation was requested); the caller then
// cancels it as a refusal. Callers hold c.evidenceMu and c.mu; c.mu is
// released around the source removal.
func (c *Controller) requeueRefused(ctx context.Context, a *execution, job model.Job, retry int, cause string) bool {
	// Never offered again, while c.mu is released, as a lost response.
	a.fencing = true
	c.mu.Unlock()
	cleanupErr := c.removeSource(job.ID)
	c.mu.Lock()
	if !c.holds(a) {
		return false
	}
	if cleanupErr != nil {
		log.Printf("controller admission retry source removal failed: job=%s: %v", job.ID, cleanupErr)
		return false
	}
	now := c.options.Now()
	next := now.Add(admissionRetryBackoff << (retry - 1))
	reason := admissionRetryReason(retry, cause, next)
	if err := c.options.Store.Requeue(ctx, job.ID, job.LeaseToken, reason, now); err != nil {
		log.Printf("controller admission retry requeue failed: job=%s: %v", job.ID, err)
		return false
	}
	c.admissionRetries[job.ID] = admissionRetry{count: retry, next: next}
	a.cancel()
	c.release(a)
	c.workerIdle = false
	log.Printf("controller returned refused admission to the queue: job=%s lane=%d retry=%d/%d next=%s cause=%q", job.ID, job.Lane, retry, maxAdmissionRetries, next.UTC().Format(time.RFC3339), cause)
	return true
}

// heldAdmissions lists the jobs whose admission retry backoff has not ended
// at now, which claims pass over, and forgets the retries of jobs that ended.
// Callers hold c.mu.
func (c *Controller) heldAdmissions(ctx context.Context, now time.Time) ([]string, error) {
	var held []string
	for id, retry := range c.admissionRetries {
		if now.Before(retry.next) {
			held = append(held, id)
			continue
		}
		job, err := c.options.Store.Get(ctx, id)
		if errors.Is(err, store.ErrNotFound) || err == nil && job.State.Terminal() {
			delete(c.admissionRetries, id)
		} else if err != nil {
			return nil, err
		}
	}
	return held, nil
}
