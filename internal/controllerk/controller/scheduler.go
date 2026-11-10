package controller

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

func (c *Controller) register(ctx context.Context, registration protocol.Registration) error {
	if !safeID(registration.Epoch) || !registration.Quiescent || registration.Lanes < 0 || registration.Lanes > model.MaxConcurrentJobs {
		return store.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrNotReady
	}
	if err := c.fenceUndelivered(ctx, registration.Epoch); err != nil {
		return err
	}
	if err := c.options.Store.RegisterWorker(ctx, registration.Epoch); err != nil {
		return err
	}
	c.epoch = registration.Epoch
	c.workerLanes = max(registration.Lanes, 1)
	c.workerIdle = len(c.active) == 0
	c.lastSeen = c.options.Now()
	return nil
}

// fenceUndelivered ends, before a new worker epoch registers, every lease of
// an older epoch never delivered. One worker epoch serves every lane and
// cannot change under a live job, but a new epoch is a worker that recovered
// quiescence holding no lease: the older epoch's worker is gone (restarted,
// or drained). Its leases never delivered would otherwise hold their lanes,
// and refuse this registration, until their deadline. A delivered lease is
// work the worker may still clean up: it keeps its heartbeat and cleanup
// windows, and the registration is refused (ErrTransition) until they end it.
// A lease still preparing is cancelled and refuses with ErrNotReady until
// prepare ends it. Callers hold c.mu, which is released around source removal.
func (c *Controller) fenceUndelivered(ctx context.Context, epoch string) error {
	var stale []*execution
	for _, a := range c.active {
		if a.job.WorkerEpoch == epoch {
			continue
		}
		if a.offered {
			return store.ErrTransition
		}
		stale = append(stale, a)
	}
	if len(stale) == 0 {
		return nil
	}
	// A replaced epoch never registers again; it must not end the leases
	// of the epoch that replaced it.
	if fenced, err := c.options.Store.EpochFenced(ctx, epoch); err != nil {
		return err
	} else if fenced {
		return store.ErrLease
	}
	// The fence is durable before c.mu is released: the older epoch can
	// neither register again (restoring c.epoch) nor be offered these
	// leases while their sources are removed, and prepare ends its
	// preparations as fenced.
	for _, a := range stale {
		if err := c.options.Store.FenceEpoch(ctx, a.job.WorkerEpoch); err != nil {
			return err
		}
	}
	c.epoch = ""
	preparing := false
	for _, a := range stale {
		a.fencing = true
		a.cancel()
		if !a.ready {
			preparing = true
			continue
		}
		job, err := c.options.Store.Get(ctx, a.job.ID)
		if err != nil {
			return err
		}
		c.endUndelivered(ctx, a, job, c.options.Now())
		if c.closed {
			return ErrNotReady
		}
	}
	if preparing {
		return ErrNotReady
	}
	// c.mu was released: refuse unless every older lease has ended.
	for _, a := range c.active {
		if a.job.WorkerEpoch != epoch {
			return store.ErrTransition
		}
	}
	return nil
}

// endUndelivered ends a's prepared lease never delivered: it removes the
// source, then records why the lease was not delivered. a is never offered
// from now on. Callers hold c.mu, which is released around the removal.
func (c *Controller) endUndelivered(ctx context.Context, a *execution, job model.Job, now time.Time) {
	a.fencing = true
	c.mu.Unlock()
	cleanupErr := c.removeSource(job.ID)
	c.mu.Lock()
	// A lease delivered before the fence is live work: checkExecution's
	// heartbeat and cleanup windows end it, not a preparation failure.
	if !c.holds(a) || a.offered {
		return
	}
	state, reason := model.Cancelled, "cancelled before lease delivery"
	if job.Deadline != nil && !now.Before(*job.Deadline) {
		state = model.TimedOut
	} else if !job.CancelRequested {
		state, reason = model.Interrupted, fencedBeforeDelivery
	}
	if c.options.Store.FailPreparation(ctx, job.ID, job.LeaseToken, state, cleanupErr == nil, reason, now) == nil {
		c.release(a)
		if cleanupErr != nil {
			c.epoch = ""
		}
	}
}

// next hands out at most one lease per call. running lists the jobs the worker
// executes in any phase: an offered lease still preparing is offered again only
// when the worker does not run it, meaning the earlier response was lost. A
// worker before lanes sends none and runs one job, so its preparing lease is
// always offered again. Otherwise a job is claimed when a lane is free.
func (c *Controller) next(ctx context.Context, epoch string, running []string) (*protocol.Lease, error) {
	gate, err := c.options.Gate(ctx)
	if err != nil {
		return nil, ErrNotReady
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrNotReady
	}
	if epoch == "" || c.epoch != epoch {
		return nil, store.ErrLease
	}
	c.lastSeen = c.options.Now()
	if len(c.active) == 0 {
		c.workerIdle = true
	}
	if gate.CancelActive && len(c.active) > 0 {
		if err := c.cancelForGate(ctx, gate, nil, c.options.Now()); err != nil {
			return nil, err
		}
	}
	service, err := c.options.Store.ServiceState(ctx)
	if err != nil {
		return nil, err
	}
	if service.Quarantined || service.Paused && len(c.active) == 0 {
		return nil, nil
	}
	var offer *execution
	var lease *protocol.Lease
	for _, a := range c.active {
		job, err := c.options.Store.Get(ctx, a.job.ID)
		if err != nil {
			return nil, err
		}
		if now := c.options.Now(); job.Deadline != nil && !now.Before(*job.Deadline) {
			if _, err := c.cancelJob(ctx, job, "job deadline exceeded", model.CancelReason{Source: model.CancelDeadline}, now); err != nil {
				return nil, err
			}
			continue
		}
		// A preparing lease may be retried when its HTTP response was lost. Running
		// and finalizing leases are never handed out a second time, nor is a
		// lease being fenced or claimed by another epoch.
		if offer != nil || !a.ready || a.fencing || job.WorkerEpoch != epoch || job.State != model.Preparing || job.CancelRequested || a.offered && slices.Contains(running, job.ID) {
			continue
		}
		offer, lease = a, &protocol.Lease{Job: job, Token: job.LeaseToken, Source: a.source.Source}
	}
	if offer != nil {
		if !offer.offered {
			offer.offered = true
			offer.heartbeat = c.options.Now()
		}
		return lease, nil
	}
	lanes := c.lanes()
	if !gate.Ready || gate.CancelActive || len(c.active) >= lanes {
		return nil, nil
	}
	// A ready gate reserves the disk of one job; each further lane needs its own.
	if len(c.active) > 0 && !health.AdmitsAnother(gate, len(c.active), lanes) {
		return nil, nil
	}
	job, err := c.options.Store.Claim(ctx, epoch, c.options.Now(), lanes)
	if errors.Is(err, store.ErrNoJob) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	duration := min(c.options.SourceTimeout, job.Deadline.Sub(c.options.Now()))
	prepCtx, cancel := context.WithTimeout(c.ctx, duration)
	a := &execution{job: job, cancel: cancel}
	c.active = append(c.active, a)
	c.prep.Add(1)
	go c.prepare(prepCtx, a)
	return nil, nil
}

func (c *Controller) prepare(ctx context.Context, a *execution) {
	defer c.prep.Done()
	if c.options.BeforeDispatch != nil {
		if err := c.options.BeforeDispatch(ctx, a.job); err != nil {
			state, reason := model.Cancelled, "dispatch admission revalidation failed"
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				state, reason = model.TimedOut, "dispatch admission revalidation deadline exceeded"
			}
			a.cancel()
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.holds(a) {
				if err := c.options.Store.FailPreparation(context.Background(), a.job.ID, a.job.LeaseToken, state, true, reason, c.options.Now()); err == nil {
					c.release(a)
				}
			}
			return
		}
	}
	// Authorize before recording source debt, but persist the intent before
	// Prepare can create anything. Recovery therefore still covers crashes.
	if err := c.options.Store.RequireSourceCleanup(ctx, a.job.ID); err != nil {
		a.cancel()
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.holds(a) {
			if failErr := c.options.Store.FailPreparation(context.Background(), a.job.ID, a.job.LeaseToken, model.Failed, true, "source cleanup intent could not be persisted", c.options.Now()); failErr == nil {
				c.release(a)
			}
		}
		return
	}
	descriptor, err := c.options.Source.Prepare(ctx, a.job)
	if err == nil {
		err = validateSource(ctx, descriptor, a.job.Request.SHA)
	}
	if err == nil {
		err = ctx.Err()
	}
	c.mu.Lock()
	job, getErr := c.options.Store.Get(context.Background(), a.job.ID)
	err = errors.Join(err, getErr)
	if err == nil && !job.CancelRequested && !c.closed {
		a.source = descriptor
		a.ready = true
		c.mu.Unlock()
		return
	}
	a.cancel()
	c.mu.Unlock()
	cleanupErr := c.removeSource(a.job.ID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.holds(a) {
		return
	}
	state, reason := model.Failed, "source preparation failed"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || job.Deadline != nil && !c.options.Now().Before(*job.Deadline) {
		state, reason = model.TimedOut, "source preparation deadline exceeded"
	} else if job.CancelRequested || c.closed {
		state, reason = model.Cancelled, "source preparation cancelled"
	} else if c.epoch != a.job.WorkerEpoch {
		state, reason = model.Interrupted, fencedBeforeDelivery
	}
	if failErr := c.options.Store.FailPreparation(context.Background(), a.job.ID, a.job.LeaseToken, state, cleanupErr == nil, reason, c.options.Now()); failErr == nil {
		c.release(a)
		if cleanupErr != nil {
			c.epoch = ""
		}
	}
}

func (c *Controller) monitor() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	sweep := time.NewTicker(time.Minute)
	defer sweep.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkActive(c.ctx)
		case <-sweep.C:
			_ = c.sweep(c.ctx)
		}
	}
}

// fencedBeforeDelivery ends a lease never delivered because its worker epoch
// was fenced (a sibling lane's cleanup failed, its heartbeat was lost, or the
// worker registered a new epoch): the draining or restarted worker can no
// longer ask for it, and it would hold its lane and keep the worker's next
// epoch from registering until its deadline.
const fencedBeforeDelivery = "worker epoch fenced before lease delivery"

func (c *Controller) checkActive(ctx context.Context) {
	gate, gateErr := c.options.Gate(ctx)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.noteGate(gate, gateErr)
	executions := slices.Clone(c.active)
	now := c.options.Now()
	// A job past its deadline records the deadline as its cause before any
	// readiness cancellation can.
	for _, a := range executions {
		job, err := c.options.Store.Get(ctx, a.job.ID)
		if err != nil {
			c.mu.Unlock()
			return
		}
		if job.Deadline != nil && !now.Before(*job.Deadline) {
			if _, err := c.cancelJob(ctx, job, "job deadline exceeded", model.CancelReason{Source: model.CancelDeadline}, now); err != nil {
				c.mu.Unlock()
				return
			}
		}
	}
	if len(executions) > 0 && (gate.CancelActive || gateErr != nil) {
		if c.cancelForGate(ctx, gate, gateErr, now) != nil {
			c.mu.Unlock()
			return
		}
	}
	c.mu.Unlock()
	for _, a := range executions {
		c.checkExecution(ctx, a, now)
	}
}

// checkExecution enforces one execution's cancellation, delivery and
// heartbeat windows; a lost heartbeat fails only that job and fences the
// epoch, while sibling lanes continue on their own leases.
func (c *Controller) checkExecution(ctx context.Context, a *execution, now time.Time) {
	c.mu.Lock()
	if c.closed || !c.holds(a) {
		c.mu.Unlock()
		return
	}
	job, err := c.options.Store.Get(ctx, a.job.ID)
	if err != nil {
		c.mu.Unlock()
		return
	}
	deadline := job.Deadline != nil && !now.Before(*job.Deadline)
	if job.CancelRequested && a.cancellingSince.IsZero() {
		a.cancellingSince = now
		// A late monitor tick must not restart the worker's cleanup budget.
		if deadline && job.Deadline.Before(a.cancellingSince) {
			a.cancellingSince = *job.Deadline
		}
	}
	if !a.offered {
		fenced := c.epoch != job.WorkerEpoch
		if job.CancelRequested || fenced {
			a.cancel()
		}
		if !a.ready || !job.CancelRequested && !fenced {
			c.mu.Unlock()
			return
		}
		c.endUndelivered(ctx, a, job, now)
		c.mu.Unlock()
		return
	}
	// A cancelled execution stops its execution-context heartbeat while the
	// worker still owns bounded cleanup and evidence-delivery work. Finalizing
	// is likewise live work, not a lost worker. Neither heartbeats nor repeated
	// stage requests extend these fixed windows indefinitely.
	finishing := a.cancellingSince
	if !a.finalizingSince.IsZero() && (finishing.IsZero() || a.finalizingSince.Before(finishing)) {
		finishing = a.finalizingSince
	}
	if !finishing.IsZero() {
		window := c.options.CleanupTimeout + c.options.DeliveryTimeout + c.options.HeartbeatTimeout
		if job.Request.Kind == model.IOSArchive {
			// The worker builds, seals and exports the archive evidence in
			// its own window after the job has stopped.
			window += worker.ArchiveEvidenceTimeout
		}
		if now.Sub(finishing) <= window {
			c.mu.Unlock()
			return
		}
	} else if now.Sub(a.heartbeat) <= c.options.HeartbeatTimeout {
		c.mu.Unlock()
		return
	}
	state, reason := model.Interrupted, "worker heartbeat lost; quiescence required"
	if deadline {
		state, reason = model.TimedOut, "deadline cleanup not confirmed; quiescence required"
	}
	if c.options.Store.Fail(ctx, job.ID, job.LeaseToken, state, false, reason, now) != nil {
		c.mu.Unlock()
		return
	}
	c.release(a)
	c.epoch = ""
	a.cancel()
	c.mu.Unlock()
	_ = c.removeSource(job.ID)
}

// sweep removes only ID-addressed private exports, then prunes their metadata.
// Artifact expiry remains enforced by getters even between sweep intervals.
func (c *Controller) sweep(ctx context.Context) error {
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	c.mu.Lock()
	c.maintaining = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.maintaining = false; c.mu.Unlock() }()
	service, err := c.options.Store.ServiceState(ctx)
	if err != nil {
		return err
	}
	gate, err := c.options.Gate(ctx)
	if err != nil {
		return err
	}
	if service.Paused || !cleanupAllowed(gate) {
		return nil
	}
	cleanupErr := c.retrySourceCleanup(ctx)
	c.poolKnown = false
	dir, err := c.root.Open("artifacts")
	if err != nil {
		return err
	}
	defer dir.Close()
	now := c.options.Now()
	for {
		names, readErr := dir.Readdirnames(128)
		for _, id := range names {
			if !safeID(id) {
				continue
			}
			job, err := c.options.Store.Get(ctx, id)
			if errors.Is(err, store.ErrNotFound) || err == nil && job.State.Terminal() && job.FinishedAt != nil && !now.Before(job.FinishedAt.Add(7*24*time.Hour)) {
				if err := c.root.RemoveAll("artifacts/" + id); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if err := c.trimPool(ctx, 0, maxArtifactPoolBytes); err != nil {
		return err
	}
	if err := c.options.Store.Prune(ctx, now); err != nil {
		return errors.Join(cleanupErr, err)
	}
	if c.options.PruneReceipts != nil {
		return errors.Join(cleanupErr, c.options.PruneReceipts(ctx))
	}
	return cleanupErr
}

func safeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func privateRegular(file *os.File) (os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("evidence is not a private regular file")
	}
	return info, nil
}
