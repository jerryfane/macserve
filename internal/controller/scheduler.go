package controller

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/store"
)

func (c *Controller) register(ctx context.Context, registration protocol.Registration) error {
	if !safeID(registration.Epoch) || !registration.Quiescent {
		return store.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrNotReady
	}
	if c.active != nil && c.active.job.WorkerEpoch != registration.Epoch {
		return store.ErrTransition
	}
	if err := c.options.Store.RegisterWorker(ctx, registration.Epoch); err != nil {
		return err
	}
	c.epoch = registration.Epoch
	c.workerIdle = c.active == nil
	c.lastSeen = c.options.Now()
	return nil
}

func (c *Controller) next(ctx context.Context, epoch string) (*protocol.Lease, error) {
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
	if c.active == nil {
		c.workerIdle = true
	}
	if gate.CancelActive && c.active != nil {
		if _, err := c.options.Store.Cancel(ctx, c.active.job.ID, "host readiness requires cancellation", c.options.Now()); err != nil {
			return nil, err
		}
	}
	service, err := c.options.Store.ServiceState(ctx)
	if err != nil {
		return nil, err
	}
	if service.Quarantined || service.Paused && c.active == nil {
		return nil, nil
	}
	if a := c.active; a != nil {
		job, err := c.options.Store.Get(ctx, a.job.ID)
		if err != nil {
			return nil, err
		}
		if job.Deadline != nil && !c.options.Now().Before(*job.Deadline) {
			_, err := c.options.Store.Cancel(ctx, job.ID, "job deadline exceeded", c.options.Now())
			return nil, err
		}
		if !a.ready || job.State != model.Preparing || job.CancelRequested {
			return nil, nil
		}
		// A preparing lease may be retried when its HTTP response was lost. Running
		// and finalizing leases are never handed out a second time.
		if !a.offered {
			a.offered = true
			a.heartbeat = c.options.Now()
		}
		return &protocol.Lease{Job: job, Token: job.LeaseToken, Source: a.source.Source}, nil
	}
	if !gate.Ready || gate.CancelActive {
		return nil, nil
	}
	job, err := c.options.Store.Claim(ctx, epoch, c.options.Now())
	if errors.Is(err, store.ErrNoJob) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := c.options.Store.RequireSourceCleanup(ctx, job.ID); err != nil {
		failErr := c.options.Store.FailPreparation(context.Background(), job.ID, job.LeaseToken, model.Failed, true, "source cleanup intent could not be persisted", c.options.Now())
		return nil, errors.Join(err, failErr)
	}
	duration := min(c.options.SourceTimeout, job.Deadline.Sub(c.options.Now()))
	prepCtx, cancel := context.WithTimeout(c.ctx, duration)
	a := &execution{job: job, cancel: cancel}
	c.active = a
	c.prep.Add(1)
	go c.prepare(prepCtx, a)
	return nil, nil
}

func (c *Controller) prepare(ctx context.Context, a *execution) {
	defer c.prep.Done()
	if c.options.BeforeDispatch != nil {
		if err := c.options.BeforeDispatch(ctx, a.job); err != nil {
			a.cancel()
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.active == a {
				if err := c.options.Store.Fail(context.Background(), a.job.ID, a.job.LeaseToken, model.Cancelled, true, "dispatch admission revalidation failed", c.options.Now()); err == nil {
					c.active = nil
				}
			}
			return
		}
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
	if c.active != a {
		return
	}
	state, reason := model.Failed, "source preparation failed"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || job.Deadline != nil && !c.options.Now().Before(*job.Deadline) {
		state, reason = model.TimedOut, "source preparation deadline exceeded"
	} else if job.CancelRequested || c.closed {
		state, reason = model.Cancelled, "source preparation cancelled"
	}
	if failErr := c.options.Store.FailPreparation(context.Background(), a.job.ID, a.job.LeaseToken, state, cleanupErr == nil, reason, c.options.Now()); failErr == nil {
		c.active = nil
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

func (c *Controller) checkActive(ctx context.Context) {
	gate, gateErr := c.options.Gate(ctx)
	c.mu.Lock()
	if c.closed || c.active == nil {
		c.mu.Unlock()
		return
	}
	a := c.active
	job, err := c.options.Store.Get(ctx, a.job.ID)
	if err != nil {
		c.mu.Unlock()
		return
	}
	now := c.options.Now()
	deadline := job.Deadline != nil && !now.Before(*job.Deadline)
	if deadline || gate.CancelActive || gateErr != nil {
		reason := "host readiness requires cancellation"
		if deadline {
			reason = "job deadline exceeded"
		}
		job, err = c.options.Store.Cancel(ctx, job.ID, reason, now)
		if err != nil {
			c.mu.Unlock()
			return
		}
	}
	if job.CancelRequested && a.cancellingSince.IsZero() {
		a.cancellingSince = now
		// A late monitor tick must not restart the worker's cleanup budget.
		if deadline && job.Deadline.Before(a.cancellingSince) {
			a.cancellingSince = *job.Deadline
		}
	}
	if !a.offered {
		if job.CancelRequested {
			a.cancel()
		}
		if !a.ready || !job.CancelRequested {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		cleanupErr := c.removeSource(job.ID)
		c.mu.Lock()
		if c.active == a {
			state := model.Cancelled
			if deadline {
				state = model.TimedOut
			}
			if c.options.Store.FailPreparation(ctx, job.ID, job.LeaseToken, state, cleanupErr == nil, "cancelled before lease delivery", now) == nil {
				c.active = nil
				if cleanupErr != nil {
					c.epoch = ""
				}
			}
		}
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
		if now.Sub(finishing) <= c.options.CleanupTimeout+c.options.DeliveryTimeout+c.options.HeartbeatTimeout {
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
	c.active = nil
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
