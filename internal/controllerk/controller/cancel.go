package controller

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/model"
)

// cancelJob requests the controller's own cancellation of job, a fresh read,
// for cause. A new request is logged with the cause the store recorded, so the
// job record and the controller log name the same source and blockers. A job
// already cancelled or terminal is returned unchanged. Callers hold c.mu.
func (c *Controller) cancelJob(ctx context.Context, job model.Job, reason string, cause model.CancelReason, now time.Time) (model.Job, error) {
	if job.CancelRequested || job.State.Terminal() {
		return job, nil
	}
	cancelled, err := c.options.Store.Cancel(ctx, job.ID, reason, cause, now)
	if err != nil {
		log.Printf("controller job cancellation failed: job=%s source=%s blockers=%s: %v", job.ID, cause.Source, blockerList(cause.Blockers), err)
		return cancelled, err
	}
	if recorded := cancelled.CancelReason; recorded != nil {
		log.Printf("controller job cancellation requested: job=%s source=%s blockers=%s detail=%q", job.ID, recorded.Source, blockerList(recorded.Blockers), recorded.Detail)
	}
	return cancelled, nil
}

// readinessCause is the cancel reason of a readiness gate that requires
// cancellation, or that could not be evaluated.
func readinessCause(gate health.GateState, err error) model.CancelReason {
	if err != nil {
		return model.CancelReason{Source: model.CancelGateError, Detail: err.Error()}
	}
	return model.CancelReason{Source: model.CancelHostReadiness, Blockers: gate.Blockers, Detail: fmt.Sprintf("free_bytes=%d used_bytes=%d", gate.FreeBytes, gate.UsedBytes)}
}

// capacityCancelInterval is how long a capacity-only cancellation spares the
// remaining jobs while the cancelled job releases its disk.
const capacityCancelInterval = 30 * time.Second

// cancelForGate cancels for a gate that requires cancellation, or that could
// not be evaluated (gateErr). Trust blockers and gate errors are host facts:
// every active job is cancelled with the readiness cause. A capacity-only gate
// cancels just the newest active job not already cancelled and, while another
// job remains active, at most one per capacityCancelInterval, so the gate is
// re-evaluated after the cancelled job frees its disk. With one active job this
// is the single-job cancellation. Callers hold c.mu.
func (c *Controller) cancelForGate(ctx context.Context, gate health.GateState, gateErr error, now time.Time) error {
	const reason = "host readiness requires cancellation"
	cause := readinessCause(gate, gateErr)
	if gateErr != nil || !gate.CapacityOnly {
		for _, a := range c.active {
			job, err := c.options.Store.Get(ctx, a.job.ID)
			if err != nil {
				return err
			}
			if _, err := c.cancelJob(ctx, job, reason, cause, now); err != nil {
				return err
			}
		}
		return nil
	}
	if len(c.active) > 1 && !c.capacityCancel.IsZero() && now.Sub(c.capacityCancel) < capacityCancelInterval {
		return nil
	}
	for i := len(c.active) - 1; i >= 0; i-- {
		job, err := c.options.Store.Get(ctx, c.active[i].job.ID)
		if err != nil {
			return err
		}
		if job.CancelRequested || job.State.Terminal() {
			continue
		}
		if _, err := c.cancelJob(ctx, job, reason, cause, now); err != nil {
			return err
		}
		c.capacityCancel = now
		return nil
	}
	return nil
}

// gateOutcome is the part of a readiness evaluation whose changes are logged.
type gateOutcome struct {
	seen, ready, cancelActive bool
	blockers                  []string
	err                       string
}

// noteGate logs the first readiness evaluation and every change of its
// outcome, with every active job, so a cancellation can be placed against the
// blockers that preceded it. Callers hold c.mu.
func (c *Controller) noteGate(gate health.GateState, err error) {
	var text string
	if err != nil {
		text = err.Error()
	}
	last := &c.gate
	if last.seen && last.ready == gate.Ready && last.cancelActive == gate.CancelActive && last.err == text && slices.Equal(last.blockers, gate.Blockers) {
		return
	}
	*last = gateOutcome{seen: true, ready: gate.Ready, cancelActive: gate.CancelActive, blockers: slices.Clone(gate.Blockers), err: text}
	active := "none"
	if len(c.active) > 0 {
		ids := make([]string, len(c.active))
		for i, a := range c.active {
			ids[i] = a.job.ID
		}
		active = strings.Join(ids, ",")
	}
	if err != nil {
		log.Printf("controller readiness: ready=false gate_error=%q active_job=%s", text, active)
		return
	}
	log.Printf("controller readiness: ready=%t cancel_active=%t blockers=%s active_job=%s", gate.Ready, gate.CancelActive, blockerList(gate.Blockers), active)
}

func blockerList(blockers []string) string {
	if len(blockers) == 0 {
		return "none"
	}
	return strings.Join(blockers, ",")
}
