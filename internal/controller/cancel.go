package controller

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

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
func readinessCause(gate GateState, err error) model.CancelReason {
	if err != nil {
		return model.CancelReason{Source: model.CancelGateError, Detail: err.Error()}
	}
	return model.CancelReason{Source: model.CancelHostReadiness, Blockers: gate.Blockers, Detail: fmt.Sprintf("free_bytes=%d used_bytes=%d", gate.FreeBytes, gate.UsedBytes)}
}

// gateOutcome is the part of a readiness evaluation whose changes are logged.
type gateOutcome struct {
	seen, ready, cancelActive bool
	blockers                  []string
	err                       string
}

// noteGate logs the first readiness evaluation and every change of its
// outcome, with the active job, so a cancellation can be placed against the
// blockers that preceded it. Callers hold c.mu.
func (c *Controller) noteGate(gate GateState, err error) {
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
	if c.active != nil {
		active = c.active.job.ID
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
