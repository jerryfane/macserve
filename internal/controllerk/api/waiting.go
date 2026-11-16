package api

import (
	"context"
	"log"
	"slices"
	"strings"

	"github.com/jerryfane/macserve/internal/controllerk/controller"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/model"
)

// Why a queued job is not claimed yet, in the order the scheduler checks
// (controller next, then store.Claim). The first that applies is reported.
const (
	waitUnavailable      = "service unavailable"
	waitQuarantined      = "service quarantined"
	waitPaused           = "service paused"
	waitWorker           = "worker unavailable"
	waitIdleCheck        = "worker idle check"
	waitHost             = "host not ready"
	waitLanes            = "all lanes busy"
	waitExclusiveRunning = "an exclusive job is running"
	waitDisk             = "disk budget"
	waitConcurrentScript = "a concurrent script job is running"
	waitExclusiveNext    = "an exclusive job is next"
	waitStagger          = "simulator start stagger"
	waitMemory           = "memory budget"
	waitNext             = "next in line"
	waitBehind           = "jobs ahead are starting"
)

// queueWait is one read of the controller status and the queue, from which
// every queued job's wait is derived without claiming anything.
type queueWait struct {
	status    controller.Status
	statusErr error
	view      store.QueueView
}

// queueWait reads the status and the queue for job views. A failed queue
// read only leaves waiting out, since the view is advisory.
func (h *handler) queueWait(ctx context.Context) *queueWait {
	q := &queueWait{}
	q.status, q.statusErr = h.Status(ctx)
	var err error
	if q.view, err = h.Store.QueueView(ctx); err != nil {
		log.Printf("controller queue view failed: %v", err)
	}
	return q
}

// lanes is how many lanes claims fill: the controller's effective lanes, or
// its configured lanes from a status without them.
func (q *queueWait) lanes() int {
	if q.status.Lanes > 0 {
		return q.status.Lanes
	}
	return max(q.status.MaxConcurrentJobs, 1)
}

// blockedBy lists the service and host blockers of a queued job.
func blockedBy(status controller.Status, err error) []string {
	if err != nil {
		return []string{"service_unavailable"}
	}
	blocked := append([]string{}, status.Gate.Blockers...)
	if status.Service.Paused {
		blocked = append(blocked, "manual_pause")
	}
	if status.Service.Quarantined {
		blocked = append(blocked, "quarantined")
	}
	if !status.WorkerReady {
		blocked = append(blocked, "worker_unavailable")
	}
	return blocked
}

// waiting is a queued job's wait: the first scheduler condition holding it
// back, the busy and total lanes, its place among its repository's queued
// jobs in the fair order (1 is next), and how many queued jobs of any
// repository precede it. It names no other job. nil when job is no longer
// queued in q's read.
func (q *queueWait) waiting(job model.Job) map[string]any {
	index := slices.IndexFunc(q.view.Queued, func(queued model.Job) bool { return queued.ID == job.ID })
	if index < 0 {
		return nil
	}
	position := 1
	for _, ahead := range q.view.Queued[:index] {
		if strings.EqualFold(ahead.Request.Repo, job.Request.Repo) {
			position++
		}
	}
	return map[string]any{"reason": q.reason(index), "lanes_busy": len(q.view.Active), "lanes": q.lanes(), "position_in_repository": position, "queued_ahead_overall": index}
}

// reason mirrors the scheduler for the queued job at index of the fair order.
func (q *queueWait) reason(index int) string {
	status, active := q.status, q.view.Active
	switch {
	case q.statusErr != nil:
		return waitUnavailable
	case status.Service.Quarantined:
		return waitQuarantined
	case status.Service.Paused:
		return waitPaused
	case !status.WorkerReady:
		return waitWorker
	case status.CompletionHeld:
		return waitIdleCheck
	case !status.Gate.Ready || status.Gate.CancelActive:
		return waitHost
	case len(active) >= q.lanes():
		return waitLanes
	case slices.ContainsFunc(active, model.Job.Exclusive):
		return waitExclusiveRunning
	case len(active) > 0 && !health.AdmitsAnother(status.Gate, len(active), q.lanes()):
		return waitDisk
	}
	// While a concurrent script job runs, Claim passes over the others,
	// which do not hold the jobs behind them.
	concurrent := slices.ContainsFunc(active, func(a model.Job) bool { return a.Profile.Concurrent() })
	job := q.view.Queued[index]
	if concurrent && job.Profile.Concurrent() {
		return waitConcurrentScript
	}
	head := q.view.Queued[slices.IndexFunc(q.view.Queued, func(queued model.Job) bool { return !concurrent || !queued.Profile.Concurrent() })]
	// A held head holds every job behind it.
	switch {
	case head.Exclusive() && len(active) > 0:
		return waitExclusiveNext
	case head.Request.Kind.UsesSimulator() && q.startingSimulator():
		return waitStagger
	case !q.view.MemoryAdmits(head):
		return waitMemory
	case head.ID == job.ID:
		return waitNext
	}
	return waitBehind
}

// startingSimulator is the claim's holdSimulators: a simulator job in its
// start window that is still preparing.
func (q *queueWait) startingSimulator() bool {
	return slices.ContainsFunc(q.view.Active, func(a model.Job) bool {
		return a.State == model.Preparing && slices.Contains(q.status.StartingSimulators, a.ID)
	})
}

// render adds blocked_by and waiting to a queued job's view.
func (q *queueWait) render(view map[string]any, job model.Job) {
	if job.State != model.Queued {
		return
	}
	view["blocked_by"] = blockedBy(q.status, q.statusErr)
	if waiting := q.waiting(job); waiting != nil {
		view["waiting"] = waiting
	}
}
