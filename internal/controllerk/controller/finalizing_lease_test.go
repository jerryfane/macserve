package controller

import (
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// finalizingAt is a delivered lease of kind that began finalizing at since,
// its last heartbeat then.
func finalizingAt(kind model.Kind, since time.Time) (*execution, model.Job) {
	job := model.Job{ID: "finalizing", Request: model.Request{Kind: kind}}
	return &execution{job: job, offered: true, heartbeat: since, finalizingSince: since}, job
}

// The controller keeps a finalizing lease for the worker's longest
// finalization (worker.FinalizationTimeout: since #150 the final barrier,
// verification and cleanup get their own window after the evidence steps)
// plus its completion's delivery (protocol.DeliveryTimeout), with heartbeat
// grace; one that outlasts both and the grace is lost. #152 review r1: with
// the controller's former 270s (120s cleanup + 120s delivery + 30s), a
// finalization of up to 210s and its delivery could expire the lease
// mid-delivery, which fences the epoch as unconfirmed cleanup.
func TestFinalizingLeaseCoversWorkerFinalizationAndDelivery(t *testing.T) {
	f := newRuntime(t)
	c := f.controller
	since := f.now
	worst := worker.FinalizationTimeout + protocol.DeliveryTimeout
	for _, kind := range []model.Kind{model.Build, model.SimulatorUITest, model.IOSArchive} {
		a, job := finalizingAt(kind, since)
		extra := time.Duration(0)
		if kind == model.IOSArchive {
			extra = worker.ArchiveEvidenceTimeout
		}
		if !c.alive(a, job, since.Add(worst+extra)) {
			t.Fatalf("%s: lease lost within the worker's finalization and delivery (%v)", kind, worst+extra)
		}
		if c.alive(a, job, since.Add(worst+extra+c.options.HeartbeatTimeout+time.Second)) {
			t.Fatalf("%s: lease outlives finalization, delivery and heartbeat grace", kind)
		}
	}
	// A cancellation's finalization is the same work.
	a, job := finalizingAt(model.Build, time.Time{})
	a.cancellingSince = since
	if !c.alive(a, job, since.Add(worst)) {
		t.Fatal("cancelled lease lost within the worker's finalization and delivery")
	}
}

// The case #152 review r1 named, on the default budgets: 200s of
// finalization, then 80s of upload. Before the controller derived its
// finalizing budget from the worker's, it expired that lease at 270s.
func TestFinalizingLeaseSurvivesLongFinalizationThenUpload(t *testing.T) {
	f := newRuntime(t)
	a, job := finalizingAt(model.SimulatorUITest, f.now)
	if !f.controller.alive(a, job, f.now.Add(200*time.Second+80*time.Second)) {
		t.Fatal("lease expired mid-delivery after a 200s finalization")
	}
}
