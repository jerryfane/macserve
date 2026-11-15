package controller

import (
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// #152 review r1: since #150 the worker's finalization of a job may take up
// to 210s (its 120s cleanup budget, then 90s for the final barrier,
// verification and cleanup), and its completion's delivery has its own 120s
// after it. The controller expired an ordinary finalizing lease at 270s
// (120s + 120s + 30s), so 200s of finalization followed by 80s of upload
// lost the lease mid-delivery, and the controller then recorded unconfirmed
// cleanup and fenced the epoch. On the default budgets that lease, and a
// cancelled one finishing the same way, now lives; one that outlasts the
// worker's finalization, its delivery and the heartbeat grace does not.
func TestFinalizingLeaseSurvivesLongFinalizationThenUpload(t *testing.T) {
	f := newRuntime(t)
	c := f.controller
	since := f.now
	job := model.Job{ID: "finalizing", Request: model.Request{Kind: model.SimulatorUITest}}
	finalizing := &execution{job: job, offered: true, heartbeat: since, finalizingSince: since}
	cancelled := &execution{job: job, offered: true, heartbeat: since, cancellingSince: since}
	for _, a := range []*execution{finalizing, cancelled} {
		if !c.alive(a, job, since.Add(200*time.Second+80*time.Second)) {
			t.Fatal("lease expired mid-delivery after a 200s finalization")
		}
		if c.alive(a, job, since.Add(210*time.Second+c.options.DeliveryTimeout+c.options.HeartbeatTimeout+time.Second)) {
			t.Fatal("lease outlives the worker's finalization, delivery and heartbeat grace")
		}
	}
}

// The controller's default finalizing lease outlasts the worker's longest
// finalization (worker.FinalizationTimeout) and the worker client's delivery
// of the completion after it (protocol.DeliveryTimeout), with heartbeat
// grace to spare, for every kind (an ios_archive job's archive evidence runs
// in its own window besides). Both sides derive their budgets from these
// constants (#152 review r1); a lease shorter than their sum expires
// mid-delivery and fences the epoch as unconfirmed cleanup.
func TestControllerFinalizingLeaseCoversFinalizationAndDelivery(t *testing.T) {
	for _, kind := range []model.Kind{model.Build, model.UnitTest, model.SimulatorUITest, model.SimulatorScript, model.IOSArchive} {
		worst := worker.FinalizationTimeout + protocol.DeliveryTimeout
		if kind == model.IOSArchive {
			worst += worker.ArchiveEvidenceTimeout
		}
		if lease := FinalizingWindow(Options{}, kind); lease <= worst {
			t.Fatalf("%s: controller finalizing lease %v does not outlast finalization and delivery %v", kind, lease, worst)
		}
	}
}
