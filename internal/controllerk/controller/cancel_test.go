package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/model"
)

// captureLog collects the standard logger's output for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(previous); log.SetFlags(flags) })
	return &buf
}

func TestDeadlineCancelRecordsReason(t *testing.T) {
	f := newRuntime(t)
	lease := f.lease(t, model.Build)
	logs := captureLog(t)
	f.offset.Store(int64(600*time.Second + time.Second))
	f.controller.checkActive(context.Background())
	job, err := f.db.Get(context.Background(), lease.Job.ID)
	want := &model.CancelReason{Source: model.CancelDeadline, At: f.controller.options.Now()}
	if err != nil || !job.CancelRequested || !reflect.DeepEqual(job.CancelReason, want) {
		t.Fatalf("deadline cause: %+v %v", job.CancelReason, err)
	}
	if line := "controller job cancellation requested: job=" + job.ID + " source=deadline blockers=none"; !strings.Contains(logs.String(), line) {
		t.Fatalf("log lacks %q:\n%s", line, logs)
	}
}

// The monitor records the gate's blockers on the job, logs the gate change
// and the cancellation with the job, and logs neither again while the gate
// is unchanged.
func TestHostReadinessCancelRecordsBlockers(t *testing.T) {
	f := newRuntime(t)
	lease := f.lease(t, model.Build)
	logs := captureLog(t)
	ctx := context.Background()
	f.controller.checkActive(ctx)
	blockers := []string{"isolation_unavailable", "service_disk_budget_exceeded", "host_memory_pressure"}
	f.controller.options.Gate = func(context.Context) (health.GateState, error) {
		return health.GateState{Blockers: blockers, CancelActive: true, FreeBytes: 7, UsedBytes: -1}, nil
	}
	f.controller.checkActive(ctx)
	f.controller.checkActive(ctx)
	job, err := f.db.Get(ctx, lease.Job.ID)
	want := &model.CancelReason{Source: model.CancelHostReadiness, Blockers: blockers, At: f.controller.options.Now(), Detail: "free_bytes=7 used_bytes=-1"}
	if err != nil || job.State != model.Cancelling || !reflect.DeepEqual(job.CancelReason, want) {
		t.Fatalf("readiness cause: %s %+v %v", job.State, job.CancelReason, err)
	}
	wantLog := []string{
		"controller readiness: ready=true cancel_active=false blockers=none active_job=" + job.ID,
		"controller readiness: ready=false cancel_active=true blockers=isolation_unavailable,service_disk_budget_exceeded,host_memory_pressure active_job=" + job.ID,
		`controller job cancellation requested: job=` + job.ID + ` source=host_readiness blockers=isolation_unavailable,service_disk_budget_exceeded,host_memory_pressure detail="free_bytes=7 used_bytes=-1"`,
	}
	if got := strings.Split(strings.TrimSpace(logs.String()), "\n"); !reflect.DeepEqual(got, wantLog) {
		t.Fatalf("controller log:\n%s", logs)
	}
}

// Probes that fail without evidence block admission and keep the running job
// until the gate cancels (the last valid health expired); the job's cause and
// the log name the count (#53).
func TestProbeFailureCancelRecordsCount(t *testing.T) {
	f := newRuntime(t)
	lease := f.lease(t, model.Build)
	logs := captureLog(t)
	ctx := context.Background()
	blockers := []string{"maintenance_probe_failed"}
	for failures := 1; failures <= 3; failures++ {
		cancel := failures == 3
		var gate health.GateState
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"probe_failures":%d}`, failures)), &gate); err != nil {
			t.Fatal(err)
		}
		gate.Blockers, gate.CancelActive, gate.FreeBytes, gate.UsedBytes = blockers, cancel, 7, 9
		f.controller.options.Gate = func(context.Context) (health.GateState, error) { return gate, nil }
		f.controller.checkActive(ctx)
		job, err := f.db.Get(ctx, lease.Job.ID)
		if err != nil || job.CancelRequested != cancel {
			t.Fatalf("failure %d: cancel_requested=%t %v", failures, job.CancelRequested, err)
		}
	}
	job, err := f.db.Get(ctx, lease.Job.ID)
	want := &model.CancelReason{Source: model.CancelHostReadiness, Blockers: blockers, At: f.controller.options.Now(), Detail: "free_bytes=7 used_bytes=9 probe_failures=3"}
	if err != nil || !reflect.DeepEqual(job.CancelReason, want) {
		t.Fatalf("probe failure cause: %+v %v", job.CancelReason, err)
	}
	for _, line := range []string{
		"controller readiness: ready=false cancel_active=false blockers=maintenance_probe_failed probe_failures=1 active_job=" + job.ID,
		"controller readiness: ready=false cancel_active=false blockers=maintenance_probe_failed probe_failures=2 active_job=" + job.ID,
		"controller readiness: ready=false cancel_active=true blockers=maintenance_probe_failed probe_failures=3 active_job=" + job.ID,
		`controller job cancellation requested: job=` + job.ID + ` source=host_readiness blockers=maintenance_probe_failed detail="free_bytes=7 used_bytes=9 probe_failures=3"`,
	} {
		if !strings.Contains(logs.String(), line+"\n") {
			t.Fatalf("log lacks %q:\n%s", line, logs)
		}
	}
}

func TestGateErrorCancelRecordsReason(t *testing.T) {
	f := newRuntime(t)
	lease := f.lease(t, model.Build)
	captureLog(t)
	f.controller.options.Gate = func(context.Context) (health.GateState, error) {
		return health.GateState{}, errors.New("health read interrupted")
	}
	f.controller.checkActive(context.Background())
	job, err := f.db.Get(context.Background(), lease.Job.ID)
	if err != nil || job.CancelReason == nil || job.CancelReason.Source != model.CancelGateError || job.CancelReason.Detail != "health read interrupted" || job.CancelReason.Blockers != nil {
		t.Fatalf("gate error cause: %+v %v", job.CancelReason, err)
	}
}

// A worker poll that finds the gate cancelling records the same cause as the
// monitor does.
func TestPollHostReadinessCancelRecordsBlockers(t *testing.T) {
	f := newRuntime(t)
	lease := f.lease(t, model.Build)
	captureLog(t)
	f.controller.options.Gate = func(context.Context) (health.GateState, error) {
		return health.GateState{Blockers: []string{"toolchain_validation_unavailable"}, CancelActive: true}, nil
	}
	if _, err := f.controller.next(context.Background(), "epoch-a", nil); err != nil {
		t.Fatal(err)
	}
	job, err := f.db.Get(context.Background(), lease.Job.ID)
	if err != nil || job.CancelReason == nil || job.CancelReason.Source != model.CancelHostReadiness || !reflect.DeepEqual(job.CancelReason.Blockers, []string{"toolchain_validation_unavailable"}) {
		t.Fatalf("poll cause: %+v %v", job.CancelReason, err)
	}
}
