package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jerryfane/macserve/internal/model"
)

// The first cancellation request records its cause; a later request, and the
// job's terminal finish, keep it.
func TestCancelRecordsFirstCauseOnly(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "owner", "job", testNow)
	job := claimJob(t, s, "epoch", testNow)
	at := testNow.Add(time.Second)
	blockers := []string{"isolation_unavailable", "service_disk_budget_exceeded", "host_memory_pressure"}
	cancelled, err := s.Cancel(ctx, job.ID, "host readiness requires cancellation", model.CancelReason{Source: model.CancelHostReadiness, Blockers: blockers, Detail: "free_bytes=1"}, at)
	if err != nil {
		t.Fatal(err)
	}
	want := &model.CancelReason{Source: model.CancelHostReadiness, Blockers: blockers, At: at, Detail: "free_bytes=1"}
	if !reflect.DeepEqual(cancelled.CancelReason, want) {
		t.Fatalf("recorded %+v, want %+v", cancelled.CancelReason, want)
	}
	again, err := s.Cancel(ctx, job.ID, "stop", model.CancelReason{Source: model.CancelClient, Principal: "owner"}, at.Add(time.Second))
	if err != nil || !reflect.DeepEqual(again.CancelReason, want) {
		t.Fatalf("second request replaced the cause: %+v %v", again.CancelReason, err)
	}
	requireError(t, s.Transition(ctx, job.ID, job.LeaseToken, model.Cancelling, model.Finalizing, "cleanup", at), nil)
	requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Cancelled, nil, true, "cancellation requested", at), nil)
	if got := getJob(t, s, job.ID); got.Reason != "cancellation requested" || !reflect.DeepEqual(got.CancelReason, want) {
		t.Fatalf("finish lost the cause: %q %+v", got.Reason, got.CancelReason)
	}
	listed, _, err := s.List(ctx, []string{job.Request.Repo}, "", 10)
	if err != nil || len(listed) != 1 || !reflect.DeepEqual(listed[0].CancelReason, want) {
		t.Fatalf("listed cause: %+v %v", listed, err)
	}
}

// A client cancel records the principal; an administrator's cancel_active
// pause records the administrator.
func TestClientAndAdminCancelRecordPrincipal(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	queued := enqueueJob(t, s, "owner", "queued", testNow)
	cancelled, err := s.Cancel(ctx, queued.ID, "not needed", model.CancelReason{Source: model.CancelClient, Principal: "agent", Detail: "not needed"}, testNow)
	if err != nil || cancelled.State != model.Cancelled {
		t.Fatalf("client cancel: %+v %v", cancelled, err)
	}
	if got := cancelled.CancelReason; got == nil || got.Source != model.CancelClient || got.Principal != "agent" || got.Detail != "not needed" || !got.At.Equal(testNow) {
		t.Fatalf("client cause: %+v", got)
	}
	enqueueJob(t, s, "owner", "active", testNow)
	active := claimJob(t, s, "epoch", testNow)
	if _, err := s.Pause(ctx, "benchmark", "cancel_active", "admin", testNow); err != nil {
		t.Fatal(err)
	}
	if got := getJob(t, s, active.ID).CancelReason; got == nil || got.Source != model.CancelAdminPause || got.Principal != "admin" || got.Detail != "benchmark" {
		t.Fatalf("admin cause: %+v", got)
	}
}

// An unknown source or a malformed blocker or principal is refused before
// anything changes; overlong detail is cut at a UTF-8 boundary, not refused.
func TestCancelReasonBounds(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	job := enqueueJob(t, s, "owner", "job", testNow)
	for name, cause := range map[string]model.CancelReason{
		"no source":          {},
		"unknown source":     {Source: "operator"},
		"control blocker":    {Source: model.CancelHostReadiness, Blockers: []string{"disk\nemergency"}},
		"empty blocker":      {Source: model.CancelHostReadiness, Blockers: []string{""}},
		"long blocker":       {Source: model.CancelHostReadiness, Blockers: []string{strings.Repeat("b", maxCancelBlocker+1)}},
		"too many blockers":  {Source: model.CancelHostReadiness, Blockers: make([]string, maxCancelBlockers+1)},
		"padded principal":   {Source: model.CancelClient, Principal: " owner"},
		"oversize principal": {Source: model.CancelClient, Principal: strings.Repeat("p", 257)},
	} {
		if _, err := s.Cancel(ctx, job.ID, "stop", cause, testNow); err != ErrInvalid {
			t.Fatalf("%s: %v", name, err)
		}
		if cause.Principal == "" {
			continue
		}
		if _, err := s.Pause(ctx, "stop", "cancel_active", cause.Principal, testNow); err != ErrInvalid {
			t.Fatalf("%s pause: %v", name, err)
		}
	}
	if got := getJob(t, s, job.ID); got.CancelRequested || got.CancelReason != nil {
		t.Fatalf("refused cause changed the job: %+v", got)
	}
	detail := strings.Repeat("x", MaxCancelDetailBytes-1) + "é" + "tail\xff"
	cancelled, err := s.Cancel(ctx, job.ID, "stop", model.CancelReason{Source: model.CancelGateError, Detail: detail}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := cancelled.CancelReason.Detail; got != strings.Repeat("x", MaxCancelDetailBytes-1) || !utf8.ValidString(got) {
		t.Fatalf("detail not bounded at a rune boundary: %d bytes", len(got))
	}
}

// A version 5 database gains the column; its jobs, cancelled or not, read
// back with no cause, and later cancellations record one.
func TestCancelReasonMigrationKeepsVersion5Jobs(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	open := enqueueJob(t, s, "owner", "open", testNow)
	cancelledOld := enqueueJob(t, s, "owner", "cancelled", testNow)
	if _, err := s.Cancel(ctx, cancelledOld.ID, "old cancel", model.CancelReason{Source: model.CancelClient}, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE jobs DROP COLUMN cancel_reason; PRAGMA user_version=5;"); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Close(), nil)
	s = openStore(t, path, Options{})
	var version int
	requireError(t, s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version), nil)
	if version != 6 {
		t.Fatalf("user_version = %d", version)
	}
	if got := getJob(t, s, open.ID); got.CancelReason != nil || !reflect.DeepEqual(got, open) {
		t.Fatalf("migrated open job: %+v", got)
	}
	if got := getJob(t, s, cancelledOld.ID); got.CancelReason != nil || !got.CancelRequested || got.Reason != "old cancel" {
		t.Fatalf("migrated cancelled job: %+v", got)
	}
	cancelled, err := s.Cancel(ctx, open.ID, "stop", model.CancelReason{Source: model.CancelClient, Principal: "owner"}, testNow)
	if err != nil || cancelled.CancelReason == nil || cancelled.CancelReason.Principal != "owner" {
		t.Fatalf("cancel after migration: %+v %v", cancelled, err)
	}
}
