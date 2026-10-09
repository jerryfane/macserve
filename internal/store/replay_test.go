package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestReplayNormalizesSnapshotAndNeverRecreatesPrunedJobs(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{Retention: time.Hour})
	job := enqueueJob(t, s, "principal", "retained", testNow)
	request := job.Request
	request.Repo = strings.ToUpper(request.Repo)
	request.SHA = strings.ToUpper(request.SHA)
	request.TimeoutSeconds = 0
	replay, err := s.Replay(ctx, "principal", "retained", request)
	if err != nil || replay.ID != job.ID || replay.Request.TimeoutSeconds != job.Profile.DefaultTimeoutSeconds {
		t.Fatalf("snapshot replay: %+v %v", replay, err)
	}
	changed := request
	changed.SHA = strings.Repeat("b", 40)
	_, err = s.Replay(ctx, "principal", "retained", changed)
	requireError(t, err, ErrConflict)
	_, err = s.Replay(ctx, "other-principal", "retained", request)
	requireError(t, err, ErrNotFound)
	if _, err := s.Cancel(ctx, job.ID, "finished", testNow); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(ctx, testNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err = s.Replay(ctx, "principal", "retained", request)
	requireError(t, err, ErrNotFound)
	_, err = s.Lookup(ctx, "principal", "retained")
	requireError(t, err, ErrNotFound)
	// A genuinely new admission can reuse the retired key, but it carries
	// only the new caller's admitted profile, not the deleted snapshot.
	admission := admissionFixture()
	admission.Profile.Version++
	admission.Profile.DefaultTimeoutSeconds = 120
	admission.Request.TimeoutSeconds = 120
	setDigest(&admission)
	fresh, reused, err := s.Enqueue(ctx, "principal", "retained", admission, testNow.Add(time.Hour))
	if err != nil || reused || fresh.ID == job.ID || fresh.Profile.Version != 2 || fresh.Request.TimeoutSeconds != 120 {
		t.Fatalf("fresh admission: %+v replay=%v err=%v", fresh, reused, err)
	}
}
