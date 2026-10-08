package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func admissionFixture() model.Admission {
	profile := model.Profile{
		ID: "build", Version: 1, Repo: "example-org/example-app", Kind: model.Build,
		Xcode:        model.Xcode{Version: "27.0", Build: "27A100"},
		DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", WorkDir: ".",
		Run:                   model.Command{Executable: "/usr/bin/true", Args: []string{"argument"}},
		GeneratedFiles:        []model.GeneratedFile{{Path: "config.txt", Content: "approved"}},
		DefaultTimeoutSeconds: 60, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512,
	}
	admission := model.Admission{
		Request: model.Request{Repo: profile.Repo, SHA: strings.Repeat("a", 40), Kind: profile.Kind, Profile: profile.ID, Xcode: profile.Xcode, TimeoutSeconds: 60},
		Profile: profile,
	}
	setDigest(&admission)
	return admission
}

func setDigest(admission *model.Admission) {
	data, _ := json.Marshal(admission.Profile)
	digest := sha256.Sum256(data)
	admission.ProfileDigest = hex.EncodeToString(digest[:])
}

func newStore(t *testing.T, options Options) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private", "queue.sqlite")
	s := openStore(t, path, options)
	return s, path
}

func openStore(t *testing.T, path string, options Options) *Store {
	t.Helper()
	s, err := Open(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func enqueueJob(t *testing.T, s *Store, principal, key string, now time.Time) model.Job {
	t.Helper()
	job, replay, err := s.Enqueue(context.Background(), principal, key, admissionFixture(), now)
	if err != nil || replay {
		t.Fatalf("enqueue: replay=%v err=%v", replay, err)
	}
	return job
}

func claimJob(t *testing.T, s *Store, epoch string, now time.Time) model.Job {
	t.Helper()
	job, err := s.Claim(context.Background(), epoch, now)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func getJob(t *testing.T, s *Store, id string) model.Job {
	t.Helper()
	job, err := s.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func finishJob(t *testing.T, s *Store, job model.Job, state model.State, cleanup bool, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if job.State != model.Finalizing {
		if err := s.Transition(ctx, job.ID, job.LeaseToken, job.State, model.Finalizing, "collecting evidence", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Finish(ctx, job.ID, job.LeaseToken, state, json.RawMessage(`{"exit_code":0}`), cleanup, "finished", now); err != nil {
		t.Fatal(err)
	}
}

func requireError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v; want %v", err, want)
	}
}

func TestRestartPreservesSnapshotsLeasesAndPause(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	input := admissionFixture()
	job, _, err := s.Enqueue(ctx, "principal", "key", input, testNow)
	if err != nil {
		t.Fatal(err)
	}
	input.Profile.Run.Args[0] = "mutated input"
	job.Profile.GeneratedFiles[0].Content = "mutated output"
	job = claimJob(t, s, "epoch-one", testNow.Add(time.Second))
	if job.Profile.Run.Args[0] != "argument" || job.Profile.GeneratedFiles[0].Content != "approved" {
		t.Fatal("profile snapshot was not isolated")
	}
	if job.State != model.Preparing || job.LeaseToken == "" || job.WorkerEpoch != "epoch-one" || job.StartedAt == nil || !job.Deadline.Equal(testNow.Add(61*time.Second)) {
		t.Fatalf("invalid claim: %+v", job)
	}
	if _, err := s.AppendLog(ctx, job.ID, "stdout", "partial output\n", testNow); err != nil {
		t.Fatal(err)
	}
	pause, err := s.Pause(ctx, "owner activity", "drain", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, Options{})
	if got := getJob(t, s, job.ID); !reflect.DeepEqual(got, job) {
		t.Fatalf("job changed across reopen: got %+v want %+v", got, job)
	}
	state, err := s.ServiceState(ctx)
	if err != nil || state != pause {
		t.Fatalf("pause did not persist: %+v, %v", state, err)
	}
	found, err := s.Lookup(ctx, "principal", "key")
	if err != nil || found.ID != job.ID {
		t.Fatalf("lookup after restart: %+v, %v", found, err)
	}
	logs, next, truncated, err := s.Logs(ctx, job.ID, 0, 0)
	if err != nil || next != 1 || truncated || len(logs) != 1 || logs[0].Text != "partial output\n" {
		t.Fatalf("logs after reopen: %+v %d %v %v", logs, next, truncated, err)
	}
	_, err = s.Claim(ctx, "epoch-two", testNow)
	requireError(t, err, ErrNoJob)
}

func TestIdempotencyPrecedesCapacityAndProfileChanges(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{QueueLimit: 1, PerPrincipalLimit: 1})
	first := enqueueJob(t, s, "principal", "opaque'key", testNow)
	changed := admissionFixture()
	changed.Profile.Version++
	changed.Profile.Run.Args[0] = "new approved command"
	setDigest(&changed)
	replay, isReplay, err := s.Enqueue(ctx, "principal", "opaque'key", changed, testNow.Add(time.Minute))
	if err != nil || !isReplay || !reflect.DeepEqual(first, replay) {
		t.Fatalf("snapshot replay: %+v %v %v", replay, isReplay, err)
	}
	changed.Profile = model.Profile{}
	changed.ProfileDigest = ""
	if replay, ok, err := s.Enqueue(ctx, "principal", "opaque'key", changed, testNow); err != nil || !ok || replay.ID != first.ID {
		t.Fatalf("retry required current profile: %v %v", ok, err)
	}
	changed.Request.SHA = strings.Repeat("b", 40)
	_, _, err = s.Enqueue(ctx, "principal", "opaque'key", changed, testNow)
	requireError(t, err, ErrConflict)
	_, _, err = s.Enqueue(ctx, "principal", "another", admissionFixture(), testNow)
	requireError(t, err, ErrFull)
	if _, err := s.Cancel(ctx, first.ID, "cancelled", testNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	terminal := getJob(t, s, first.ID)
	replay, isReplay, err = s.Enqueue(ctx, "principal", "opaque'key", admissionFixture(), testNow.Add(time.Hour))
	if err != nil || !isReplay || !reflect.DeepEqual(replay, terminal) {
		t.Fatalf("terminal replay changed: %+v %v %v", replay, isReplay, err)
	}
}

func TestPrincipalScopeCapacityAndFIFO(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{QueueLimit: 3, PerPrincipalLimit: 2})
	first := enqueueJob(t, s, "one", "same-key", testNow)
	second := enqueueJob(t, s, "two", "same-key", testNow)
	third := enqueueJob(t, s, "one", "other-key", testNow)
	if first.ID == second.ID {
		t.Fatal("idempotency crossed principal boundary")
	}
	_, _, err := s.Enqueue(ctx, "three", "key", admissionFixture(), testNow)
	requireError(t, err, ErrFull)
	claimed := claimJob(t, s, "epoch", testNow)
	if claimed.ID != first.ID {
		t.Fatal("claim did not use insertion order")
	}
	if _, err := s.Cancel(ctx, second.ID, "remove queued job", testNow); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Enqueue(ctx, "one", "over-own-limit", admissionFixture(), testNow)
	requireError(t, err, ErrFull)
	fourth := enqueueJob(t, s, "three", "key", testNow)
	finishJob(t, s, claimed, model.Succeeded, true, testNow.Add(time.Second))
	claimed = claimJob(t, s, "epoch", testNow.Add(2*time.Second))
	if claimed.ID != third.ID {
		t.Fatalf("FIFO skipped third job for %s", claimed.ID)
	}
	finishJob(t, s, claimed, model.Succeeded, true, testNow.Add(3*time.Second))
	if claimed = claimJob(t, s, "epoch", testNow.Add(4*time.Second)); claimed.ID != fourth.ID {
		t.Fatal("FIFO tail changed")
	}
}

func TestIndependentHandlesClaimExactlyOne(t *testing.T) {
	ctx := context.Background()
	one, path := newStore(t, Options{})
	two := openStore(t, path, Options{})
	first := enqueueJob(t, one, "principal", "one", testNow)
	second := enqueueJob(t, one, "principal", "two", testNow)
	type result struct {
		job model.Job
		err error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var group sync.WaitGroup
	for _, handle := range []*Store{one, two} {
		group.Add(1)
		go func(handle *Store) {
			defer group.Done()
			<-start
			job, err := handle.Claim(ctx, "worker", testNow)
			results <- result{job, err}
		}(handle)
	}
	close(start)
	group.Wait()
	close(results)
	var winner model.Job
	wins, busy := 0, 0
	for result := range results {
		if result.err == nil {
			wins++
			winner = result.job
		} else if errors.Is(result.err, ErrNoJob) {
			busy++
		} else {
			t.Fatal(result.err)
		}
	}
	if wins != 1 || busy != 1 || winner.ID != first.ID {
		t.Fatalf("claim winners=%d busy=%d winner=%s", wins, busy, winner.ID)
	}
	// Even a writer bypassing Claim must not be able to create a second active
	// job. This protects the consumer-visible singleton at the database boundary.
	_, err := two.db.ExecContext(ctx, "UPDATE jobs SET state='preparing',worker_epoch='other',lease_token='other',started_at=?,deadline=? WHERE id=?", testNow.UnixNano(), testNow.Add(time.Minute).UnixNano(), second.ID)
	if err == nil {
		t.Fatal("database allowed a second active job")
	}
	finishJob(t, one, winner, model.Succeeded, true, testNow.Add(time.Second))
	if got := claimJob(t, two, "worker", testNow.Add(2*time.Second)); got.ID != second.ID || got.LeaseToken == winner.LeaseToken {
		t.Fatal("slot did not release with a fresh lease")
	}
}

func TestIndependentHandlesAdmissionIsAtomic(t *testing.T) {
	for _, sameKey := range []bool{true, false} {
		t.Run(map[bool]string{true: "same idempotency", false: "capacity"}[sameKey], func(t *testing.T) {
			ctx := context.Background()
			one, path := newStore(t, Options{QueueLimit: 1})
			two := openStore(t, path, Options{QueueLimit: 1})
			type result struct {
				job    model.Job
				replay bool
				err    error
			}
			results := make(chan result, 2)
			start := make(chan struct{})
			for index, handle := range []*Store{one, two} {
				key := "one"
				if index == 1 && !sameKey {
					key = "two"
				}
				go func(handle *Store, key string) {
					<-start
					job, replay, err := handle.Enqueue(ctx, "principal", key, admissionFixture(), testNow)
					results <- result{job, replay, err}
				}(handle, key)
			}
			close(start)
			left, right := <-results, <-results
			if sameKey {
				if left.err != nil || right.err != nil || left.job.ID != right.job.ID || left.replay == right.replay {
					t.Fatalf("non-atomic replay: %+v %+v", left, right)
				}
			} else if !(left.err == nil && errors.Is(right.err, ErrFull) || right.err == nil && errors.Is(left.err, ErrFull)) {
				t.Fatalf("non-atomic cap: %+v %+v", left, right)
			}
		})
	}
}

func TestListUsesDurableRepositoryScopedCursor(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{Retention: time.Hour})
	first := enqueueJob(t, s, "principal", "one", testNow)
	other := admissionFixture()
	other.Request.Repo = "example-org/example-library"
	other.Profile.Repo = other.Request.Repo
	setDigest(&other)
	if _, _, err := s.Enqueue(ctx, "principal", "other-repo", other, testNow); err != nil {
		t.Fatal(err)
	}
	second := enqueueJob(t, s, "principal", "two", testNow)
	third := enqueueJob(t, s, "principal", "three", testNow)
	for _, repos := range [][]string{nil, {}} {
		jobs, cursor, err := s.List(ctx, repos, "", 1)
		if err != nil || len(jobs) != 0 || cursor != "" {
			t.Fatal("empty authorization allowed listing")
		}
	}
	jobs, cursor, err := s.List(ctx, []string{"example-org/example-app"}, "", 1)
	if err != nil || len(jobs) != 1 || jobs[0].ID != first.ID || cursor == "" {
		t.Fatalf("first page: %+v %q %v", jobs, cursor, err)
	}
	if _, err := s.Cancel(ctx, first.ID, "done", testNow); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(ctx, testNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, Options{Retention: time.Hour})
	jobs, cursor, err = s.List(ctx, []string{"example-org/example-app"}, cursor, 1)
	if err != nil || len(jobs) != 1 || jobs[0].ID != second.ID || cursor == "" {
		t.Fatalf("cursor shifted after prune/reopen: %+v %q %v", jobs, cursor, err)
	}
	jobs, cursor, err = s.List(ctx, []string{"example-org/example-app"}, cursor, 1)
	if err != nil || len(jobs) != 1 || jobs[0].ID != third.ID || cursor != "" {
		t.Fatalf("last page: %+v %q %v", jobs, cursor, err)
	}
	jobs, _, err = s.List(ctx, []string{"example-org/example-app') OR 1=1 --"}, "", 100)
	if err != nil || len(jobs) != 0 {
		t.Fatal("repository filter was not bound as data")
	}
	_, _, err = s.List(ctx, []string{"example-org/example-app"}, "not-a-cursor", 1)
	requireError(t, err, ErrInvalid)
}

func TestBoundaryRejectsMalformedAdmission(t *testing.T) {
	cases := map[string]func(*model.Admission){
		"sha":                     func(a *model.Admission) { a.Request.SHA = "branch-name" },
		"unknown kind":            func(a *model.Admission) { a.Request.Kind = "archive" },
		"zero timeout":            func(a *model.Admission) { a.Request.TimeoutSeconds = 0 },
		"excess timeout":          func(a *model.Admission) { a.Request.TimeoutSeconds = 601 },
		"digest":                  func(a *model.Admission) { a.ProfileDigest = strings.Repeat("0", 64) },
		"repo mismatch":           func(a *model.Admission) { a.Profile.Repo = "example-org/example-library"; setDigest(a) },
		"toolchain mismatch":      func(a *model.Admission) { a.Request.Xcode.Build = "27B200" },
		"missing command":         func(a *model.Admission) { a.Profile.Run.Executable = ""; setDigest(a) },
		"invalid profile timeout": func(a *model.Admission) { a.Profile.MaxTimeoutSeconds = -1; setDigest(a) },
		"missing simulator": func(a *model.Admission) {
			a.Request.Kind = model.SimulatorUITest
			a.Profile.Kind = model.SimulatorUITest
			setDigest(a)
		},
		"missing unit simulator": func(a *model.Admission) {
			a.Request.Kind = model.UnitTest
			a.Profile.Kind = model.UnitTest
			setDigest(a)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := newStore(t, Options{})
			admission := admissionFixture()
			mutate(&admission)
			_, _, err := s.Enqueue(context.Background(), "principal", "key", admission, testNow)
			requireError(t, err, ErrInvalid)
			_, err = s.Claim(context.Background(), "epoch", testNow)
			requireError(t, err, ErrNoJob)
		})
	}
	s, _ := newStore(t, Options{})
	for _, value := range []string{"", "  ", strings.Repeat("x", 257), "line\nbreak"} {
		_, _, err := s.Enqueue(context.Background(), value, "key", admissionFixture(), testNow)
		requireError(t, err, ErrInvalid)
		_, _, err = s.Enqueue(context.Background(), "principal", value, admissionFixture(), testNow)
		requireError(t, err, ErrInvalid)
	}
}

func TestOpenProtectsLocalStorage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "queue.sqlite")
	s := openStore(t, path, Options{})
	enqueueJob(t, s, "principal", "key", testNow)
	for _, name := range []string{dir, path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatalf("storage is not private: %s mode=%o", filepath.Base(name), info.Mode().Perm())
		}
	}
	public := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(public, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	_, err := Open(filepath.Join(public, "queue.sqlite"), Options{})
	requireError(t, err, ErrInvalid)
	_, err = Open(filepath.Join(t.TempDir(), "queue.sqlite"), Options{QueueLimit: -1})
	requireError(t, err, ErrInvalid)
}
