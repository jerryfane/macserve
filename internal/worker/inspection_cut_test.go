package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// cutFake is laneFake whose admissions and residue count return the
// configured errors, as production inspections cut short by their deadline
// on a loaded host do.
type cutFake struct {
	*laneFake
	cmu                               sync.Mutex
	admission, laneAdmission, residue error
}

func newCutFake() *cutFake { return &cutFake{laneFake: newLaneFake()} }

func (f *cutFake) set(admission, laneAdmission, residue error) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.admission, f.laneAdmission, f.residue = admission, laneAdmission, residue
}

func (f *cutFake) errors() (admission, laneAdmission, residue error) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.admission, f.laneAdmission, f.residue
}

func (f *cutFake) Admission(ctx context.Context) error {
	if err, _, _ := f.errors(); err != nil {
		f.event("admission")
		return err
	}
	return f.laneFake.Admission(ctx)
}

func (f *cutFake) LaneAdmission(ctx context.Context) error {
	if _, err, _ := f.errors(); err != nil {
		f.event("lane-admission")
		return err
	}
	return f.laneFake.LaneAdmission(ctx)
}

func (f *cutFake) Residue(ctx context.Context) ([]string, error) {
	if _, _, err := f.errors(); err != nil {
		return nil, err
	}
	return f.laneFake.Residue(ctx)
}

// membershipWaitDelay is the error the registration writer policy returned
// at Studio v0.1.56, 2026-11-14 17:33:42Z (j_4bb131a8, six lanes): a
// dsmemberutil probe that exited but whose output did not close within the
// 100 ms WaitDelay. It is built by the production policy from that probe's
// error (registrationGroupMember).
func membershipWaitDelay(t *testing.T) error {
	t.Helper()
	options := Options{OwnerUID: 501, JobUID: 6202, ControllerUID: 6201}
	lookup := func(id string) (*user.User, error) {
		return &user.User{Uid: id, Gid: id, Username: "fixture" + id}, nil
	}
	lookupGroup := func(name string) (*user.Group, error) {
		return &user.Group{Name: name, Gid: map[string]string{"wheel": "0", "staff": "20", "admin": "80"}[name]}, nil
	}
	groups := func(account *user.User) ([]string, error) { return []string{account.Gid}, nil }
	member := func(*user.User, string) (bool, error) {
		return false, errors.Join(exec.ErrWaitDelay, errors.New("registration service account memberships unavailable"))
	}
	err := registrationWriterIdentities(options, lookup, lookupGroup, groups, member)
	if err == nil || err.Error() != "exec: WaitDelay expired before I/O complete\nregistration service account memberships unavailable\nregistration service account memberships unavailable" {
		t.Fatalf("not the logged membership failure: %v", err)
	}
	return err
}

// The admission inspections of Studio v0.1.56, six lanes at load 20-35
// (#150), ran out of their own time in ways #148 did not classify, and each
// left a job's cleanup unverified: 17:24:21Z j_5d77e640 "context deadline
// exceeded" (a persistence authority bracket whose 2 s ran out between its
// commands) and 17:33:42Z j_4bb131a8 "exec: WaitDelay expired before I/O
// complete" with "registration service account memberships unavailable".
// Each observed nothing and nothing of the job ran: only that job is
// refused, with cleanup_ok, no quarantine and no drain, at lane admission
// and at a solo admission alike.
func TestAdmissionInspectionDeadlineRefusesOnlyTheJob(t *testing.T) {
	for name, cut := range map[string]error{
		"bracket deadline 17:24:21Z":     context.DeadlineExceeded,
		"membership WaitDelay 17:33:42Z": membershipWaitDelay(t),
	} {
		t.Run(name+"/lane", func(t *testing.T) {
			runner := newCutFake()
			engine := laneEngine(t, runner, 2)
			source, data := sourceFixture(t)
			gate := runner.gate("job-a")
			a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
			<-runner.started
			runner.set(nil, cut, nil)
			result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), source, bytes.NewReader(data), nil)
			firstLine := strings.SplitN(cut.Error(), "\n", 2)[0]
			if !errors.Is(err, ErrACLCensusUnavailable) || result.State != model.Failed || !result.CleanupOK || result.Concurrency.IdleVerdict != IdleNotRequired || !strings.HasPrefix(result.Reason, "lane admission: "+firstLine) {
				t.Fatalf("inspection cut short at lane admission: %+v %v", result, err)
			}
			if _, err := engine.root.Lstat(quarantineRecord); err == nil {
				t.Fatal("an inspection cut short quarantined the worker")
			}
			if err := engine.LaneReady(context.Background()); err != nil {
				t.Fatalf("engine stopped admitting beside the running job: %v", err)
			}
			runner.set(nil, nil, nil)
			close(gate)
			if first := <-a; first.err != nil || !first.result.CleanupOK || first.result.Concurrency.IdleVerdict != IdleClean {
				t.Fatalf("sibling: %+v %v", first.result, first.err)
			}
		})
		t.Run(name+"/solo", func(t *testing.T) {
			runner := newCutFake()
			engine := laneEngine(t, runner, 2)
			source, data := sourceFixture(t)
			runner.set(cut, nil, nil)
			result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-a", model.Build), source, bytes.NewReader(data), nil)
			if !errors.Is(err, ErrACLCensusUnavailable) || result.State != model.Failed || !result.CleanupOK || result.Concurrency.IdleVerdict != IdleNotRequired || !strings.HasPrefix(result.Reason, "admission: ") {
				t.Fatalf("inspection cut short at solo admission: %+v %v", result, err)
			}
			runner.set(nil, nil, nil)
			if next, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), source, bytes.NewReader(data), nil); err != nil || next.State != model.Succeeded || !next.CleanupOK {
				t.Fatalf("next job after the refusal: %+v %v", next, err)
			}
		})
	}
}

// The same inspections cut short in a job's finalization, after its own
// processes were stopped and verified: the job's cleanup stands, its idle
// verdict is deferred, the engine drains until the idle Recover judges the
// account, and nothing is quarantined. Alone that is its final admission;
// beside others its residue census.
func TestFinalizationInspectionDeadlineDefersToIdleCheck(t *testing.T) {
	for name, cut := range map[string]error{
		"bracket deadline 17:24:21Z":     context.DeadlineExceeded,
		"membership WaitDelay 17:33:42Z": membershipWaitDelay(t),
	} {
		for _, alone := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/alone=%t", name, alone), func(t *testing.T) {
				runner := newCutFake()
				engine := laneEngine(t, runner, 2)
				source, data := sourceFixture(t)
				var sibling chan laneOutcome
				var siblingGate chan struct{}
				if !alone {
					siblingGate = runner.gate("job-s")
					sibling = runLane(engine, fixtureLaneJob(t, "job-s", model.Build), source, data)
					<-runner.started
				}
				gate := runner.gate("job-a")
				a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
				<-runner.started
				if alone {
					runner.set(cut, nil, nil)
				} else {
					runner.set(nil, nil, cut)
				}
				close(gate)
				first := <-a
				if first.err != nil || first.result.State != model.Succeeded || !first.result.CleanupOK || first.result.Concurrency.IdleVerdict != IdleDeferred {
					t.Fatalf("inspection cut short at job end: %+v %v", first.result, first.err)
				}
				if _, err := engine.root.Lstat(quarantineRecord); err == nil {
					t.Fatal("an inspection cut short quarantined the worker")
				}
				if err := engine.LaneReady(context.Background()); !errors.Is(err, ErrDrain) {
					t.Fatalf("engine admits before the idle check: %v", err)
				}
				runner.set(nil, nil, nil)
				if sibling != nil {
					close(siblingGate)
					<-sibling
				}
				if err := engine.Recover(context.Background()); err != nil {
					t.Fatalf("clean idle check: %v", err)
				}
				if err := engine.LaneReady(context.Background()); err != nil {
					t.Fatalf("drain survived the idle check: %v", err)
				}
			})
		}
	}
}

// barrierFake counts the account quiesces of a job that ends alone, after
// its recipe ran, and lets the test answer each.
type barrierFake struct {
	*laneFake
	ran       atomic.Bool
	calls     atomic.Int32
	answer    func(ctx context.Context, call int32) error
	remaining atomic.Int64
}

func newBarrierFake(answer func(ctx context.Context, call int32) error) *barrierFake {
	f := &barrierFake{laneFake: newLaneFake(), answer: answer}
	hook := f.laneFake.fakeRunner.hook
	f.laneFake.fakeRunner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if c.Executable == "/usr/bin/xcodebuild" && len(c.Args) > 0 && c.Args[0] == "test" {
			f.ran.Store(true)
		}
		return hook(ctx, c, out, stderr)
	}
	f.laneFake.fakeRunner.quiesce = func(ctx context.Context) error {
		if !f.ran.Load() {
			return ctx.Err()
		}
		call := f.calls.Add(1)
		if deadline, ok := ctx.Deadline(); ok {
			f.remaining.Store(int64(time.Until(deadline)))
		}
		if err := ctx.Err(); err != nil {
			// The production quiesce on an expired deadline.
			return errors.Join(ErrCleanup, err)
		}
		return f.answer(ctx, call)
	}
	return f
}

// Barriers of a passing test job that ends alone, in order: stopWriters,
// the barrier after evidence extraction (testEvidence), collection's, and
// the final one.
const (
	collectBarrier = 3
	finalBarrier   = 4
)

// Studio v0.1.56, 2026-11-15 00:08:28Z, j_e63178e6 (#150): at the end of a
// passing UI test the evidence steps used the whole cleanup budget
// (collection's barrier passed at its end, the collection then found the
// deadline: "context deadline exceeded"), so the final barrier failed at
// once on the expired deadline ("worker process cleanup failed / context
// deadline exceeded") and the job's cleanup was reported unverified, which
// drained the worker. The final barrier, the account's verification and the
// cleanup now get a window of their own (finalVerificationWindow): the job keeps its
// verified cleanup.
func TestFinalBarrierGetsItsOwnWindowAfterEvidence(t *testing.T) {
	runner := newBarrierFake(func(ctx context.Context, call int32) error {
		if call == collectBarrier {
			<-ctx.Done()
		}
		return nil
	})
	engine := laneEngine(t, runner, 2)
	engine.options.CleanupTimeout = 500 * time.Millisecond
	source, data := sourceFixture(t)
	result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-a", model.UnitTest), source, bytes.NewReader(data), nil)
	if runner.calls.Load() != finalBarrier || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("not the logged finalization: calls=%d err=%v", runner.calls.Load(), err)
	}
	if errors.Is(err, ErrCleanup) || !result.CleanupOK || result.Concurrency.IdleVerdict != IdleClean || result.Summary == nil || result.Summary.Failed != 0 {
		t.Fatalf("final barrier had no time of its own: %+v %v", result, err)
	}
	if left := time.Duration(runner.remaining.Load()); left < time.Minute {
		t.Fatalf("final barrier got only %v", left)
	}
	if err := engine.LaneReady(context.Background()); err != nil {
		t.Fatalf("verified cleanup drained the engine: %v", err)
	}
}

// A final barrier that ran out of its own time after every earlier barrier
// verified the job's processes defers to the idle check, which stops and
// judges whatever it did not, before the workspace is removed.
func TestFinalBarrierCutShortDefersToIdleCheck(t *testing.T) {
	runner := newBarrierFake(func(ctx context.Context, call int32) error {
		if call == finalBarrier {
			return errors.Join(ErrCleanup, context.DeadlineExceeded)
		}
		return nil
	})
	engine := laneEngine(t, runner, 2)
	source, data := sourceFixture(t)
	result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-a", model.UnitTest), source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK || result.Concurrency.IdleVerdict != IdleDeferred {
		t.Fatalf("final barrier cut short: %+v %v", result, err)
	}
	if _, err := engine.workspaces.Lstat("job-a"); err != nil {
		t.Fatalf("workspace removed before the idle check: %v", err)
	}
	if err := engine.LaneReady(context.Background()); !errors.Is(err, ErrDrain) {
		t.Fatalf("engine admits before the idle check: %v", err)
	}
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatalf("clean idle check: %v", err)
	}
	if _, err := engine.workspaces.Lstat("job-a"); !os.IsNotExist(err) {
		t.Fatalf("idle check left the workspace: %v", err)
	}
}

// Real findings and failures keep their verdicts: a final barrier that ran
// and failed, or found a survivor, leaves the cleanup unverified (a survivor
// quarantines); a final barrier cut short after an earlier barrier already
// failed is not deferred; and at a job's end alone, contamination found by
// its admission quarantines however close its deadline was.
func TestFinalizationFindingsKeepTheirVerdicts(t *testing.T) {
	survivor := fmt.Errorf("%w: job processes remain after termination", ErrContamination)
	for name, c := range map[string]struct {
		answer     func(runner *cutFake, call int32) error
		quarantine bool
	}{
		"final barrier failed": {answer: func(_ *cutFake, call int32) error {
			if call == finalBarrier {
				return errors.Join(ErrCleanup, errors.New("signal: operation not permitted"))
			}
			return nil
		}},
		"final barrier survivor": {answer: func(_ *cutFake, call int32) error {
			if call == finalBarrier {
				return survivor
			}
			return nil
		}, quarantine: true},
		"earlier barrier failed": {answer: func(_ *cutFake, call int32) error {
			if call == collectBarrier || call == finalBarrier {
				return errors.Join(ErrCleanup, context.DeadlineExceeded)
			}
			return nil
		}},
		"admission contamination beside its deadline": {answer: func(runner *cutFake, call int32) error {
			if call == finalBarrier {
				// The job's final admission alone finds it.
				runner.set(errors.Join(survivor, context.DeadlineExceeded), nil, nil)
			}
			return nil
		}, quarantine: true},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &cutFake{}
			runner.laneFake = newBarrierFake(func(_ context.Context, call int32) error { return c.answer(runner, call) }).laneFake
			engine := laneEngine(t, runner, 2)
			source, data := sourceFixture(t)
			result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-a", model.UnitTest), source, bytes.NewReader(data), nil)
			if err == nil || result.CleanupOK || result.Concurrency.IdleVerdict != IdleDeferred {
				t.Fatalf("finding passed as a deadline: %+v %v", result, err)
			}
			if _, err := engine.root.Lstat(quarantineRecord); (err == nil) != c.quarantine {
				t.Fatalf("quarantine %v, want %v", err == nil, c.quarantine)
			}
		})
	}
}

// At a job's admission a finding beside a deadline keeps its verdict: a
// writable ACL quarantines, an unattributed process drains, and a job whose
// own context ended is not refused as the service's (#150 classifies only an
// inspection that ran out of its own time).
func TestAdmissionFindingBesideDeadlineKeepsItsVerdict(t *testing.T) {
	acl := fmt.Errorf("%w: ACL requires manual review", ErrContamination)
	for name, c := range map[string]struct {
		err               error
		quarantine, drain bool
	}{
		"writable ACL":       {err: errors.Join(acl, context.DeadlineExceeded), quarantine: true},
		"unattributed":       {err: errors.Join(fmt.Errorf("%w: 1 unattributed job-account process(es)", ErrDrain), context.DeadlineExceeded), drain: true},
		"census that failed": {err: errors.New("registered tree ACL census failed: exit status 1")},
	} {
		t.Run(name, func(t *testing.T) {
			runner := newCutFake()
			engine := laneEngine(t, runner, 2)
			source, data := sourceFixture(t)
			gate := runner.gate("job-a")
			a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
			<-runner.started
			runner.set(nil, c.err, nil)
			result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), source, bytes.NewReader(data), nil)
			if err == nil || errors.Is(err, ErrACLCensusUnavailable) || result.CleanupOK {
				t.Fatalf("finding refused as a deadline: %+v %v", result, err)
			}
			if _, err := engine.root.Lstat(quarantineRecord); (err == nil) != c.quarantine {
				t.Fatalf("quarantine %v, want %v", err == nil, c.quarantine)
			}
			if err := engine.LaneReady(context.Background()); c.drain && !errors.Is(err, ErrDrain) {
				t.Fatalf("unattributed process did not drain: %v", err)
			}
			runner.set(nil, nil, nil)
			close(gate)
			<-a
		})
	}
	t.Run("job context ended", func(t *testing.T) {
		runner := newCutFake()
		engine := laneEngine(t, runner, 2)
		source, data := sourceFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if result, err := engine.Execute(ctx, fixtureLaneJob(t, "job-a", model.Build), source, bytes.NewReader(data), nil); errors.Is(err, ErrACLCensusUnavailable) || result.CleanupOK {
			t.Fatalf("cancelled job refused as the service's: %+v %v", result, err)
		}
	})
}

// A hot persistence inspection its deadline cut short observed nothing and
// runs once more with a fresh allocation; a finding, or a failure that ran,
// ends it at once (#150: seven refusals in 23 minutes at six lanes).
func TestHotPersistenceCutShortIsRetriedOnce(t *testing.T) {
	options, _ := attestationFixture(t)
	boot, err := bootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PersistenceDigest(options.PersistencePath, options.JobUID)
	if err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(filepath.Dir(options.PersistencePath), "baseline.json")
	if err := saveBaseline(baselinePath, GUIBaseline{JobUID: options.JobUID, Boot: boot, PersistenceSHA256: digest, Processes: []ProcessIdentity{{PID: 100, Start: "retry-fixture"}}, Launchd: &LaunchdEnvironment{}}); err != nil {
		t.Fatal(err)
	}
	reached := errors.New("second attempt reached")
	contamination := fmt.Errorf("%w: nonempty job-user crontab", ErrContamination)
	for name, c := range map[string]struct {
		answers []error
		calls   int
		want    error
	}{
		"cut, then answered":   {answers: []error{context.DeadlineExceeded, reached}, calls: 2, want: reached},
		"membership WaitDelay": {answers: []error{membershipWaitDelay(t), reached}, calls: 2, want: reached},
		"cut twice":            {answers: []error{context.DeadlineExceeded, context.DeadlineExceeded}, calls: 2, want: context.DeadlineExceeded},
		"finding":              {answers: []error{contamination, reached}, calls: 1, want: ErrContamination},
		"failure that ran":     {answers: []error{errors.New("login item inspection unavailable"), reached}, calls: 1},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			runner := &nativeRunner{
				uid: int(options.JobUID), scope: &processScope{},
				baselinePath: baselinePath, persistencePath: options.PersistencePath,
				console: func() error { return nil },
				persistence: func(ctx context.Context) error {
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > persistenceAdmissionTimeout {
						t.Fatalf("attempt without its own bound: %v", deadline)
					}
					calls++
					return c.answers[calls-1]
				},
			}
			for _, admit := range []func(context.Context) error{runner.Admission, runner.LaneAdmission} {
				calls = 0
				err := admit(context.Background())
				if calls != c.calls || err == nil || c.want != nil && !errors.Is(err, c.want) {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
			}
		})
	}
}

// An authority bracket's lock wait bounds only the wait for a held lock: a
// free lock is taken however little of the wait is left, and the
// protected-input inspection of the authority's directory runs under the
// bracket's own deadline (#150: at load 20-35 that inspection outlasted the
// 1 s lock wait that bounded it).
func TestAttestationLockWaitBoundsOnlyTheWait(t *testing.T) {
	options, _ := attestationFixture(t)
	ran := false
	err := withAttestationFileLock(context.Background(), options, persistenceAttestationFile+".lock", time.Nanosecond, func(*os.Root) error {
		ran = true
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("free lock refused: ran=%t err=%v", ran, err)
	}
}

// An inspection command's output may close a little after the command
// exits on a loaded host: at 100 ms (Studio v0.1.56, 17:33:42Z) a probe that
// answered still ended in exec.ErrWaitDelay (#150).
func TestInspectionOutputCloseGetsLoadedHostWaitDelay(t *testing.T) {
	// The shell exits at once; its background child holds the output open
	// for 400 ms more.
	out, _, err := inspectCommand(context.Background(), nil, "/bin/sh", "-c", "sleep 0.4 & echo answered")
	if err != nil || strings.TrimSpace(out) != "answered" {
		t.Fatalf("output closing after exit: %q %v", out, err)
	}
}
