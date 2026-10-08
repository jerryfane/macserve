package worker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"testing"
	"time"
)

const testJobUID = 12345

func trustedGUI() processSample {
	return processSample{pid: 100, group: 100, uid: testJobUID, start: "boot:100"}
}
func scopeFixture() *processScope {
	return &processScope{uid: testJobUID, baseline: GUIBaseline{JobUID: testJobUID, Boot: "boot", Processes: []ProcessIdentity{{PID: 100, Start: "boot:100"}}}, interval: time.Millisecond, grace: time.Millisecond}
}

func TestScopeTerminatesEscapedAndOrphanProcessesOnly(t *testing.T) {
	s := scopeFixture()
	// These PIDs belong to unrelated process groups, including an orphan's new
	// session. No process in this test exists in the host kernel.
	rows := []processSample{trustedGUI(), {pid: 200, group: 200, uid: testJobUID, start: "escaped"}, {pid: 300, group: 300, uid: testJobUID, start: "orphan"}, {pid: 400, group: 400, uid: 999, start: "owner"}, {pid: 500, uid: 0, start: "broker"}}
	var signalled []int
	s.sample = func(context.Context) ([]processSample, error) { return append([]processSample(nil), rows...), nil }
	s.signal = func(_ context.Context, p processSample, _ syscall.Signal) error {
		signalled = append(signalled, p.pid)
		for i, row := range rows {
			if row.pid == p.pid {
				rows = append(rows[:i], rows[i+1:]...)
				break
			}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.quiesce(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(signalled, []int{200, 300}) {
		t.Fatalf("unsafe UID cleanup targets: %v", signalled)
	}
	if len(rows) != 3 || rows[0].pid != 100 || rows[1].uid != 999 || rows[2].uid != 0 {
		t.Fatalf("trusted or foreign process changed: %+v", rows)
	}
}

func TestScopeQuarantinesUnobservableOrUnkillableProcesses(t *testing.T) {
	for _, mode := range []string{"sample-error", "signal-error", "residual", "baseline-reused", "baseline-missing", "baseline-foreign"} {
		t.Run(mode, func(t *testing.T) {
			s := scopeFixture()
			s.sample = func(context.Context) ([]processSample, error) {
				baseline := trustedGUI()
				switch mode {
				case "sample-error":
					return nil, errors.New("kernel snapshot unavailable")
				case "baseline-missing":
					return nil, nil
				case "baseline-reused":
					baseline.start = "replacement"
				case "baseline-foreign":
					baseline.uid = 999
				}
				return []processSample{baseline, {pid: 200, uid: testJobUID, start: "escaped"}}, nil
			}
			calls := 0
			s.signal = func(context.Context, processSample, syscall.Signal) error {
				calls++
				if mode == "signal-error" {
					return syscall.EPERM
				}
				return nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			if err := s.quiesce(ctx); !errors.Is(err, ErrCleanup) {
				t.Fatalf("uncertain scope accepted: %v", err)
			}
			if (mode == "baseline-reused" || mode == "baseline-missing" || mode == "baseline-foreign" || mode == "sample-error") && calls != 0 {
				t.Fatal("signalled before validating protected baseline")
			}
		})
	}
}

func TestScopeRechecksEmptySnapshot(t *testing.T) {
	s := scopeFixture()
	samples, signalled := 0, 0
	s.sample = func(context.Context) ([]processSample, error) {
		samples++
		rows := []processSample{trustedGUI()}
		if samples == 2 {
			rows = append(rows, processSample{pid: 201, uid: testJobUID, start: "late-writer"})
		}
		return rows, nil
	}
	s.signal = func(context.Context, processSample, syscall.Signal) error { signalled++; return nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.quiesce(ctx); err != nil {
		t.Fatal(err)
	}
	if samples != 4 || signalled != 1 {
		t.Fatalf("late writer escaped settled barrier: samples=%d signals=%d", samples, signalled)
	}
}

func TestBaselineNeverAdoptsCurrentProcesses(t *testing.T) {
	valid := scopeFixture().baseline
	for name, mutate := range map[string]func(*GUIBaseline){
		"empty":         func(b *GUIBaseline) { b.Processes = nil },
		"boot-changed":  func(b *GUIBaseline) { b.Boot = "new boot" },
		"wrong-uid":     func(b *GUIBaseline) { b.JobUID++ },
		"missing-start": func(b *GUIBaseline) { b.Processes[0].Start = "" },
		"duplicate":     func(b *GUIBaseline) { b.Processes = append(b.Processes, b.Processes[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			b := valid
			b.Processes = append([]ProcessIdentity(nil), valid.Processes...)
			mutate(&b)
			if err := validateBaseline(b, testJobUID, "boot"); err == nil {
				t.Fatal("unqualified baseline accepted")
			}
		})
	}
	if err := validateBaseline(valid, testJobUID, "boot"); err != nil {
		t.Fatal(err)
	}
}

func TestSignalIdentityRejectsPIDReuseAndCrossUID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		uid   int
		start string
		want  bool
	}{
		{"job", testJobUID, "original", true},
		{"reused-job-pid", testJobUID, "replacement", false},
		{"owner", 999, "original", false},
		{"controller", 998, "original", false},
		{"root", 0, "original", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := signalIdentity([]processSample{{pid: 200, uid: tc.uid, start: tc.start}}, 200, "original", testJobUID, syscall.SIGKILL, func(pid int, sig syscall.Signal) error {
				calls++
				if pid != 200 || sig != syscall.SIGKILL {
					t.Fatal("group or unexpected signal")
				}
				return nil
			})
			if (err == nil) != tc.want || (calls == 1) != tc.want {
				t.Fatalf("signal identity decision: calls=%d err=%v", calls, err)
			}
		})
	}
	// A UID change after observation is rejected by the kernel because the helper
	// runs as the job UID. EPERM must remain uncertainty, not successful cleanup.
	err := signalIdentity([]processSample{{pid: 200, uid: testJobUID, start: "original"}}, 200, "original", testJobUID, syscall.SIGTERM, func(int, syscall.Signal) error { return syscall.EPERM })
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("kernel permission failure swallowed: %v", err)
	}
}

func TestPrivilegeDropFailsClosedBeforeJobExecution(t *testing.T) {
	for _, failure := range []string{"", "groups", "gid", "uid", "incomplete"} {
		t.Run(failure, func(t *testing.T) {
			uid, gid := 0, 0
			supplementary := []int{0, 80}
			var order []string
			deny := errors.New("credential transition refused")
			c := childCredentials{
				uid: func() int { return uid }, euid: func() int { return uid }, gid: func() int { return gid }, egid: func() int { return gid },
				groups: func(groups []int) error {
					order = append(order, "groups")
					if failure == "groups" {
						return deny
					}
					supplementary = groups
					return nil
				},
				setgid: func(value int) error {
					order = append(order, "gid")
					if failure == "gid" {
						return deny
					}
					gid = value
					return nil
				},
				setuid: func(value int) error {
					order = append(order, "uid")
					if failure == "uid" {
						return deny
					}
					if failure != "incomplete" {
						uid = value
					}
					return nil
				},
			}
			err := dropJobPrivileges(testJobUID, 502, c)
			if failure == "" {
				if err != nil || uid != testJobUID || gid != 502 || len(supplementary) != 0 || !reflect.DeepEqual(order, []string{"groups", "gid", "uid"}) {
					t.Fatalf("unsafe child credentials: uid=%d gid=%d groups=%v order=%v err=%v", uid, gid, supplementary, order, err)
				}
			} else if err == nil {
				t.Fatal("job admitted with incomplete credential transition")
			}
			if failure == "groups" && len(order) != 1 || failure == "gid" && len(order) != 2 {
				t.Fatalf("continued after credential failure: %v", order)
			}
		})
	}
}

func TestProtectedGroupNeverSignalsForeignOrBaselinePID(t *testing.T) {
	for _, p := range []processSample{{pid: 201, group: 201, uid: 999, start: "owner"}, {pid: 100, group: 201, uid: testJobUID, start: "boot:100"}} {
		r := newProcessRunner()
		r.scope = scopeFixture()
		r.scope.sample = func(context.Context) ([]processSample, error) { return []processSample{p}, nil }
		r.signalProcess = func(context.Context, processSample, syscall.Signal) error {
			t.Fatal("unsafe signal reached kernel seam")
			return nil
		}
		if err := r.cleanupProtectedGroup(201, testJobUID, func() {}, func() bool { return true }); !errors.Is(err, ErrCleanup) {
			t.Fatalf("unsafe group accepted: %v", err)
		}
	}
}

func TestNoImplicitSameUIDProductionRunner(t *testing.T) {
	// An incomplete old configuration must fail before any launchctl, credential
	// transition or system operation, even when a test happens to run as root.
	if runner, err := NewNativeRunner(Options{}); err == nil || runner != nil {
		t.Fatal("insecure same-UID production runner remains available")
	}
	runner := newProcessRunner()
	if _, err := runner.Run(context.Background(), Command{Executable: "/unused", Dir: "/"}, nil, nil); err == nil {
		t.Fatal("unbound command launcher executed")
	}
	if err := runner.Quiesce(context.Background()); err == nil {
		t.Fatal("unbound process scope claimed quiescence")
	}
}

func TestUIDScopeTerminatesOnlyOwnedSetsidHelper(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestNativeRunnerHelper$")
	child.Env = []string{"MACSERVE_RUNNER_HELPER=hang"}
	child.Dir = t.TempDir()
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill() // exact unreaped owned child, never a UID/group
			_ = child.Wait()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := identityProcesses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var identity processSample
	for _, row := range rows {
		if row.pid == child.Process.Pid {
			identity = row
			break
		}
	}
	if identity.pid == 0 || identity.group != child.Process.Pid || identity.start == "" || identity.uid != os.Geteuid() {
		t.Fatalf("helper did not enter a kernel-identified independent session: %+v", identity)
	}
	baseline := processSample{pid: 2147483647, group: 2147483647, uid: os.Geteuid(), start: "synthetic-trusted-baseline"}
	scope := &processScope{
		uid:      os.Geteuid(),
		baseline: GUIBaseline{Processes: []ProcessIdentity{{PID: baseline.pid, Start: baseline.start}}},
		interval: 5 * time.Millisecond, grace: 25 * time.Millisecond,
	}
	scope.sample = func(ctx context.Context) ([]processSample, error) {
		rows, err := identityProcesses(ctx)
		if err != nil {
			return nil, err
		}
		// Critically, no other real owner-UID process ever enters the cleanup
		// scope. The baseline is synthetic and only this owned child is real.
		filtered := []processSample{baseline}
		for _, row := range rows {
			if row.pid == child.Process.Pid {
				filtered = append(filtered, row)
			}
		}
		return filtered, nil
	}
	signalled := false
	scope.signal = func(_ context.Context, target processSample, sig syscall.Signal) error {
		if target.pid != child.Process.Pid || target.start != identity.start || target.uid != identity.uid {
			t.Fatalf("unsafe helper signal target: %+v", target)
		}
		signalled = true
		err := child.Process.Signal(sig)
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	if err := scope.quiesce(ctx); err != nil {
		t.Fatal(err)
	}
	waitErr := child.Wait()
	waited = true
	status, ok := child.ProcessState.Sys().(syscall.WaitStatus)
	if !signalled || waitErr == nil || !ok || !status.Signaled() || (status.Signal() != syscall.SIGTERM && status.Signal() != syscall.SIGKILL) {
		t.Fatalf("escaped helper survived or exited without scope cleanup: signalled=%v state=%v err=%v", signalled, child.ProcessState, waitErr)
	}
}
