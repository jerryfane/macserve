//go:build macserve_realhost && darwin

package worker

// Real-host lane attribution: two "jobs" of real process trees, run as the
// test's own (unprivileged) user, with the production kernel process table,
// executable reader and lane sampler. The test process stands in for the
// broker. Nothing runs as root or as the job account.

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRealHostLanesSplitTreesAndQuiesceOneJob(t *testing.T) {
	uid := os.Getuid()
	root := t.TempDir()
	runner := newProcessRunner()
	runner.uid = uid
	runner.workspaceRoot = root
	runner.describe = describeProcess
	runner.scope = &processScope{uid: uid, sample: identityProcesses, interval: 50 * time.Millisecond, grace: 500 * time.Millisecond,
		signal: func(ctx context.Context, p processSample, sig syscall.Signal) error {
			samples, err := identityProcesses(ctx)
			if err != nil {
				return err
			}
			return signalIdentity(samples, p.pid, p.start, uid, sig, syscall.Kill)
		}}
	started := time.Now().Add(-time.Second)
	for _, job := range []string{"job-a", "job-b"} {
		if err := os.Mkdir(filepath.Join(root, job), 0700); err != nil {
			t.Fatal(err)
		}
		runner.BeginJob(job, started)
	}
	t.Cleanup(func() { runner.EndJob("job-a"); runner.EndJob("job-b") })
	var cmds []*exec.Cmd
	start := func(job string, script string) *exec.Cmd {
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if job != "" {
			runner.laneTracker().addRoot(job, cmd.Process.Pid)
		}
		cmds = append(cmds, cmd)
		go cmd.Wait()
		return cmd
	}
	t.Cleanup(func() {
		for _, cmd := range cmds {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	})
	// Each job: a background child, a grandchild whose parent exits after
	// 0.5 s (reparented to launchd), and the root itself.
	start("job-a", "/bin/sleep 300 & (/bin/sleep 301 & /bin/sleep 0.5); exec /bin/sleep 302")
	start("job-b", "/bin/sleep 310 & (/bin/sleep 311 & /bin/sleep 0.5); exec /bin/sleep 312")
	// A process launched outside any job's lineage whose executable lies
	// in job-a's workspace is job-a's (the reparented repo-built binary).
	copy := filepath.Join(root, "job-a", "sleepcopy")
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copy, data, 0700); err != nil {
		t.Fatal(err)
	}
	start("", "("+copy+" 320 &)")
	time.Sleep(2 * time.Second)

	samples, err := identityProcesses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	runner.laneTracker().update(samples)
	byArg := map[string]string{}
	tracker := runner.laneTracker()
	tracker.mu.Lock()
	for _, p := range samples {
		if p.uid != uid || p.zombie {
			continue
		}
		label, ok := tracker.labels[processInstance{p.pid, p.start}]
		if !ok {
			continue
		}
		d, err := describeProcess(p.pid, true)
		if err != nil {
			continue
		}
		byArg[d.args] = label
		_ = d
		if d.args == "/bin/sleep\x00301" && p.parent != 1 {
			t.Logf("sleep 301 parent %d (not yet reparented)", p.parent)
		}
	}
	tracker.mu.Unlock()
	for _, p := range samples {
		if d, err := describeProcess(p.pid, true); err == nil && strings.Contains(d.args, "sleepcopy") {
			t.Logf("copy pid=%d ppid=%d uid=%d start=%s exe=%q root=%q", p.pid, p.parent, p.uid, p.start, d.executable, tracker.workspaceRoot)
		}
	}
	for args, want := range map[string]string{
		"/bin/sleep\x00300": "job-a", "/bin/sleep\x00301": "job-a", "/bin/sleep\x00302": "job-a",
		"/bin/sleep\x00310": "job-b", "/bin/sleep\x00311": "job-b", "/bin/sleep\x00312": "job-b",
		copy + "\x00320": "job-a",
	} {
		if byArg[args] != want {
			t.Errorf("%q labelled %q, want %q (labels %v)", args, byArg[args], want, byArg)
		}
	}
	if t.Failed() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runner.QuiesceJob(ctx, "job-a"); err != nil {
		t.Fatal(err)
	}
	samples, err = identityProcesses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	alive := map[string]bool{}
	for _, p := range samples {
		if p.uid != uid || p.zombie {
			continue
		}
		if d, err := describeProcess(p.pid, true); err == nil {
			alive[d.args] = true
		}
	}
	for _, n := range []int{300, 301, 302} {
		if alive["/bin/sleep\x00"+strconv.Itoa(n)] {
			t.Errorf("job-a sleep %d survived its lane quiesce", n)
		}
	}
	if alive[copy+"\x00320"] {
		t.Error("job-a workspace binary survived its lane quiesce")
	}
	for _, n := range []int{310, 311, 312} {
		if !alive["/bin/sleep\x00"+strconv.Itoa(n)] {
			t.Errorf("sibling job-b sleep %d was stopped", n)
		}
	}
	if err := runner.QuiesceJob(ctx, "job-b"); err != nil {
		t.Fatal(err)
	}
}
