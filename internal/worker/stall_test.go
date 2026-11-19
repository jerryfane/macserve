//go:build darwin || linux

package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// stallScript ignores SIGTERM and blocks in sleep, after starting a child
// that leaves its process group (as coreutils timeout puts a hung `simctl
// ui` in a group of its own), ignores SIGTERM and blocks too. It prints the
// child's PID, then nothing more.
const stallScript = `#!/bin/bash
trap '' TERM
perl -e '$| = 1; setpgrp(0, 0); $SIG{TERM} = "IGNORE"; print "escaped=$$\n"; sleep 1000'
`

var escapedPID = regexp.MustCompile(`escaped=(\d+)`)

// #201 acceptance (herdrup j_8798460a, 2026-11-19): a script job whose
// output stops is ended as stalled, and its hung children, inside and
// outside the command's process group, are SIGKILLed before the
// finalization's census, which then confirms cleanup. The script and its
// children run as real processes; the job's run command alone is watched
// (the default ten minutes, cut to a second here), never prepare.
func TestStalledScriptJobEndsWithConfirmedCleanup(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl is required to start a child outside the command's group")
	}
	native := newProcessRunner()
	native.command = func(c Command) *exec.Cmd { return exec.Command(c.Executable, c.Args...) }
	native.termGrace = 50 * time.Millisecond
	native.drainTimeout = 100 * time.Millisecond
	var output bytes.Buffer
	escaped := 0
	runner := &fakeRunner{}
	runner.hook = func(ctx context.Context, c Command, stdout, stderr io.Writer) (bool, ProcessResult, error) {
		if c.StallTimeout != 0 && c.Executable != "/bin/bash" {
			t.Errorf("%s %q is watched for output (%s); only the run command is", c.Executable, c.Args, c.StallTimeout)
		}
		if c.Executable != "/bin/bash" {
			return false, ProcessResult{}, nil
		}
		if c.StallTimeout != model.DefaultStallSeconds*time.Second {
			t.Errorf("script stall limit %s, want the script default %ds", c.StallTimeout, model.DefaultStallSeconds)
		}
		c.StallTimeout = time.Second
		result, err := native.Run(ctx, c, io.MultiWriter(stdout, &output), stderr)
		if m := escapedPID.FindStringSubmatch(output.String()); m != nil {
			escaped, _ = strconv.Atoi(m[1])
		}
		return true, result, err
	}
	// The census: the job account's quiesce finds no process of the job.
	runner.quiesce = func(ctx context.Context) error {
		if escaped == 0 {
			return nil
		}
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if err := syscall.Kill(escaped, 0); errors.Is(err, syscall.ESRCH) {
				return nil
			}
		}
		return fmt.Errorf("%w: escaped child %d of the stalled job is still running", ErrContamination, escaped)
	}
	t.Cleanup(func() {
		if escaped > 0 {
			_ = syscall.Kill(escaped, syscall.SIGKILL)
		}
	})
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": scriptConfig, "Tools/ci/duo-screenshots.sh": stallScript})
	job := testTemplateJob(t, model.SimulatorScript, scriptShard)
	// Without the watchdog the job would run to this bound, not stall.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := engine.Execute(ctx, job, source, bytes.NewReader(data), nil, nil)
	if escaped == 0 {
		t.Fatalf("the script's child never started: %q", output.String())
	}
	if !errors.Is(err, ErrStalled) || result.State != model.Cancelled || !strings.HasPrefix(result.Reason, "stalled") {
		t.Fatalf("stalled job ended %s (%q): %v", result.State, result.Reason, err)
	}
	if !result.CleanupOK {
		t.Fatalf("stalled job's cleanup was not confirmed: %q: %v", result.Reason, err)
	}
	if len(simctl(runner, "shutdown")) == 0 {
		t.Fatal("the stalled job's simulator was not shut down")
	}
}
