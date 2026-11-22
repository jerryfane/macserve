package hostguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// JobLoginListable checks the job account's login authority without requesting
// credentials or changing the account. A live GUI session is checked separately.
func JobLoginListable(ctx context.Context, name string) error {
	return jobLoginListable(ctx, name, "/usr/bin/dscl")
}

func jobLoginListable(ctx context.Context, name, dsclPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.Command(dsclPath, ".", "-read", "/Users/"+name, "AuthenticationAuthority")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	data, err, cutShort := runToDeadline(ctx, cmd)
	if cutShort {
		// Still running at its deadline, the read observed nothing:
		// inconclusive, not a refusal. Under job load (Studio 2026-11-22
		// 20:26Z, #215) such a read cancelled every running job as a finding;
		// the next probe 9 s later read the account unchanged. dscl runs as
		// root here, so the job cannot stop or signal it to cause this.
		return fmt.Errorf("job user login authority read cut short: %w", ctx.Err())
	}
	if err != nil || !bytes.Contains(data, []byte(";ShadowHash;")) {
		// Directory output and command errors can contain sensitive account data.
		return errors.New("job user not listable at login window")
	}
	return nil
}

// reapPoll is how often runToDeadline checks whether its command ended;
// checkedRunning is called after each check that found it running (tests).
var (
	reapPoll       = 10 * time.Millisecond
	checkedRunning = func() {}
)

// drainGrace is how long runToDeadline keeps reading output after its
// command ended (as exec's WaitDelay).
const drainGrace = 100 * time.Millisecond

// runToDeadline runs cmd, whose Stdout and Stderr must be unset, and returns
// its stdout and its error (nil only for exit status 0). cutShort reports
// that ctx ended first: the command never started, or it was still running
// when ctx ended, so it was killed and observed nothing. A command that had
// ended by then in any way (any exit status, or any signal from anyone) is
// judged on its own status, even if a descendant still holds its output.
// It reaps the command itself, so the deadline check sees a command that
// ended but was not yet reaped as ended (#219 review).
func runToDeadline(ctx context.Context, cmd *exec.Cmd) (out []byte, err error, cutShort bool) {
	if err := ctx.Err(); err != nil {
		return nil, err, true
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err, false
	}
	defer r.Close()
	cmd.Stdout = w
	err = cmd.Start()
	w.Close()
	if err != nil {
		return nil, err, false
	}
	pid := cmd.Process.Pid
	defer cmd.Process.Release()
	read := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(r)
		read <- data
	}()
	var status syscall.WaitStatus
	for {
		// The deadline is read before the reap check, so a command found
		// running after it was still running when ctx ended.
		deadline := ctx.Err() != nil
		ended, err := reaped(pid, &status, syscall.WNOHANG)
		if err != nil {
			return nil, err, false
		}
		if ended {
			break
		}
		if deadline {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			if _, err := reaped(pid, &status, 0); err != nil {
				return nil, err, false
			}
			return nil, ctx.Err(), true
		}
		checkedRunning()
		select {
		case <-ctx.Done():
		case <-time.After(reapPoll):
		}
	}
	select {
	case out = <-read:
	case <-time.After(drainGrace):
		r.Close()
		out = <-read
	}
	if status.Exited() && status.ExitStatus() == 0 {
		return out, nil, false
	}
	return out, fmt.Errorf("command ended with wait status %#x", uint32(status)), false
}

// reaped reaps pid with wait4 options (WNOHANG or 0), retrying EINTR.
func reaped(pid int, status *syscall.WaitStatus, options int) (bool, error) {
	for {
		got, err := syscall.Wait4(pid, status, options, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return false, err
		}
		return got == pid, nil
	}
}
