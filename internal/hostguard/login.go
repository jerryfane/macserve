package hostguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	cmd := exec.CommandContext(ctx, dsclPath, ".", "-read", "/Users/"+name, "AuthenticationAuthority")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 100 * time.Millisecond
	interrupted := watchCancel(cmd)
	data, err := cmd.Output()
	if err != nil && interrupted.cutShort(ctx, err) {
		// Killed at its deadline, the read observed nothing: inconclusive, not
		// a refusal. Under job load (Studio 2026-11-22 20:26Z, #215) such a
		// read cancelled every running job as a finding; the next probe 9 s
		// later read the account unchanged.
		return fmt.Errorf("job user login authority read cut short: %w", ctx.Err())
	}
	if err != nil || !bytes.Contains(data, []byte(";ShadowHash;")) {
		// Directory output and command errors can contain sensitive account data.
		return errors.New("job user not listable at login window")
	}
	return nil
}

// cancelSignal is the signal a context cancellation sends a watched command
// (watchCancel). Nothing else sends it to these commands, so a wait status
// reporting it identifies the cancellation; dscl's default action for it is
// to terminate (checked on the Studio, 2026-11-22).
const cancelSignal = syscall.SIGUSR2

// cancelWatch tells whether cmd's context cancellation ended it.
type cancelWatch struct{ cmd *exec.Cmd }

// watchCancel makes cmd's context cancellation identifiable by its wait
// status: the cancellation sends cancelSignal instead of SIGKILL; call it
// before cmd starts. A command that ignores the signal is killed by exec
// after WaitDelay and is then judged as any other failure.
func watchCancel(cmd *exec.Cmd) *cancelWatch {
	cmd.Cancel = func() error { return cmd.Process.Signal(cancelSignal) }
	return &cancelWatch{cmd: cmd}
}

// cutShort reports whether the context, not the command, ended cmd, which
// failed with err: ctx kept it from starting, or ctx's cancellation
// terminated it (its wait status reports cancelSignal). A command that
// ended any other way (an exit with any status, or another signal from
// anyone, before or after the context ended) is a result, even if ctx
// expired while its output was still drained (#219 review).
func (w *cancelWatch) cutShort(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() == nil {
		return false
	}
	if w.cmd.Process == nil {
		return errors.Is(err, ctx.Err())
	}
	if w.cmd.ProcessState == nil {
		return false
	}
	status, ok := w.cmd.ProcessState.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == cancelSignal
}
