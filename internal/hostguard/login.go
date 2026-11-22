package hostguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync/atomic"
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

// cancelWatch records whether cmd's context cancellation killed it.
type cancelWatch struct {
	cmd    *exec.Cmd
	killed atomic.Bool
}

// watchCancel makes cmd's context cancellation observable; call it before
// cmd starts. exec calls Cancel only when the context ends before the
// process is reaped, never during the drain of its output afterwards.
func watchCancel(cmd *exec.Cmd) *cancelWatch {
	w := &cancelWatch{cmd: cmd}
	cmd.Cancel = func() error {
		err := cmd.Process.Kill()
		if err == nil {
			w.killed.Store(true)
		}
		return err
	}
	return w
}

// cutShort reports whether the context, not the command, ended cmd, which
// failed with err: ctx kept it from starting, or ctx's cancellation killed
// it while it ran. A command reaped before its context ended (an exit with
// any status, or a signal from anyone else) is a result, even if ctx expired
// while its output was still drained (#219 review).
func (w *cancelWatch) cutShort(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() == nil {
		return false
	}
	if w.cmd.Process == nil {
		return errors.Is(err, ctx.Err())
	}
	return w.killed.Load() && (w.cmd.ProcessState == nil || !w.cmd.ProcessState.Exited())
}
