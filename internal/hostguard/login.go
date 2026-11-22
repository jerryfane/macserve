package hostguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
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
	data, err := cmd.Output()
	if err != nil && cutShort(ctx, cmd, err) {
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

// cutShort reports whether ctx, not the command, ended cmd, which failed with
// err: it never started because ctx was done, or ctx's cancellation killed
// it. A command that exited on its own completed whatever its status, even if
// ctx expired while its output was still drained (#219 review).
func cutShort(ctx context.Context, cmd *exec.Cmd, err error) bool {
	if ctx.Err() == nil {
		return false
	}
	if cmd.ProcessState == nil {
		return errors.Is(err, ctx.Err())
	}
	return !cmd.ProcessState.Exited()
}
