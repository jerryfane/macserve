package hostguard

import (
	"bytes"
	"context"
	"errors"
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
	if err != nil || !bytes.Contains(data, []byte(";ShadowHash;")) {
		// Directory output and command errors can contain sensitive account data.
		return errors.New("job user not listable at login window")
	}
	return nil
}
