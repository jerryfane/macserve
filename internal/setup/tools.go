package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
)

// xcodeSystemSteps are the Xcode steps the tools step runs, with the
// installed DEVELOPER_DIR's xcodebuild, in this order. Each converges, so
// an interrupted tools step runs them again.
//
// Only the two steps that write system locations run as root:
//   - -license accept records the acceptance in
//     /Library/Preferences/com.apple.dt.Xcode.plist, which only root may
//     write (Apple documents it as sudo xcodebuild -license accept);
//   - -runFirstLaunch installs Xcode's bundled system packages into
//     /Library and /System locations through installer, which needs root.
//
// -downloadComponent MetalToolchain runs as the owner: the download is
// handled by the system asset service and needs no root [INFERENCE:
// Apple's documentation shows it without sudo; unverified on a host].
var xcodeSystemSteps = []struct {
	args    []string
	timeout time.Duration
	asOwner bool
}{
	{[]string{"-license", "accept"}, 5 * time.Minute, false},
	{[]string{"-runFirstLaunch"}, 20 * time.Minute, false},
	{[]string{"-downloadComponent", "MetalToolchain"}, time.Hour, true},
}

// readConfig reads an installed configuration file: a regular single-link
// file owned by RootUID without group or other write, at most max bytes.
func (h *Helper) readConfig(name string, max int64) ([]byte, error) {
	path := h.configPath(name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	uid, _, nlink, ok := statOwner(info)
	if !ok || !info.Mode().IsRegular() || uid != h.Store.RootUID || info.Mode().Perm()&0o022 != 0 || nlink != 1 || info.Size() > max {
		return nil, fmt.Errorf("%s must be a root-owned single-link regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if opened, err := f.Stat(); err != nil || !os.SameFile(opened, info) {
		return nil, fmt.Errorf("%s changed while it was read", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is oversized", path)
	}
	return data, nil
}

// installedEnv is the deploy.env deploy-install installed, parsed. It must
// be byte-identical to the one install recorded, so DEVELOPER_DIR, the
// account IDs and the repository pins are the ones the owner confirmed,
// or, during an upgrade, to the one the keyholder migration recorded.
func (h *Helper) installedEnv(l *Ledger) (deploy.Environment, []byte, error) {
	data, err := h.readConfig("deploy.env", deploy.MaxEnvironment)
	if err != nil {
		return deploy.Environment{}, nil, err
	}
	if d := digestHex(data); d != l.record(StepInstall).Inputs["deploy.env"] {
		if rel := l.PendingRelease(); rel == nil || rel.KeyholderEnvSHA256 != d {
			return deploy.Environment{}, nil, errors.New("the installed deploy.env is not the one install recorded")
		}
	}
	e, err := deploy.ParseEnvironment(data)
	return e, data, err
}

// tools runs the Xcode steps with a fixed environment. The toolchain
// policy is checked again immediately before each command, since the run
// can take over an hour. That policy (root-owned, no symlink, nothing
// world-writable, group write only by admin) admits /Applications: its
// admin group write gives no one a path to root they lack, since every
// admin can already sudo. A failing command leaves the step running (it
// is retryable), so the next macserve setup runs it again.
func (h *Helper) tools(l *Ledger, loc LedgerLocation) (Response, error) {
	if next, _, _ := l.Next(); next.Step != StepTools {
		return Response{}, fmt.Errorf("setup continues at %s, not tools", next.Step)
	}
	e, data, err := h.installedEnv(l)
	if err != nil {
		return Response{}, err
	}
	xcodebuild := filepath.Join(e.DeveloperDir, "usr/bin/xcodebuild")
	check := func() error {
		if err := h.ToolCheck(xcodebuild, e.JobUID); err != nil {
			return fmt.Errorf("xcodebuild is not a protected toolchain executable: %w", err)
		}
		return nil
	}
	if err := check(); err != nil {
		return Response{}, err
	}
	boot, err := h.begin(l, loc, StepTools)
	if err != nil {
		return Response{}, err
	}
	for _, step := range xcodeSystemSteps {
		c := Cmd{Argv: append([]string{xcodebuild}, step.args...), Timeout: step.timeout,
			Env: []string{FixedPath, "DEVELOPER_DIR=" + e.DeveloperDir, "HOME=/private/var/root", "LANG=C", "LC_ALL=C"}}
		if step.asOwner {
			c.Env[2] = "HOME=" + h.Owner.Home
			c.Credential = &syscall.Credential{Uid: h.Owner.UID, Gid: h.Owner.GID, Groups: []uint32{h.Owner.GID}}
		}
		if err := check(); err != nil {
			return Response{}, err
		}
		if err := h.Exec(context.Background(), c); err != nil {
			return Response{}, fmt.Errorf("xcodebuild %v: %w (run macserve setup again to retry)", step.args, err)
		}
	}
	if err := h.complete(l, loc, StepTools, boot, map[string]string{"deploy.env": digestHex(data)}); err != nil {
		return Response{}, err
	}
	return Response{Done: true}, nil
}
