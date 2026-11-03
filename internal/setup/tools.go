package setup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
)

// xcodeSystemSteps are the Xcode steps the tools step runs system-wide,
// with the installed DEVELOPER_DIR's xcodebuild, in this order. Each
// converges, so an interrupted tools step runs them again.
var xcodeSystemSteps = []struct {
	args    []string
	timeout time.Duration
}{
	{[]string{"-license", "accept"}, 5 * time.Minute},
	{[]string{"-runFirstLaunch"}, 20 * time.Minute},
	{[]string{"-downloadComponent", "MetalToolchain"}, time.Hour},
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

// installedEnv is the deploy.env deploy-install installed, parsed.
func (h *Helper) installedEnv() (deploy.Environment, []byte, error) {
	data, err := h.readConfig("deploy.env", deploy.MaxEnvironment)
	if err != nil {
		return deploy.Environment{}, nil, err
	}
	e, err := deploy.ParseEnvironment(data)
	return e, data, err
}

// tools runs the Xcode system steps as root with a fixed environment. A
// failing command leaves the step running (it is retryable), so the next
// macserve setup runs it again.
func (h *Helper) tools(l *Ledger, loc LedgerLocation) (Response, error) {
	if next, _, _ := l.Next(); next.Step != StepTools {
		return Response{}, fmt.Errorf("setup continues at %s, not tools", next.Step)
	}
	e, data, err := h.installedEnv()
	if err != nil {
		return Response{}, err
	}
	xcodebuild := filepath.Join(e.DeveloperDir, "usr/bin/xcodebuild")
	if err := h.ToolCheck(xcodebuild, e.JobUID); err != nil {
		return Response{}, fmt.Errorf("xcodebuild is not a protected toolchain executable: %w", err)
	}
	boot, err := h.begin(l, loc, StepTools)
	if err != nil {
		return Response{}, err
	}
	env := []string{FixedPath, "DEVELOPER_DIR=" + e.DeveloperDir, "HOME=/private/var/root", "LANG=C", "LC_ALL=C"}
	for _, step := range xcodeSystemSteps {
		argv := append([]string{xcodebuild}, step.args...)
		if err := h.Exec(context.Background(), Cmd{Argv: argv, Env: env, Timeout: step.timeout}); err != nil {
			return Response{}, fmt.Errorf("xcodebuild %v: %w (run macserve setup again to retry)", step.args, err)
		}
	}
	if err := h.complete(l, loc, StepTools, boot, map[string]string{"deploy.env": digestHex(data)}); err != nil {
		return Response{}, err
	}
	return Response{Done: true}, nil
}
