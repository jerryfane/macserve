package plan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// readOnlyCommands are the only fixed commands the preflight runs, sorted.
// checks/readonly pins this file as the package's only use of os/exec, and
// TestReadOnlyCommandsGolden pins the list.
var readOnlyCommands = [][]string{
	{"/usr/bin/csrutil", "status"},
	{"/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID"},
	{"/usr/bin/dscl", ".", "-list", "/Users", "PrimaryGroupID"},
	{"/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"},
	{"/usr/bin/dscl", "/Search", "-list", "/Groups", "PrimaryGroupID"},
	{"/usr/bin/dscl", "/Search", "-list", "/Users", "PrimaryGroupID"},
	{"/usr/bin/dscl", "/Search", "-list", "/Users", "UniqueID"},
	{"/usr/bin/fdesetup", "status"},
	{"/usr/bin/fdesetup", "supportsauthrestart"},
	{"/usr/bin/sw_vers", "-buildVersion"},
	{"/usr/bin/sw_vers", "-productVersion"},
	{"/usr/bin/xcode-select", "-p"},
	{"/usr/sbin/sysctl", "-n", "hw.optional.arm64"},
}

// xcodebuildSuffix completes a developer directory to the one other
// command, `<developer dir>/usr/bin/xcodebuild -version`.
const xcodebuildSuffix = "/usr/bin/xcodebuild"

// commandEnv is the complete environment of every preflight command.
var commandEnv = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}

const (
	maxCommandOutput = 4 << 20
	commandTimeout   = 30 * time.Second
)

// AllowedCommand reports whether argv is one of the preflight's read-only
// commands.
func AllowedCommand(argv []string) bool {
	if slices.ContainsFunc(readOnlyCommands, func(c []string) bool { return slices.Equal(c, argv) }) {
		return true
	}
	if len(argv) == 2 && argv[1] == "-version" && strings.HasSuffix(argv[0], xcodebuildSuffix) {
		return validDeveloperDir(strings.TrimSuffix(argv[0], xcodebuildSuffix))
	}
	return false
}

// validDeveloperDir accepts a clean absolute Xcode app developer directory,
// not the Command Line Tools.
func validDeveloperDir(dir string) bool {
	return filepath.IsAbs(dir) && filepath.Clean(dir) == dir && strings.HasSuffix(dir, ".app/Contents/Developer") &&
		!strings.ContainsAny(dir, "\x00\n\r\t\"'`$\\{};<>!")
}

// boundedBuffer collects at most maxCommandOutput bytes.
type boundedBuffer struct {
	buf  bytes.Buffer
	over bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > maxCommandOutput {
		b.over = true
		return 0, errors.New("command output too large")
	}
	return b.buf.Write(p)
}

// command builds the process for one allowed argv: the absolute path as
// given (never looked up), the fixed environment, cwd "/", no stdin and
// bounded output. It is the package's only exec.Cmd construction. It checks
// and uses its own copy of argv, so a caller changing its slice
// concurrently cannot run something other than what was checked.
func command(ctx context.Context, argv []string) (*exec.Cmd, *boundedBuffer, error) {
	argv = slices.Clone(argv)
	if !AllowedCommand(argv) {
		return nil, nil, fmt.Errorf("refused: %q is not a read-only preflight command", argv)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = slices.Clone(commandEnv)
	if developer, ok := strings.CutSuffix(argv[0], xcodebuildSuffix); ok {
		cmd.Env = append(cmd.Env, "DEVELOPER_DIR="+developer)
	}
	cmd.Dir = "/"
	out := &boundedBuffer{}
	cmd.Stdout, cmd.Stderr = out, &boundedBuffer{}
	return cmd, out, nil
}

// runReadOnly runs one allowed command and returns its standard output.
func runReadOnly(ctx context.Context, argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd, out, err := command(ctx, argv)
	if err != nil {
		return "", err
	}
	name := filepath.Base(cmd.Path)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %v", name, err)
	}
	if out.over {
		return "", fmt.Errorf("%s: output too large", name)
	}
	return out.buf.String(), nil
}
