package doctor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/setup/plan"
)

// launchctlCommands are the launchctl reads doctor runs besides the setup
// preflight's commands (plan.AllowedCommand); `launchctl print gui/UID` is
// checked by launchctlGUI. checks/readonly pins this list.
var launchctlCommands = [][]string{
	{"/bin/launchctl", "print", "system/org.macserve.controller"},
	{"/bin/launchctl", "print", "system/org.macserve.maintenance"},
	{"/bin/launchctl", "print", "system/org.macserve.worker"},
	{"/bin/launchctl", "print-disabled", "system"},
}

var launchctlGUI = regexp.MustCompile(`^gui/[1-9][0-9]{0,9}$`)

// doctorEnv is the complete environment of every command.
var doctorEnv = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}

const (
	maxOutput      = 4 << 20
	commandTimeout = 30 * time.Second
)

// AllowedCommand reports whether argv is one of doctor's read-only
// commands.
func AllowedCommand(argv []string) bool {
	if plan.AllowedCommand(argv) || slices.ContainsFunc(launchctlCommands, func(c []string) bool { return slices.Equal(c, argv) }) {
		return true
	}
	return len(argv) == 3 && argv[0] == "/bin/launchctl" && argv[1] == "print" && launchctlGUI.MatchString(argv[2])
}

// SystemProbe reads the running host. FDA and GitHub stay nil: they are
// --live only. Its reads are this package's own (not plan.SystemProbe's), so
// checks/readonly can name each read's only caller.
func SystemProbe() Probe {
	return Probe{
		GOOS: runtime.GOOS, EUID: os.Geteuid(),
		Run: runReadOnly, ReadFile: readFile,
		Lstat: lstat, Addrs: interfaceAddrs, PortInUse: portInUse,
		Boot: setup.SystemBoot, Now: time.Now,
	}
}

func lstat(path string) (plan.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return plan.FileInfo{}, nil
	}
	if err != nil {
		return plan.FileInfo{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return plan.FileInfo{}, fmt.Errorf("%s: no ownership information", path)
	}
	return plan.FileInfo{Exists: true, Mode: info.Mode(), UID: st.Uid, GID: st.Gid, Nlink: uint64(st.Nlink)}, nil
}

func interfaceAddrs() ([]netip.Addr, error) {
	list, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range list {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

// portInUse dials ap once; the connection is only closed.
func portInUse(ctx context.Context, ap netip.AddrPort) bool {
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "tcp", ap.String())
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// boundedBuffer collects at most maxOutput bytes.
type boundedBuffer struct {
	buf  bytes.Buffer
	over bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > maxOutput {
		b.over = true
		return 0, errors.New("command output too large")
	}
	return b.buf.Write(p)
}

// command builds the process for one allowed argv, checked on its own
// copy: the absolute path as given, the fixed environment, cwd "/", no
// stdin and bounded output. It is the package's only exec.Cmd.
func command(ctx context.Context, argv []string) (*exec.Cmd, *boundedBuffer, error) {
	argv = slices.Clone(argv)
	if !AllowedCommand(argv) {
		return nil, nil, fmt.Errorf("refused: %q is not a read-only doctor command", argv)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = slices.Clone(doctorEnv)
	if developer, ok := strings.CutSuffix(argv[0], "/usr/bin/xcodebuild"); ok {
		cmd.Env = append(cmd.Env, "DEVELOPER_DIR="+developer)
	}
	cmd.Dir = "/"
	out := &boundedBuffer{}
	cmd.Stdout, cmd.Stderr = out, &boundedBuffer{}
	return cmd, out, nil
}

// runReadOnly runs one allowed command and returns its standard output;
// its standard error is never shown.
func runReadOnly(ctx context.Context, argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd, out, err := command(ctx, argv)
	if err != nil {
		return "", err
	}
	name := filepath.Base(cmd.Path)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s failed", name)
	}
	if out.over {
		return "", fmt.Errorf("%s: output too large", name)
	}
	return out.buf.String(), nil
}

// readFile reads a file of at most max bytes.
func readFile(path string, max int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, max)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return data, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
