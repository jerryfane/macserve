package setup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/assets"
	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/hostguard"
)

// RootUsage is the only argv `macserve _setup-root` accepts. The digest is
// the one the wizard computed of this binary (or the owner's --sha256).
const RootUsage = "Usage: sudo /path/to/macserve _setup-root --sha256 LOWERCASE_HEX (started by macserve setup)"

// ParseRootArgs accepts exactly --sha256 and a lowercase sha256.
func ParseRootArgs(args []string) (string, error) {
	if len(args) != 2 || args[0] != "--sha256" || !sha256Hex.MatchString(args[1]) {
		return "", errors.New(RootUsage)
	}
	return args[1], nil
}

// SudoOwner resolves SUDO_UID: a canonical decimal, not root, a local
// account of at least uid 501 whose name is a valid owner name, with its
// primary group and an absolute home directory.
func SudoOwner(sudoUID string, lookup func(string) (*user.User, error)) (Owner, error) {
	uid, err := strconv.ParseUint(sudoUID, 10, 32)
	if sudoUID == "" || err != nil || strconv.FormatUint(uid, 10) != sudoUID || uid < 501 {
		return Owner{}, errors.New("run macserve setup from your own login; the root helper needs SUDO_UID to name you")
	}
	u, err := lookup(sudoUID)
	if err != nil {
		return Owner{}, fmt.Errorf("SUDO_UID %s: %w", sudoUID, err)
	}
	if !ownerName.MatchString(u.Username) {
		return Owner{}, fmt.Errorf("account name %q is not supported", u.Username)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil || strconv.FormatUint(gid, 10) != u.Gid || !filepath.IsAbs(u.HomeDir) || filepath.Clean(u.HomeDir) != u.HomeDir {
		return Owner{}, fmt.Errorf("account %s has no usable primary group or home directory", u.Username)
	}
	return Owner{UID: uint32(uid), GID: uint32(gid), Name: u.Username, Home: u.HomeDir}, nil
}

// RootHelper is the production helper.
func RootHelper(owner Owner, sha string, terminal io.Writer) (*Helper, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, name := range assets.DeployNames {
		data, err := fs.ReadFile(assets.Deploy, name)
		if err != nil {
			return nil, err
		}
		files[name] = data
	}
	return &Helper{
		Store: SystemStore(), Root: deploy.Prefix, Owner: owner, SHA256: sha, Executable: exe, Assets: files,
		Install: deploy.Install, Exec: terminalCommand(terminal), Probe: quietCommand,
		ConsoleUID: hostguard.ConsoleUID, ToolCheck: hostguard.ToolchainExecutable,
		Boot: SystemBoot, Now: time.Now, Terminal: terminal, TerminalCheck: stdoutTerminal, FDAWait: 30 * time.Second,
		Output: outputCommand, Qualify: &SystemQualifier{Root: deploy.Prefix, Staging: StagingDir},
	}, nil
}

func command(ctx context.Context, c Cmd) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Env = c.Env
	cmd.Dir = "/"
	cmd.WaitDelay = time.Second
	if c.Credential != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: c.Credential}
	}
	return cmd, cancel
}

// stdoutTerminal requires the helper's stdout (the owner's terminal, where
// deploy-install's account helper asks for the build account's password)
// to be a terminal.
func stdoutTerminal() error {
	info, err := os.Stdout.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeCharDevice == 0 {
		return errors.New("deploy-install asks for the build account's password on this terminal; run macserve setup with its output on the terminal, not into a pipe or file")
	}
	return nil
}

// terminalCommand runs c with output to the terminal and no stdin.
func terminalCommand(terminal io.Writer) func(context.Context, Cmd) error {
	return func(ctx context.Context, c Cmd) error {
		cmd, cancel := command(ctx, c)
		defer cancel()
		cmd.Stdout, cmd.Stderr = terminal, terminal
		return cmd.Run()
	}
}

// outputCommand runs c and returns its standard output (at most 1 MiB)
// and exit status; err is set only when it could not run or timed out.
func outputCommand(ctx context.Context, c Cmd) ([]byte, int, error) {
	cmd, cancel := command(ctx, c)
	defer cancel()
	var out bytes.Buffer
	cmd.Stdout = &limitedBuffer{b: &out, max: 1 << 20}
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return out.Bytes(), exit.ExitCode(), nil
	}
	if err != nil {
		return nil, 0, err
	}
	return out.Bytes(), 0, nil
}

// limitedBuffer keeps the first max bytes and reports an error beyond.
type limitedBuffer struct {
	b   *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.b.Len()+len(p) > l.max {
		return 0, errors.New("command output exceeds its bound")
	}
	return l.b.Write(p)
}

// quietCommand runs c and discards its output.
func quietCommand(ctx context.Context, c Cmd) error {
	cmd, cancel := command(ctx, c)
	defer cancel()
	return cmd.Run()
}

// Listen creates the helper socket: dir (root:RootGID 0711, refused if it
// exists otherwise or is a link) under Store.Top, a stale socket removed
// (callers hold the helper Lock, so no live helper owns it), the new socket
// owned by owner with mode 0600.
func (s Store) Listen(dir string, owner uint32) (*net.UnixListener, error) {
	if err := s.ensureDir(dir, 0o711); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, SocketName)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(true)
	if err := errors.Join(os.Chown(path, int(owner), int(s.RootGID)), os.Chmod(path, 0o600)); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// RunRoot is `macserve _setup-root`: the one root helper `macserve setup`
// starts through sudo. It refuses anything but darwin, real and effective
// root, the fixed argv, a SUDO_UID that is the console user, an approved
// qualification and (D12) an installation without a native ledger. It then
// clears its environment, serves the fixed verbs on the helper socket to
// that user only and exits when the wizard disconnects or after
// IdleTimeout.
func RunRoot(args []string, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, "macserve _setup-root:", err)
		return 1
	}
	if runtime.GOOS != "darwin" {
		return fail(errors.New("requires macOS"))
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return fail(errors.New("requires real and effective root; macserve setup starts it with sudo"))
	}
	sha, err := ParseRootArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	owner, err := SudoOwner(os.Getenv("SUDO_UID"), user.LookupId)
	if err != nil {
		return fail(err)
	}
	console, err := hostguard.ConsoleUID()
	if err != nil {
		return fail(err)
	}
	if console != owner.UID {
		return fail(errors.New("run macserve setup from the login of the user at this Mac's screen"))
	}
	os.Clearenv()
	if err := errors.Join(os.Setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"), os.Chdir("/")); err != nil {
		return fail(err)
	}
	syscall.Umask(0o077)
	h, err := RootHelper(owner, sha, stdout)
	if err != nil {
		return fail(err)
	}
	if err := h.ServeRoot(SocketDir, IdleTimeout); err != nil {
		return fail(err)
	}
	return 0
}

// ServeRoot takes the exclusive helper lock in dir and holds it until the
// session ends, so a second helper refuses before it reads the ledger or
// touches the socket. Then it checks the start conditions, creates the
// staging directory and the socket, and serves the wizard.
func (h *Helper) ServeRoot(dir string, idle time.Duration) error {
	lock, err := h.Store.Lock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := h.CheckStart(); err != nil {
		return err
	}
	if err := h.Store.EnsureStaging(); err != nil {
		return err
	}
	ln, err := h.Store.Listen(dir, h.Owner.UID)
	if err != nil {
		return err
	}
	return h.Serve(ln, idle)
}
