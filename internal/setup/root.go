package setup

import (
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
// account of at least uid 501 whose name is a valid owner name.
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
	return Owner{UID: uint32(uid), Name: u.Username}, nil
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
		Boot: SystemBoot, Now: time.Now, Terminal: terminal, FDAWait: 30 * time.Second,
	}, nil
}

func command(ctx context.Context, c Cmd) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Env = c.Env
	cmd.Dir = "/"
	cmd.WaitDelay = time.Second
	return cmd, cancel
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

// quietCommand runs c and discards its output.
func quietCommand(ctx context.Context, c Cmd) error {
	cmd, cancel := command(ctx, c)
	defer cancel()
	return cmd.Run()
}

// Listen creates the helper socket: dir (root:RootGID 0711, refused if it
// exists otherwise or is a link) under Store.Top, a stale socket removed,
// the new socket owned by owner with mode 0600.
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
	if err := h.CheckStart(); err != nil {
		return fail(err)
	}
	if err := h.Store.EnsureStaging(); err != nil {
		return fail(err)
	}
	ln, err := h.Store.Listen(SocketDir, owner.UID)
	if err != nil {
		return fail(err)
	}
	if err := h.Serve(ln, IdleTimeout); err != nil {
		return fail(err)
	}
	return 0
}
