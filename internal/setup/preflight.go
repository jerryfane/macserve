// Package setup implements the native first-time setup of macserve: the
// read-only preflight and plan, generated configuration and the ordered
// setup ledger.
//
// The preflight only reads. It runs a fixed list of read-only system
// commands (see AllowedCommand), lists interface addresses, stats paths and
// dials one local TCP port; it writes, creates and starts nothing.
package setup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Account is the invoking owner.
type Account struct {
	Name string
	UID  uint32
	Home string
	GIDs []uint32
}

// FileInfo is what preflight needs from lstat.
type FileInfo struct {
	Exists bool
	Mode   fs.FileMode
	UID    uint32
	GID    uint32
}

// Probe is every host read the preflight performs. SystemProbe reads the
// real host; tests substitute fakes. No field can change host state.
type Probe struct {
	GOOS      string
	UID, EUID int
	Environ   []string
	// Run executes one command for which AllowedCommand holds and returns
	// its standard output.
	Run func(ctx context.Context, argv []string) (string, error)
	// Addrs lists interface addresses.
	Addrs func() ([]netip.Addr, error)
	// Lstat stats a path without following a final symlink.
	Lstat func(path string) (FileInfo, error)
	// Owner resolves the invoking user (real UID).
	Owner func() (Account, error)
	// AdminGID resolves the "admin" group.
	AdminGID func() (uint32, error)
	// PortInUse reports whether something accepts TCP connections at ap.
	PortInUse func(ctx context.Context, ap netip.AddrPort) bool
}

// Fixed read-only commands. xcodebuild -version is the only other command;
// its path is derived from the selected developer directory.
var readOnlyCommands = [][]string{
	{"/usr/bin/sw_vers", "-productVersion"},
	{"/usr/bin/sw_vers", "-buildVersion"},
	{"/usr/sbin/sysctl", "-n", "hw.optional.arm64"},
	{"/usr/bin/csrutil", "status"},
	{"/usr/bin/fdesetup", "status"},
	{"/usr/bin/fdesetup", "supportsauthrestart"},
	{"/usr/bin/xcode-select", "-p"},
	{"/usr/bin/dscl", "/Search", "-list", "/Users", "UniqueID"},
	{"/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"},
	{"/usr/bin/dscl", "/Search", "-list", "/Groups", "PrimaryGroupID"},
	{"/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID"},
	{"/usr/bin/dscl", "/Search", "-list", "/Users", "PrimaryGroupID"},
	{"/usr/bin/dscl", ".", "-list", "/Users", "PrimaryGroupID"},
}

// AllowedCommand reports whether argv is one of the preflight's read-only
// commands. The system runner refuses anything else before executing.
func AllowedCommand(argv []string) bool {
	for _, c := range readOnlyCommands {
		if slices.Equal(c, argv) {
			return true
		}
	}
	if len(argv) == 2 && argv[1] == "-version" && strings.HasSuffix(argv[0], "/usr/bin/xcodebuild") {
		return validDeveloperDir(strings.TrimSuffix(argv[0], "/usr/bin/xcodebuild"))
	}
	return false
}

// validDeveloperDir accepts a clean absolute Xcode app developer directory,
// not the Command Line Tools.
func validDeveloperDir(dir string) bool {
	return filepath.IsAbs(dir) && filepath.Clean(dir) == dir && strings.HasSuffix(dir, ".app/Contents/Developer") &&
		!strings.ContainsAny(dir, "\x00\n\t\"'`$\\{};<>!")
}

const maxCommandOutput = 4 << 20

type boundedBuffer struct {
	bytes.Buffer
	over bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxCommandOutput {
		b.over = true
		return 0, errors.New("command output too large")
	}
	return b.Buffer.Write(p)
}

// SystemProbe reads the running host.
func SystemProbe() Probe {
	return Probe{
		GOOS:    runtime.GOOS,
		UID:     os.Getuid(),
		EUID:    os.Geteuid(),
		Environ: os.Environ(),
		Run:     runReadOnly,
		Addrs: func() ([]netip.Addr, error) {
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
		},
		Lstat: func(path string) (FileInfo, error) {
			info, err := os.Lstat(path)
			if errors.Is(err, fs.ErrNotExist) {
				return FileInfo{}, nil
			}
			if err != nil {
				return FileInfo{}, err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return FileInfo{}, fmt.Errorf("%s: no ownership information", path)
			}
			return FileInfo{Exists: true, Mode: info.Mode(), UID: st.Uid, GID: st.Gid}, nil
		},
		Owner: func() (Account, error) {
			u, err := user.LookupId(strconv.Itoa(os.Getuid()))
			if err != nil {
				return Account{}, err
			}
			uid, err := strconv.ParseUint(u.Uid, 10, 32)
			if err != nil {
				return Account{}, err
			}
			a := Account{Name: u.Username, UID: uint32(uid), Home: u.HomeDir}
			gids, err := u.GroupIds()
			if err != nil {
				return Account{}, err
			}
			for _, g := range gids {
				n, err := strconv.ParseInt(g, 10, 64)
				if err != nil {
					return Account{}, fmt.Errorf("group id %q: %w", g, err)
				}
				if n >= 0 && n <= 1<<32-1 {
					a.GIDs = append(a.GIDs, uint32(n))
				}
			}
			return a, nil
		},
		AdminGID: func() (uint32, error) {
			g, err := user.LookupGroup("admin")
			if err != nil {
				return 0, err
			}
			n, err := strconv.ParseUint(g.Gid, 10, 32)
			return uint32(n), err
		},
		PortInUse: func(ctx context.Context, ap netip.AddrPort) bool {
			d := net.Dialer{Timeout: time.Second}
			conn, err := d.DialContext(ctx, "tcp", ap.String())
			if err == nil {
				conn.Close()
				return true
			}
			// Only a refused connection proves the port is free.
			return !errors.Is(err, syscall.ECONNREFUSED)
		},
	}
}

// runReadOnly runs one allowed command with a fixed environment and cwd.
func runReadOnly(ctx context.Context, argv []string) (string, error) {
	if !AllowedCommand(argv) {
		return "", fmt.Errorf("refused: %q is not a read-only preflight command", argv)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	if strings.HasSuffix(argv[0], "/usr/bin/xcodebuild") {
		cmd.Env = append(cmd.Env, "DEVELOPER_DIR="+strings.TrimSuffix(argv[0], "/usr/bin/xcodebuild"))
	}
	cmd.Dir = "/"
	var stdout, stderr boundedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %v", filepath.Base(argv[0]), err)
	}
	if stdout.over {
		return "", fmt.Errorf("%s: output too large", filepath.Base(argv[0]))
	}
	return stdout.String(), nil
}

// Check statuses.
const (
	OK   = "ok"
	Warn = "warn"
	Fail = "fail"
)

// Check is one preflight result with a fixed ID.
type Check struct {
	ID     string
	Status string
	Detail string
	Fix    string
}

// Plan is the read-only result of `macserve setup --plan`.
type Plan struct {
	Checks        []Check
	Owner         Account
	MacOS         string
	FileVaultOn   bool
	AuthRestart   bool
	DeveloperDir  string
	Xcode         string
	IDs           IDs
	Environment   []byte // generated deploy.env; nil if it could not be generated
	HasRepository bool
	ExistingSetup bool // a native setup ledger exists
}

// Ready reports that no check failed and the environment was generated.
func (p Plan) Ready() bool {
	for _, c := range p.Checks {
		if c.Status == Fail {
			return false
		}
	}
	return p.Environment != nil
}

// Preflight checks this Mac and generates the configuration setup would
// install. It only reads host state.
func Preflight(ctx context.Context, p Probe, c Choices) Plan {
	var plan Plan
	add := func(id, status, detail, fix string) {
		plan.Checks = append(plan.Checks, Check{ID: id, Status: status, Detail: detail, Fix: fix})
	}
	if p.GOOS != "darwin" {
		add("host.macos", Fail, "this is "+p.GOOS+", not macOS", "Run macserve setup on the Mac that will build.")
		return plan
	}
	if p.Elevated() {
		add("host.user", Fail, "running as root or under sudo", "Run macserve setup as yourself, without sudo; it asks for your password once when needed.")
		return plan
	}
	run := func(argv ...string) (string, error) { return p.Run(ctx, argv) }

	owner, err := p.Owner()
	ownerOK := err == nil
	if err != nil {
		add("host.user", Fail, "cannot resolve the invoking user: "+err.Error(), "")
	} else {
		plan.Owner = owner
		add("host.user", OK, fmt.Sprintf("you are %s (uid %d); setup runs as you, not root", owner.Name, owner.UID), "")
		if admin, err := p.AdminGID(); err != nil {
			add("host.admin", Fail, "cannot resolve the admin group: "+err.Error(), "")
		} else if !slices.Contains(owner.GIDs, admin) {
			add("host.admin", Fail, owner.Name+" is not an administrator", "Use an administrator account (System Settings → Users & Groups).")
		} else {
			add("host.admin", OK, owner.Name+" is an administrator", "")
		}
	}

	if version, err := run("/usr/bin/sw_vers", "-productVersion"); err != nil {
		add("host.macos", Fail, "cannot read the macOS version: "+err.Error(), "")
	} else {
		build, _ := run("/usr/bin/sw_vers", "-buildVersion")
		plan.MacOS = strings.TrimSpace(version)
		if b := strings.TrimSpace(build); b != "" {
			plan.MacOS += " (" + b + ")"
		}
		add("host.macos", OK, "macOS "+plan.MacOS, "")
	}
	if out, err := run("/usr/sbin/sysctl", "-n", "hw.optional.arm64"); err == nil && strings.TrimSpace(out) == "1" {
		add("host.arch", OK, "Apple silicon", "")
	} else {
		add("host.arch", Fail, "not Apple silicon", "macserve needs an Apple-silicon Mac.")
	}
	if out, err := run("/usr/bin/csrutil", "status"); err == nil && strings.HasPrefix(strings.TrimSpace(out), "System Integrity Protection status: enabled.") {
		add("host.sip", OK, "System Integrity Protection enabled", "")
	} else {
		add("host.sip", Fail, "System Integrity Protection is not fully enabled", "Turn SIP on from macOS Recovery (csrutil enable).")
	}
	fv, fvErr := run("/usr/bin/fdesetup", "status")
	switch strings.TrimSpace(fv) {
	case "FileVault is Off.":
		add("host.filevault", OK, "FileVault is off; the setup restart needs nobody at the Mac", "")
	case "FileVault is On.":
		plan.FileVaultOn = true
		ar, err := run("/usr/bin/fdesetup", "supportsauthrestart")
		plan.AuthRestart = err == nil && strings.TrimSpace(ar) == "true"
		if plan.AuthRestart {
			add("host.filevault", Warn, "FileVault is on; the setup restart will ask for your password once (authenticated restart supported)", "")
		} else {
			add("host.filevault", Warn, "FileVault is on and authenticated restart is not supported; someone must unlock the Mac at its screen after the setup restart", "")
		}
	default:
		detail := "FileVault state unknown"
		if fvErr != nil {
			detail += ": " + fvErr.Error()
		}
		add("host.filevault", Warn, detail, "A restart during setup may need you at the Mac.")
	}

	if out, err := run("/usr/bin/xcode-select", "-p"); err != nil {
		add("xcode.developer_dir", Fail, "no developer directory selected", "Install Xcode, then run: sudo xcode-select -s /Applications/Xcode.app")
	} else if dir := strings.TrimSpace(out); !validDeveloperDir(dir) {
		add("xcode.developer_dir", Fail, "selected developer directory is not an Xcode app: "+dir, "Install Xcode, then run: sudo xcode-select -s /Applications/Xcode.app")
	} else {
		plan.DeveloperDir = dir
		add("xcode.developer_dir", OK, dir, "")
		version, err := run(dir+"/usr/bin/xcodebuild", "-version")
		name, build, ok := parseXcodeVersion(version)
		if err != nil || !ok {
			add("xcode.version", Warn, "Xcode did not report its version", "Open Xcode once and accept its license; setup step 4 also does this.")
		} else {
			plan.Xcode = name + " (" + build + ")"
			add("xcode.version", OK, plan.Xcode, "")
		}
	}

	var tailnet netip.Addr
	var hosts []string
	if addrs, err := p.Addrs(); err != nil {
		add("net.tailnet", Fail, "cannot list interface addresses: "+err.Error(), "")
	} else if tailnet, hosts, err = SelectAddresses(addrs); err != nil {
		add("net.tailnet", Fail, err.Error(), "Install Tailscale, log in, and run setup again.")
	} else {
		add("net.tailnet", OK, "Tailscale address "+tailnet.String(), "")
		add("net.host_addresses", OK, strings.Join(hosts, ", "), "")
	}
	var port uint16
	if tailnet.IsValid() {
		for candidate := uint16(DefaultPort); candidate < DefaultPort+portCandidates; candidate++ {
			if !p.PortInUse(ctx, netip.AddrPortFrom(tailnet, candidate)) {
				port = candidate
				break
			}
		}
		if port == 0 {
			add("net.port", Fail, fmt.Sprintf("ports %d-%d are in use on %s", DefaultPort, DefaultPort+portCandidates-1, tailnet), "Free port 8443 and run setup again.")
		} else {
			add("net.port", OK, fmt.Sprintf("port %d is free", port), "")
		}
	}

	var dir Directory
	dirOK := true
	for _, q := range []struct {
		dst  *[]DirectoryRecord
		path string
		key  string
	}{
		{&dir.Users, "/Users", "UniqueID"},
		{&dir.Groups, "/Groups", "PrimaryGroupID"},
		{&dir.UserPrimaryGroups, "/Users", "PrimaryGroupID"},
	} {
		for _, node := range []string{"/Search", "."} {
			out, err := run("/usr/bin/dscl", node, "-list", q.path, q.key)
			var records []DirectoryRecord
			if err == nil {
				records, err = ParseDirectoryList(out)
			}
			if err != nil {
				dirOK = false
				add("ids.accounts", Fail, "cannot enumerate "+q.path+" "+q.key+" in "+node+": "+err.Error(), "")
				break
			}
			*q.dst = append(*q.dst, records...)
		}
		if !dirOK {
			break
		}
	}
	idsOK := false
	if dirOK && ownerOK {
		ids, err := PickIDs(dir, c, owner)
		if err != nil {
			add("ids.accounts", Fail, err.Error(), "Choose other account names.")
		} else {
			plan.IDs, idsOK = ids, true
			add("ids.accounts", OK, fmt.Sprintf("%s uid/gid %d, %s (%q) uid/gid %d", c.ControllerUser, ids.ControllerUID, c.JobUser, c.JobRealName, ids.JobUID), "")
		}
	}

	if ownerOK {
		checkOwnerHome(p, owner, add)
	}
	plan.ExistingSetup = checkExisting(p, add)

	if ownerOK && idsOK && tailnet.IsValid() && port != 0 && plan.DeveloperDir != "" {
		env, _, err := RenderEnvironment(EnvironmentFacts{Owner: owner, TailnetIP: tailnet, HostAddresses: hosts, Port: port, DeveloperDir: plan.DeveloperDir}, c, plan.IDs)
		if err != nil {
			add("config.environment", Fail, err.Error(), "")
		} else {
			plan.Environment, plan.HasRepository = env, c.Repository != ""
			add("config.environment", OK, "deploy.env generated and accepted by the deploy-install parser", "")
		}
	}
	return plan
}

// Elevated reports root or a sudo environment. Setup refuses both: the
// owner probe refuses evidence gathered under sudo.
func (p Probe) Elevated() bool {
	if p.UID == 0 || p.EUID == 0 {
		return true
	}
	for _, kv := range p.Environ {
		if strings.HasPrefix(kv, "SUDO_") {
			return true
		}
	}
	return false
}

func parseXcodeVersion(out string) (string, string, bool) {
	first, rest, ok := strings.Cut(out, "\n")
	build, _, _ := strings.Cut(strings.TrimPrefix(rest, "Build version "), "\n")
	if !ok || !strings.HasPrefix(first, "Xcode ") || !strings.HasPrefix(rest, "Build version ") || build == "" {
		return "", "", false
	}
	return first, build, true
}

// Groups every local account on macOS belongs to, so also the build
// account: everyone, staff and localaccounts.
var sharedGroups = []uint32{12, 20, 61}

// checkOwnerHome applies docs/install.md: the owner's home is 0700, or 0750
// with an owner-private group that is not staff and excludes the job
// account. Setup never changes it. ACLs are not inspected here;
// qualification's owner-home category measures actual access.
func checkOwnerHome(p Probe, owner Account, add func(id, status, detail, fix string)) {
	fix := "Run: chmod 700 " + owner.Home + " (setup never changes your home's permissions)"
	info, err := p.Lstat(owner.Home)
	switch {
	case err != nil:
		add("owner.home", Fail, "cannot inspect "+owner.Home+": "+err.Error(), "")
	case !info.Exists || !info.Mode.IsDir() || info.UID != owner.UID:
		add("owner.home", Fail, owner.Home+" is not a directory you own", "")
	case info.Mode.Perm()&0o007 != 0:
		add("owner.home", Fail, owner.Home+" is open to every account", fix)
	case info.Mode.Perm()&0o070 != 0 && slices.Contains(sharedGroups, info.GID):
		add("owner.home", Fail, fmt.Sprintf("%s is open to group %d, which the build account will belong to", owner.Home, info.GID), fix)
	case info.Mode.Perm()&0o070 != 0:
		add("owner.home", Warn, fmt.Sprintf("%s is open to group %d; it must exclude the build account (qualification checks this)", owner.Home, info.GID), fix)
	default:
		add("owner.home", OK, owner.Home+" is private to you (ACLs are checked by qualification)", "")
	}
}

// checkExisting refuses a /Library/macserve that has no native setup
// ledger: such a host is managed by other tooling (decision D12).
func checkExisting(p Probe, add func(id, status, detail, fix string)) bool {
	root, err := p.Lstat(InstallRoot)
	if err != nil {
		add("setup.existing", Fail, "cannot inspect "+InstallRoot+": "+err.Error(), "")
		return false
	}
	if !root.Exists {
		add("setup.existing", OK, InstallRoot+" does not exist yet", "")
		return false
	}
	ledger, err := p.Lstat(LedgerPath)
	if err == nil && root.Mode.IsDir() && ledger.Exists && ledger.Mode.IsRegular() && ledger.UID == 0 {
		add("setup.existing", Warn, "a native setup ledger exists at "+LedgerPath+"; the values below are for a fresh install", "Resuming a setup is not available in this release.")
		return true
	}
	add("setup.existing", Fail, InstallRoot+" exists without a native setup ledger; this Mac is managed by other tooling", "macserve setup does not change an existing installation.")
	return false
}

// WritePlan prints the plan. It returns an error only if w fails.
func WritePlan(w io.Writer, plan Plan) error {
	var b bytes.Buffer
	b.WriteString("macserve setup --plan: read-only. Nothing was written, created or started.\n\nChecks\n")
	for _, c := range plan.Checks {
		fmt.Fprintf(&b, "  %-4s  %-20s %s\n", c.Status, c.ID, c.Detail)
		if c.Fix != "" && c.Status != OK {
			fmt.Fprintf(&b, "        %-20s fix: %s\n", "", c.Fix)
		}
	}
	if plan.Environment != nil {
		b.WriteString("\nGenerated deploy.env (validated with the deploy-install parser; installed in step 3)\n")
		for _, line := range strings.SplitAfter(string(plan.Environment), "\n") {
			if line != "" {
				b.WriteString("  " + line)
			}
		}
		if !plan.HasRepository {
			b.WriteString("  # REPOSITORIES is added in step 2 (connect-github), or pass --repository OWNER/NAME:ID\n")
		}
	}
	b.WriteString("\nSetup steps (each recorded in " + LedgerPath + "; a failed step blocks later ones)\n")
	for i, s := range Steps {
		fmt.Fprintf(&b, "  %2d. %-18s %s\n", i+1, s, StepSummaries[s])
	}
	if plan.Ready() {
		b.WriteString("\nResult: ready. This release does not apply the plan yet.\n")
	} else {
		n := 0
		for _, c := range plan.Checks {
			if c.Status == Fail {
				n++
			}
		}
		fmt.Fprintf(&b, "\nResult: blocked (%d failed check(s)).\n", n)
	}
	_, err := w.Write(b.Bytes())
	return err
}
