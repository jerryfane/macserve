// Package plan is the read-only part of `macserve setup`: the preflight
// checks of this Mac, the generated deploy.env and the printed plan.
//
// The package only reads. Through Probe it runs a fixed list of read-only
// commands (runner.go), lists interface addresses, lstats paths, looks up
// the invoking account and dials at most a few TCP ports on its own
// Tailscale address to find a free API port. checks/readonly enforces this
// over every file of the package and everything it calls.
package plan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"slices"
	"strings"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/setup"
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
	Nlink  uint64
}

// Probe is every host read the preflight performs. SystemProbe reads the
// real host; tests substitute fakes.
type Probe struct {
	GOOS                 string
	UID, EUID, GID, EGID int
	Environ              []string
	// Run executes one command for which AllowedCommand holds and returns
	// its standard output.
	Run func(ctx context.Context, argv []string) (string, error)
	// Addrs lists interface addresses.
	Addrs func() ([]netip.Addr, error)
	// Lstat stats a path without following a final symlink. A missing path
	// is FileInfo{} without error.
	Lstat func(path string) (FileInfo, error)
	// Owner resolves the invoking user (real UID).
	Owner func() (Account, error)
	// AdminGID resolves the "admin" group.
	AdminGID func() (uint32, error)
	// PortInUse reports whether something accepts TCP connections at ap.
	PortInUse func(ctx context.Context, ap netip.AddrPort) bool
}

// Elevated reports root, a root or set-id credential, or a sudo
// environment. Setup refuses all of them: the owner probe refuses
// evidence gathered under sudo.
func (p Probe) Elevated() bool {
	// Real IDs equal effective ones, so checking the effective IDs for 0
	// covers the real ones.
	if p.UID != p.EUID || p.GID != p.EGID || p.EUID == 0 || p.EGID == 0 {
		return true
	}
	return slices.ContainsFunc(p.Environ, func(kv string) bool { return strings.HasPrefix(kv, "SUDO_") })
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
}

// Ready reports that no check failed and the environment was generated.
func (p Plan) Ready() bool {
	return p.Environment != nil && !slices.ContainsFunc(p.Checks, func(c Check) bool { return c.Status == Fail })
}

// portCandidates is how many ports from DefaultPort the preflight tries.
const portCandidates = 16

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
		add("host.user", Fail, "running as root, set-id or under sudo", "Run macserve setup as yourself, without sudo; it asks for your password once when needed.")
		return plan
	}
	choicesOK := true
	if err := c.Validate(); err != nil {
		choicesOK = false
		add("config.choices", Fail, err.Error(), "")
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
	if out, err := run("/usr/bin/csrutil", "status"); err == nil && strings.TrimSpace(out) == "System Integrity Protection status: enabled." {
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
		add("xcode.developer_dir", Fail, "selected developer directory is not an Xcode app", "Install Xcode, then run: sudo xcode-select -s /Applications/Xcode.app")
	} else {
		plan.DeveloperDir = dir
		add("xcode.developer_dir", OK, dir, "")
		version, err := run(dir+xcodebuildSuffix, "-version")
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
		dst  *[]deploy.DirectoryRecord
		path string
		key  string
	}{
		{&dir.Users, "/Users", "UniqueID"},
		{&dir.Groups, "/Groups", "PrimaryGroupID"},
		{&dir.UserPrimaryGroups, "/Users", "PrimaryGroupID"},
	} {
		for _, node := range []string{"/Search", "."} {
			out, err := run("/usr/bin/dscl", node, "-list", q.path, q.key)
			var records []deploy.DirectoryRecord
			if err == nil {
				records, err = deploy.ParseDirectoryList(out)
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
	if dirOK && ownerOK && choicesOK {
		ids, err := PickIDs(dir, c, owner)
		if err != nil {
			add("ids.accounts", Fail, err.Error(), "Choose other account names.")
		} else {
			plan.IDs, idsOK = ids, true
			add("ids.accounts", OK, fmt.Sprintf("%s uid/gid %d, %s (%q) uid/gid %d, %s uid/gid %d with %s gid %d", c.ControllerUser, ids.ControllerUID, c.JobUser, c.JobRealName, ids.JobUID, deploy.KeyholderAccount, ids.KeyholderUID, deploy.KeyRPCGroup, ids.KeyRPCGID), "")
		}
	}

	if ownerOK {
		checkOwnerHome(p, owner, add)
	}
	checkExisting(p, add)

	if choicesOK && ownerOK && idsOK && tailnet.IsValid() && port != 0 && plan.DeveloperDir != "" {
		env, err := RenderEnvironment(EnvironmentFacts{Owner: owner, TailnetIP: tailnet, HostAddresses: hosts, Port: port, DeveloperDir: plan.DeveloperDir}, c, plan.IDs)
		if err != nil {
			add("config.environment", Fail, err.Error(), "")
		} else {
			plan.Environment, plan.HasRepository = env, c.Repository != ""
			add("config.environment", OK, "deploy.env generated and accepted by the deploy-install parser", "")
		}
	}
	return plan
}

func parseXcodeVersion(out string) (string, string, bool) {
	first, rest, ok := strings.Cut(out, "\n")
	build, _, _ := strings.Cut(strings.TrimPrefix(rest, "Build version "), "\n")
	if !ok || !strings.HasPrefix(first, "Xcode ") || !strings.HasPrefix(rest, "Build version ") || build == "" || !printable(first) || !printable(build) {
		return "", "", false
	}
	return first, build, true
}

// printable reports printable ASCII text without control characters.
func printable(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
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

// checkExisting blocks on any existing /Library/macserve. A host managed by
// other tooling (decision D12) gets that explanation; a native setup
// ledger (root:wheel 0600, one link, in root-owned directories without
// group or other write) is reported as such: `macserve setup` resumes it.
func checkExisting(p Probe, add func(id, status, detail, fix string)) {
	root, err := p.Lstat(setup.InstallRoot)
	if err != nil {
		add("setup.existing", Fail, "cannot inspect "+setup.InstallRoot+": "+err.Error(), "")
		return
	}
	if !root.Exists {
		add("setup.existing", OK, setup.InstallRoot+" does not exist yet", "")
		return
	}
	native := true
	for _, dir := range []string{setup.InstallRoot, setup.InstallRoot + "/var", setup.LedgerDir} {
		info, err := p.Lstat(dir)
		if err != nil || !info.Exists || !info.Mode.IsDir() || info.UID != 0 || info.Mode.Perm()&0o022 != 0 {
			native = false
		}
	}
	ledger, err := p.Lstat(setup.LedgerPath)
	if err != nil || !ledger.Exists || !ledger.Mode.IsRegular() || ledger.Mode.Perm() != 0o600 || ledger.UID != 0 || ledger.GID != 0 || ledger.Nlink != 1 {
		native = false
	}
	if native {
		add("setup.existing", Fail, "a native setup ledger exists at "+setup.LedgerPath, "Run macserve setup (without --plan) to resume from the ledger.")
		return
	}
	add("setup.existing", Fail, setup.InstallRoot+" exists without a native setup ledger; this Mac is managed by other tooling", "macserve setup does not change an existing installation.")
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
			b.WriteString("  # REPOSITORIES is missing: setup needs --repository OWNER/NAME:ID before install\n")
		}
	}
	b.WriteString("\nSetup steps (each recorded in " + setup.LedgerPath + "; a failed step blocks later ones)\n")
	for i, s := range setup.Steps {
		fmt.Fprintf(&b, "  %2d. %-18s %s\n", i+1, s, setup.StepSummaries[s])
	}
	if plan.Ready() {
		b.WriteString("\nResult: ready. macserve setup (without --plan) applies it, through qualification and your typed approval.\n")
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
