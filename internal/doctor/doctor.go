// Package doctor is `macserve doctor`: a fixed list of read-only checks of an
// installed macserve, each with a fixed ID, a status, a one-line detail and a
// one-line fix. It never prints secrets or raw command output.
//
// checks/readonly proves that `macserve doctor` without --live reaches only
// this package's reads (Probe from SystemProbe). The two checks that need an
// effect, the transient launchd Full Disk Access probe and the GitHub App
// call, are Probe.FDA and Probe.GitHub; only `sudo macserve doctor --live`
// sets them, outside that proof.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/setup/plan"
)

// Status of one check.
type Status string

const (
	Pass    Status = "pass"
	Warn    Status = "warn"
	Fail    Status = "fail"
	Unknown Status = "unknown"
)

// IDs are the fixed check IDs, in report order.
var IDs = []string{
	"host.macos", "host.arch", "host.sip", "host.filevault", "xcode.pins", "net.tailnet",
	"release.bytes", "fs.protect", "tcc.fda", "session.job", "persistence", "qual.state",
	"svc.state", "health", "github.app", "disk", "setup.ledger",
}

// Check is one result.
type Check struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// Report is the whole result; Schema versions the --json form.
type Report struct {
	Schema  int            `json:"schema"`
	Root    bool           `json:"root"`
	Live    bool           `json:"live"`
	Checks  []Check        `json:"checks"`
	Summary map[Status]int `json:"summary"`
}

const reportSchema = 1

// ExitCode is 1 when a check failed and 0 otherwise; unknown checks (not
// run without sudo or --live) do not fail the report.
func (r Report) ExitCode() int {
	if r.Summary[Fail] > 0 {
		return 1
	}
	return 0
}

// Paths of the installed deployment.
const (
	Root          = "/Library/macserve"
	Binary        = Root + "/bin/macserve"
	EnvFile       = Root + "/config/deploy.env"
	ProfilesFile  = Root + "/config/profiles.json"
	HealthFile    = Root + "/health/current.json"
	SecretsDir    = Root + "/var/controller/secrets"
	Qualification = Root + "/config/qualification.json"
	Anchor        = Root + "/config/activation-anchor.json"
	Console       = "/dev/console"
	launchDaemons = "/Library/LaunchDaemons/"
	// MaxBinary bounds the installed binary doctor hashes.
	MaxBinary = 256 << 20
	maxConfig = 1 << 20
)

// Labels are the three macserve services.
var Labels = []string{"org.macserve.controller", "org.macserve.maintenance", "org.macserve.worker"}

// Probe is every host read doctor performs. SystemProbe reads the real
// host; tests substitute fakes.
type Probe struct {
	GOOS string
	EUID int
	// Run runs one allowed read-only command (AllowedCommand) and returns
	// its standard output.
	Run func(ctx context.Context, argv []string) (string, error)
	// ReadFile reads at most max bytes of a file; fs.ErrNotExist and
	// fs.ErrPermission pass through.
	ReadFile func(path string, max int64) ([]byte, error)
	// Lstat is plan's lstat: a missing path is FileInfo{} without error.
	Lstat     func(path string) (plan.FileInfo, error)
	Addrs     func() ([]netip.Addr, error)
	PortInUse func(ctx context.Context, ap netip.AddrPort) bool
	Boot      func() (setup.Boot, error)
	Now       func() time.Time
	// FDA runs the transient launchd Full Disk Access probe; nil unless
	// --live.
	FDA func() (granted bool, detail string, err error)
	// GitHub checks the App and its installations; nil unless --live.
	GitHub func(ctx context.Context) (detail string, err error)
}

// Options are the command-line inputs.
type Options struct {
	// ReleaseSHA256 is the digest the owner verified (--sha256); empty
	// uses SHA256Sums, then the digest setup recorded.
	ReleaseSHA256 string
	// SHA256Sums is the path of the release's SHA256SUMS (--sha256sums).
	SHA256Sums string
}

// releaseAsset is the SHA256SUMS entry of the installed binary.
const releaseAsset = "macserve-darwin-arm64"

var sumsLine = regexp.MustCompile(`^([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)$`)

// sumsDigest returns releaseAsset's digest from SHA256SUMS text.
func sumsDigest(data []byte) (string, error) {
	found := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		m := sumsLine.FindStringSubmatch(line)
		if m == nil {
			return "", errors.New("SHA256SUMS has a malformed line")
		}
		if m[2] == releaseAsset {
			if found != "" {
				return "", errors.New("SHA256SUMS lists " + releaseAsset + " twice")
			}
			found = m[1]
		}
	}
	if found == "" {
		return "", errors.New("SHA256SUMS does not list " + releaseAsset)
	}
	return found, nil
}

// state is what the checks share.
type state struct {
	ctx      context.Context
	p        Probe
	o        Options
	results  map[string]Check
	env      *deploy.Environment
	envErr   error
	health   *health.Health
	hErr     error
	ledger   *setup.Ledger
	ledgErr  error
	disabled map[string]bool // print-disabled system: label -> disabled
}

func (s *state) set(id string, status Status, detail, fix string) {
	s.results[id] = Check{ID: id, Status: status, Detail: detail, Fix: fix}
}

// Run performs every check.
func Run(ctx context.Context, p Probe, o Options) Report {
	s := &state{ctx: ctx, p: p, o: o, results: map[string]Check{}}
	report := Report{Schema: reportSchema, Root: p.EUID == 0, Live: p.FDA != nil || p.GitHub != nil, Summary: map[Status]int{Pass: 0, Warn: 0, Fail: 0, Unknown: 0}}
	if p.GOOS != "darwin" {
		s.set("host.macos", Fail, "this is "+p.GOOS+", not macOS", "Run macserve doctor on the Mac that builds.")
	} else {
		s.load()
		s.host()
		s.xcode()
		s.network()
		s.release()
		s.protect()
		s.fda()
		s.session()
		s.healthChecks()
		s.qualification()
		s.services()
		s.github()
		s.setupLedger()
	}
	for _, id := range IDs {
		c, ok := s.results[id]
		if !ok {
			c = Check{ID: id, Status: Unknown, Detail: "not checked on this host"}
		}
		report.Checks = append(report.Checks, c)
		report.Summary[c.Status]++
	}
	return report
}

func (s *state) run(argv ...string) (string, error) { return s.p.Run(s.ctx, argv) }

const (
	fixSetup = "Run macserve setup."
	fixSudo  = "Run sudo macserve doctor for this check."
	fixLive  = "Run sudo macserve doctor --live for this check."
)

// unreadable explains a file doctor could not read.
func (s *state) unreadable(id, what string, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.set(id, Fail, what+" is missing: macserve is not installed", fixSetup)
	case errors.Is(err, fs.ErrPermission) && s.p.EUID != 0:
		s.set(id, Unknown, what+" is readable only by root", fixSudo)
	case errors.Is(err, fs.ErrPermission):
		s.set(id, Fail, what+" cannot be read", "Run sudo macserve doctor; if it persists, run macserve setup.")
	default:
		s.set(id, Fail, what+" is invalid or unreadable", "Reinstall with macserve setup.")
	}
}

func (s *state) load() {
	if data, err := s.p.ReadFile(EnvFile, deploy.MaxEnvironment); err != nil {
		s.envErr = err
	} else if e, err := deploy.ParseEnvironment(data); err != nil {
		s.envErr = errors.New("invalid deploy.env")
	} else {
		s.env = &e
	}
	if data, err := s.p.ReadFile(HealthFile, maxConfig); err != nil {
		s.hErr = err
	} else {
		var h health.Health
		if err := json.Unmarshal(data, &h); err != nil {
			s.hErr = errors.New("invalid health file")
		} else {
			s.health = &h
		}
	}
	s.ledger, s.ledgErr = s.readLedger()
	if out, err := s.run("/bin/launchctl", "print-disabled", "system"); err == nil {
		s.disabled = parseDisabled(out)
	}
}

func (s *state) readLedger() (*setup.Ledger, error) {
	var last error
	for _, path := range []string{setup.LedgerPath, setup.StagingDir + "/ledger.json"} {
		data, err := s.p.ReadFile(path, setup.MaxLedger)
		if err != nil {
			last = err
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		var l setup.Ledger
		if err := json.Unmarshal(data, &l); err != nil || l.Schema != 1 || len(l.Records) != len(setup.Steps) {
			return nil, errors.New("invalid setup ledger")
		}
		return &l, nil
	}
	return nil, last
}

// parseDisabled reads `launchctl print-disabled system` lines of the form
// `"label" => disabled|enabled|true|false`.
func parseDisabled(out string) map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		label, value, ok := strings.Cut(strings.TrimSpace(line), "=>")
		if !ok {
			continue
		}
		label = strings.Trim(strings.TrimSpace(label), `"`)
		switch strings.TrimSpace(value) {
		case "disabled", "true":
			m[label] = true
		case "enabled", "false":
			m[label] = false
		}
	}
	return m
}

func (s *state) host() {
	if v, err := s.run("/usr/bin/sw_vers", "-productVersion"); err != nil {
		s.set("host.macos", Fail, "cannot read the macOS version", "")
	} else {
		s.set("host.macos", Pass, "macOS "+strings.TrimSpace(v), "")
	}
	if out, err := s.run("/usr/sbin/sysctl", "-n", "hw.optional.arm64"); err == nil && strings.TrimSpace(out) == "1" {
		s.set("host.arch", Pass, "Apple silicon", "")
	} else {
		s.set("host.arch", Fail, "not Apple silicon", "macserve needs a Mac with Apple silicon.")
	}
	if out, err := s.run("/usr/bin/csrutil", "status"); err != nil {
		s.set("host.sip", Unknown, "cannot read System Integrity Protection status", "")
	} else if strings.Contains(out, "enabled.") {
		s.set("host.sip", Pass, "System Integrity Protection is on", "")
	} else {
		s.set("host.sip", Fail, "System Integrity Protection is not fully on", "macserve needs SIP on: turn it back on in macOS Recovery (csrutil enable).")
	}
	out, err := s.run("/usr/bin/fdesetup", "status")
	switch {
	case err != nil:
		s.set("host.filevault", Unknown, "cannot read FileVault status", "")
	case strings.Contains(out, "FileVault is Off"):
		s.set("host.filevault", Pass, "FileVault is off: macserve restarts without you", "")
	default:
		auth, err := s.run("/usr/bin/fdesetup", "supportsauthrestart")
		if err == nil && strings.TrimSpace(auth) == "true" {
			s.set("host.filevault", Pass, "FileVault is on and supports authenticated restart", "")
		} else {
			s.set("host.filevault", Warn, "FileVault is on without authenticated restart", "A reboot will need you at the Mac to unlock the disk.")
		}
	}
}

// pins lists the Xcode pins of every profile and template.
func (s *state) pins() ([]model.Xcode, error) {
	data, err := s.p.ReadFile(ProfilesFile, maxConfig)
	if err != nil {
		return nil, err
	}
	var f struct {
		Profiles  []model.Profile  `json:"profiles"`
		Templates []model.Template `json:"templates"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, errors.New("invalid profiles.json")
	}
	var out []model.Xcode
	for _, p := range f.Profiles {
		out = append(out, p.Xcode)
	}
	for _, t := range f.Templates {
		out = append(out, t.Xcode)
	}
	return out, nil
}

func (s *state) xcode() {
	pins, err := s.pins()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			s.unreadable("xcode.pins", "profiles.json", err)
		} else {
			s.set("xcode.pins", Fail, err.Error(), fixSetup)
		}
		return
	}
	dir, err := s.run("/usr/bin/xcode-select", "-p")
	if err != nil {
		s.set("xcode.pins", Fail, "no Xcode is selected", "Install Xcode and run sudo xcode-select -s /Applications/Xcode.app.")
		return
	}
	out, err := s.run(strings.TrimSpace(dir)+"/usr/bin/xcodebuild", "-version")
	if err != nil {
		s.set("xcode.pins", Fail, "the selected developer directory is not an Xcode app", "Install Xcode and run sudo xcode-select -s /Applications/Xcode.app.")
		return
	}
	installed := parseXcode(out)
	if len(pins) == 0 {
		s.set("xcode.pins", Warn, "Xcode "+installed.Version+" ("+installed.Build+"); no build profile or template pins it yet", "Run macserve setup.")
		return
	}
	for _, pin := range pins {
		if pin != installed {
			s.set("xcode.pins", Fail, "installed Xcode "+installed.Version+" ("+installed.Build+") differs from the pinned "+pin.Version+" ("+pin.Build+")", "Xcode changed: run macserve setup requalify.")
			return
		}
	}
	s.set("xcode.pins", Pass, "Xcode "+installed.Version+" ("+installed.Build+") matches every pin", "")
}

// parseXcode reads `xcodebuild -version`: "Xcode 16.2\nBuild version 16C5032a".
func parseXcode(out string) model.Xcode {
	var x model.Xcode
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "Xcode "); ok {
			x.Version = strings.TrimSpace(v)
		} else if b, ok := strings.CutPrefix(line, "Build version "); ok {
			x.Build = strings.TrimSpace(b)
		}
	}
	return x
}

func (s *state) network() {
	if s.env == nil {
		s.unreadable("net.tailnet", "deploy.env", s.envErr)
		return
	}
	ip, err := netip.ParseAddr(s.env.TailnetIP)
	if err != nil {
		s.set("net.tailnet", Fail, "deploy.env has no valid TAILNET_IP", fixSetup)
		return
	}
	addrs, err := s.p.Addrs()
	if err != nil || !slices.Contains(addrs, ip) {
		s.set("net.tailnet", Fail, ip.String()+" is not assigned to this Mac", "Tailscale is logged out or changed address: log in to Tailscale again.")
		return
	}
	ap := netip.AddrPortFrom(ip, s.env.Port)
	if !s.p.PortInUse(s.ctx, ap) {
		s.set("net.tailnet", Warn, ap.String()+" is assigned but nothing accepts connections", "The controller is not running; see svc.state.")
		return
	}
	s.set("net.tailnet", Pass, ap.String()+" accepts connections", "")
}

// recordedBinary is the digest setup recorded for the installed binary:
// install's, or the last macserve upgrade's.
func (s *state) recordedBinary() string {
	if s.ledger == nil {
		return ""
	}
	for i := len(s.ledger.Releases) - 1; i >= 0; i-- {
		if s.ledger.Releases[i].Status == setup.StatusDone {
			return s.ledger.Releases[i].SHA256
		}
	}
	for i := len(s.ledger.Records) - 1; i >= 0; i-- {
		if d := s.ledger.Records[i].Inputs["macserve"]; d != "" {
			return d
		}
	}
	return ""
}

func (s *state) binaryDigest() (string, error) {
	data, err := s.p.ReadFile(Binary, MaxBinary)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

func (s *state) release() {
	digest, err := s.binaryDigest()
	if err != nil {
		s.unreadable("release.bytes", Binary, err)
		return
	}
	want, source := s.o.ReleaseSHA256, "the release digest you gave"
	if want == "" && s.o.SHA256Sums != "" {
		data, err := s.p.ReadFile(s.o.SHA256Sums, 64<<10)
		if err == nil {
			want, err = sumsDigest(data)
		}
		if err != nil {
			s.set("release.bytes", Fail, "cannot use --sha256sums: "+err.Error(), "Pass the SHA256SUMS of the release you installed.")
			return
		}
		source = "the release's SHA256SUMS"
	}
	if want == "" {
		want, source = s.recordedBinary(), "the digest setup recorded"
	}
	switch {
	case want == "" && s.ledger == nil && s.p.EUID != 0:
		s.set("release.bytes", Unknown, "installed binary sha256 "+digest+"; nothing to compare it with", "Run macserve doctor --sha256sums SHA256SUMS with the release's SHA256SUMS, or sudo macserve doctor.")
	case want == "":
		s.set("release.bytes", Unknown, "installed binary sha256 "+digest+"; setup recorded no digest", "Run macserve doctor --sha256sums SHA256SUMS with the release's SHA256SUMS.")
	case want != digest:
		s.set("release.bytes", Fail, "installed binary sha256 "+digest+" is not "+source, "Installed binary is not the release you installed: reinstall it with macserve setup.")
	default:
		s.set("release.bytes", Pass, "installed binary matches "+source, "")
	}
}

// protected is one path of the installation and how it must look.
type protected struct {
	path    string
	dir     bool
	private bool // no access for others
}

var protectedPaths = []protected{
	{path: Root, dir: true},
	{path: Root + "/bin", dir: true},
	{path: Binary},
	{path: Root + "/config", dir: true},
	{path: EnvFile},
	{path: ProfilesFile},
	{path: SecretsDir, dir: true, private: true},
}

func (s *state) protect() {
	paths := slices.Clone(protectedPaths)
	for _, label := range Labels {
		paths = append(paths, protected{path: launchDaemons + label + ".plist"})
	}
	for _, want := range paths {
		info, err := s.p.Lstat(want.path)
		switch {
		case err != nil:
			s.set("fs.protect", Unknown, "cannot inspect "+want.path, fixSudo)
			return
		case !info.Exists:
			s.set("fs.protect", Fail, want.path+" is missing", fixSetup)
			return
		case want.dir != info.Mode.IsDir() || !want.dir && !info.Mode.IsRegular():
			s.set("fs.protect", Fail, want.path+" has the wrong type", "Reinstall with macserve setup.")
			return
		case info.Mode.Perm()&0o022 != 0 || want.private && info.Mode.Perm()&0o007 != 0:
			s.set("fs.protect", Fail, want.path+" has mode "+fmt.Sprintf("%04o", info.Mode.Perm()), "Reinstall with macserve setup; something changed its permissions.")
			return
		case !want.private && info.UID != 0 || want.private && s.env != nil && info.UID != s.env.ControllerUID || !want.dir && info.Nlink != 1:
			s.set("fs.protect", Fail, want.path+" is not owned by root alone", "Reinstall with macserve setup; something changed its owner.")
			return
		}
	}
	s.set("fs.protect", Pass, "the installation, its secrets and the service plists are protected", "")
}

func (s *state) fda() {
	if s.p.FDA == nil {
		s.set("tcc.fda", Unknown, "Full Disk Access is checked only from launchd context", fixLive)
		return
	}
	granted, detail, err := s.p.FDA()
	switch {
	case err != nil:
		s.set("tcc.fda", Unknown, "the launchd Full Disk Access probe did not complete", "Run sudo macserve doctor --live again.")
	case granted:
		s.set("tcc.fda", Pass, detail, "")
	default:
		s.set("tcc.fda", Fail, detail, "Open System Settings → Privacy & Security → Full Disk Access, remove and re-add /Library/macserve/bin/macserve.")
	}
}

func (s *state) session() {
	if s.env == nil {
		s.unreadable("session.job", "deploy.env", s.envErr)
		return
	}
	if _, err := s.run("/bin/launchctl", "print", "gui/"+strconv.FormatUint(uint64(s.env.JobUID), 10)); err != nil {
		s.set("session.job", Fail, "the build account "+s.env.JobUser+" has no GUI session", "Log in to macserve build at the login window, then use Switch User to return.")
		return
	}
	console, err := s.p.Lstat(Console)
	if err != nil || !console.Exists {
		s.set("session.job", Unknown, "cannot read the console owner", "")
		return
	}
	if hostguard.ConsoleAdmissible(console.UID, s.env.OwnerUID) != nil {
		s.set("session.job", Fail, "the build account is in the foreground", "Use Switch User to return to your own login; leave macserve build logged in.")
		return
	}
	s.set("session.job", Pass, "the build account is logged in in the background", "")
}

// blockerText maps a gate blocker to a sentence.
var blockerText = map[string]string{
	"isolation_unavailable":                "the boundary check is stale or failed",
	"persistence_attestation_unavailable":  "the persistence attestation is not valid",
	"worker_admission_inconclusive":        "the worker refused an inconclusive admission",
	"service_disk_budget_exceeded":         "macserve uses more than its disk budget",
	"service_disk_reservation_unavailable": "macserve's disk budget has no room for one more job",
	"host_memory_pressure":                 "the Mac is under memory pressure",
}

func (s *state) healthChecks() {
	if s.health == nil {
		for _, id := range []string{"health", "persistence", "disk"} {
			s.unreadable(id, "the maintenance health file", s.hErr)
		}
		return
	}
	h, now := *s.health, s.p.Now()
	var blockers []string
	if h.Schema != 3 || (s.env != nil && h.JobUID != s.env.JobUID) || !h.BoundaryValidated || h.CheckedAt.After(now.Add(5*time.Second)) || now.Sub(h.CheckedAt) > 45*time.Second || !h.ExpiresAt.After(now) || h.ExpiresAt.Sub(h.CheckedAt) > 45*time.Second {
		blockers = append(blockers, "isolation_unavailable")
	}
	persistOK := h.PersistenceValid && !h.PersistenceNeedsReview && !h.PersistenceLastVerified.IsZero() && !h.PersistenceLastVerified.After(now)
	if !persistOK {
		blockers = append(blockers, "persistence_attestation_unavailable")
	}
	if h.AdmissionInconclusive != "" {
		blockers = append(blockers, "worker_admission_inconclusive")
	}
	switch {
	case h.AccountedBytes < 0 || h.AccountedBytes > health.ServiceBudgetBytes:
		blockers = append(blockers, "service_disk_budget_exceeded")
		s.set("disk", Fail, fmt.Sprintf("macserve accounts %d GiB of its %d GiB budget", h.AccountedBytes>>30, health.ServiceBudgetBytes>>30), "Remove old jobs' evidence or wait for retention cleanup.")
	case h.AccountedBytes > health.ServiceBudgetBytes-health.JobReservationBytes:
		blockers = append(blockers, "service_disk_reservation_unavailable")
		s.set("disk", Warn, fmt.Sprintf("macserve accounts %d GiB of its %d GiB budget; no room for one more job", h.AccountedBytes>>30, health.ServiceBudgetBytes>>30), "Wait for retention cleanup before the next build.")
	default:
		s.set("disk", Pass, fmt.Sprintf("macserve accounts %d GiB of its %d GiB budget", h.AccountedBytes>>30, health.ServiceBudgetBytes>>30), "")
	}
	if h.MemoryPressure {
		blockers = append(blockers, "host_memory_pressure")
	}
	switch {
	case persistOK:
		s.set("persistence", Pass, "the persistence attestation is valid", "")
	case h.PersistenceNeedsReview:
		s.set("persistence", Fail, "the persistence attestation needs review", "Review the new launch items, then run macserve setup requalify.")
	default:
		s.set("persistence", Fail, "the persistence attestation is not valid", "Run macserve setup requalify.")
	}
	if len(blockers) == 0 {
		s.set("health", Pass, "maintenance health is fresh and admits jobs", "")
		return
	}
	var text []string
	for _, b := range blockers {
		text = append(text, blockerText[b])
	}
	fix := "Start the services with macserve setup, or wait for maintenance."
	if blockers[0] != "isolation_unavailable" {
		fix = "Resolve: " + strings.Join(blockers, ", ") + "."
	}
	s.set("health", Fail, strings.Join(text, "; "), fix)
}

func (s *state) qualification() {
	for _, path := range []string{Qualification, Anchor} {
		info, err := s.p.Lstat(path)
		if err != nil {
			s.set("qual.state", Unknown, "cannot inspect "+path, fixSudo)
			return
		}
		if !info.Exists {
			s.set("qual.state", Fail, path+" is missing: qualification is not approved", "Continue with macserve setup.")
			return
		}
	}
	if s.ledger == nil || s.ledger.Approval == nil {
		if s.ledger == nil && s.p.EUID != 0 {
			s.set("qual.state", Pass, "qualification and activation anchor exist; the approval needs sudo to check", "")
		} else {
			s.set("qual.state", Pass, "qualification and activation anchor exist", "")
		}
		return
	}
	boot, err := s.p.Boot()
	if err != nil {
		s.set("qual.state", Unknown, "cannot read this boot's identity", "")
		return
	}
	if s.ledger.Approval.Boot != boot {
		s.set("qual.state", Warn, "qualification is approved; the approval was given in an earlier boot", "After a reboot run macserve setup requalify.")
		return
	}
	s.set("qual.state", Pass, "qualification is approved in this boot", "")
}

func (s *state) services() {
	if s.disabled == nil {
		s.set("svc.state", Unknown, "cannot read launchd's disabled services", "")
		return
	}
	loaded, disabled := 0, 0
	for _, label := range Labels {
		if info, err := s.p.Lstat(launchDaemons + label + ".plist"); err != nil || !info.Exists {
			s.set("svc.state", Fail, launchDaemons+label+".plist is missing", fixSetup)
			return
		}
		if _, err := s.run("/bin/launchctl", "print", "system/"+label); err == nil {
			loaded++
		}
		if s.disabled[label] {
			disabled++
		}
	}
	var foreign []string
	for label := range s.disabled {
		if strings.HasPrefix(label, "org.macserve.") && !slices.Contains(Labels, label) && label != setup.FDALabel {
			foreign = append(foreign, label)
		}
	}
	slices.Sort(foreign)
	n := len(Labels)
	switch {
	case len(foreign) > 0:
		s.set("svc.state", Fail, "foreign launchd overrides: "+strings.Join(foreign, ", "), "Remove them with sudo launchctl enable/disable; macserve installs only its three services.")
	case loaded == n && disabled == 0:
		s.set("svc.state", Pass, "the three services are loaded and enabled", "")
	case loaded == 0 && disabled == n:
		s.set("svc.state", Warn, "the three services are installed and disabled", "Continue with macserve setup to start them.")
	default:
		s.set("svc.state", Fail, fmt.Sprintf("%d of %d services loaded, %d disabled", loaded, n, disabled), "Continue with macserve setup; it starts or stops all three together.")
	}
}

func (s *state) github() {
	if s.p.GitHub == nil {
		s.set("github.app", Unknown, "the GitHub App is checked only with --live", fixLive)
		return
	}
	detail, err := s.p.GitHub(s.ctx)
	if err != nil {
		s.set("github.app", Fail, err.Error(), "App uninstalled or repository removed: run sudo macserve connect-github.")
		return
	}
	s.set("github.app", Pass, detail, "")
}

func (s *state) setupLedger() {
	if s.ledger == nil {
		if errors.Is(s.ledgErr, fs.ErrNotExist) {
			s.set("setup.ledger", Fail, "no setup ledger: setup has not started", fixSetup)
		} else {
			s.unreadable("setup.ledger", "the setup ledger", s.ledgErr)
		}
		return
	}
	for _, r := range s.ledger.Records {
		if r.Status == setup.StatusFailed {
			s.set("setup.ledger", Fail, "setup step "+string(r.Step)+" failed", "Resume with macserve setup.")
			return
		}
	}
	for _, r := range s.ledger.Records {
		if r.Status != setup.StatusDone {
			s.set("setup.ledger", Warn, "setup continues at step "+string(r.Step)+" ("+string(r.Status)+")", "Resume with macserve setup.")
			return
		}
	}
	s.set("setup.ledger", Pass, "every setup step is done", "")
}
