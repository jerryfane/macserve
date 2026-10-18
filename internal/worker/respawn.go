package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// LaunchdService is launchd provenance recorded once, at worker-reset, for an
// audited process. It is the only thing that lets a later, unaudited job-UID
// process stand in for that audited PID after launchd relaunches it. The
// baseline file (and its digest) is never rewritten for exits or respawns.
//
// A LaunchAgent runs in domain "gui" (Aqua session) or "user" (Background
// session, LimitLoadToSessionType=Background, for example
// com.apple.TrustEvaluationAgent) and its plist is the SIP-protected
// /System/Library/LaunchAgents/<label>.plist. Domain "user" is also a per-user
// XPC service and "pid" an XPC service inside Owner's per-process domain; both
// must be bundles under root-only system paths. Executable and LaunchSHA256 pin
// the kernel executable path and the exact exec path and argv. InheritedSHA256
// pins the `inherited environment` launchd prints for the service, where a
// `launchctl setenv` in its domain appears.
//
// No identity is taken from a process environment. With SIP enabled the
// kernel withholds the KERN_PROCARGS2 environment of every CS_RESTRICT process
// from every caller, root included (xnu sysctl_procargsx); on macOS 27.0 that
// is every process under /System, /usr, /bin and /sbin.
type LaunchdService struct {
	Domain          string `json:"domain"`
	Owner           int    `json:"owner,omitempty"`
	Label           string `json:"label"`
	Path            string `json:"path"`
	Executable      string `json:"executable"`
	LaunchSHA256    string `json:"launch_sha256"`
	InheritedSHA256 string `json:"inherited_sha256"`
}

// agentProcess holds kernel facts about one live PID: kinfo_proc, csops,
// PROC_PIDPATHINFO and, from process only, the KERN_PROCARGS2 exec path and
// argv with their digest (launchArguments).
type agentProcess struct {
	start      string
	uid        int
	ppid       int
	executable string
	platform   bool
	launch     string
	// program and argv are the launch strings launch digests; adoption
	// compares them with launchd's record.
	program, argv string
}

// agentInspector is the read-only native seam: kernel facts alone (kernel),
// kernel facts with the launch arguments (process), and launchctl print of one
// exact service target (service) or domain (domain).
type agentInspector interface {
	kernel(pid int) (agentProcess, error)
	process(pid int) (agentProcess, error)
	service(ctx context.Context, target string) (launchctlprint.Snapshot, error)
	domain(ctx context.Context, target string) (launchctlprint.Domain, error)
}

func validLaunchdLabel(label string) bool {
	if label == "" || len(label) > 255 || label[0] == '.' || label[0] == '-' || strings.Contains(label, "..") {
		return false
	}
	for _, c := range label {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// systemPath accepts canonical OS paths the job UID cannot write: /System
// (except /System/Volumes), /usr (except /usr/local), /bin and /sbin.
// Platform-signed copies elsewhere (for example in a job home) keep their
// platform flag, so the path is pinned separately from the signature.
func systemPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	switch {
	case strings.HasPrefix(path, "/System/Volumes/"), strings.HasPrefix(path, "/usr/local/"):
		return false
	case strings.HasPrefix(path, "/System/"), strings.HasPrefix(path, "/usr/"), strings.HasPrefix(path, "/bin/"), strings.HasPrefix(path, "/sbin/"):
		return true
	}
	return false
}

func systemAgentPlist(label string) string {
	return "/System/Library/LaunchAgents/" + label + ".plist"
}

func (s LaunchdService) target(uid, owner int) string {
	switch s.Domain {
	case "gui":
		return "gui/" + strconv.Itoa(uid) + "/" + s.Label
	case "user":
		return "user/" + strconv.Itoa(uid) + "/" + s.Label
	case "pid":
		return "pid/" + strconv.Itoa(owner) + "/" + s.Label
	}
	return ""
}

// serviceType is launchd's `type` for s: only the system plist path is a
// LaunchAgent, every bundle an XPCService.
func (s LaunchdService) serviceType() string {
	if s.Path == systemAgentPlist(s.Label) {
		return "LaunchAgent"
	}
	return "XPCService"
}

func (s LaunchdService) valid(self int) bool {
	if !validLaunchdLabel(s.Label) || !systemPath(s.Executable) || !validLaunchDigest(s.LaunchSHA256) || !validLaunchDigest(s.InheritedSHA256) {
		return false
	}
	switch s.Domain {
	case "gui":
		return s.Owner == 0 && s.Path == systemAgentPlist(s.Label)
	case "user":
		return s.Owner == 0 && (s.Path == systemAgentPlist(s.Label) || xpcBundle(s.Path, s.Executable))
	case "pid":
		return s.Owner > 1 && s.Owner != self && xpcBundle(s.Path, s.Executable)
	}
	return false
}

func xpcBundle(path, executable string) bool {
	return systemPath(path) && strings.HasSuffix(path, ".xpc") && strings.HasPrefix(executable, path+"/")
}

func validLaunchDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

// inheritedEnvironment is the canonical form of a printed `inherited
// environment`: its KEY=VALUE entries in key order, NUL-joined. Not printed
// and empty are the same.
func inheritedEnvironment(env map[string]string) string {
	entries := make([]string, 0, len(env))
	for _, key := range slices.Sorted(maps.Keys(env)) {
		entries = append(entries, key+"="+env[key])
	}
	return strings.Join(entries, "\x00")
}

func inheritedDigest(env map[string]string) string {
	digest := sha256.Sum256([]byte(inheritedEnvironment(env)))
	return hex.EncodeToString(digest[:])
}

// launchedBy reports whether pid, with kernel facts already read, is launchd's
// running instance of s: a valid platform binary at the recorded executable,
// child of launchd, exec'd with the recorded exec path and argv, that
// launchctl print of the recorded target names as its running PID with the
// recorded launchd path, type and inherited environment. The facts are read
// again after launchctl answers and must be identical, binding that answer to
// this process instance rather than to a reused PID.
func launchedBy(ctx context.Context, agents agentInspector, uid int, s LaunchdService, owner, pid int, facts agentProcess) bool {
	if facts.uid != uid || facts.ppid != 1 || !facts.platform || facts.executable != s.Executable || facts.launch != s.LaunchSHA256 {
		return false
	}
	target := s.target(uid, owner)
	snapshot, err := agents.service(ctx, target)
	if err != nil || snapshot.Target != target || snapshot.PID != pid || snapshot.Path != s.Path || snapshot.Type != s.serviceType() || inheritedDigest(snapshot.Inherited) != s.InheritedSHA256 {
		return false
	}
	again, err := agents.process(pid)
	return err == nil && again == facts
}

// respawned removes from candidates every process that is launchd's verified
// relaunch of an absent audited process and returns those relaunches by
// audited PID. A pid-domain XPC service is looked up only in the
// domain of a present audited owner or of that owner's verified relaunch,
// never a job process. Owners may themselves be pid-domain services listed in
// any order, so passes repeat until no owner resolves; each repeated pass
// resolves at least one entry, bounding the work by len(pending)+1 passes.
func respawned(ctx context.Context, agents agentInspector, uid int, b GUIBaseline, absent map[int]string, candidates []processSample) ([]processSample, map[int]processSample) {
	current := make(map[int]int, len(b.Processes))
	var pending []ProcessIdentity
	for _, p := range b.Processes {
		if _, gone := absent[p.PID]; !gone {
			current[p.PID] = p.PID
		} else if p.Service.Domain != "" {
			pending = append(pending, p)
		}
	}
	if len(pending) == 0 {
		return candidates, nil
	}
	type candidate struct {
		sample processSample
		facts  agentProcess
		ok     bool
	}
	inspected := make([]candidate, len(candidates))
	for i, p := range candidates {
		facts, err := agents.process(p.pid)
		inspected[i] = candidate{sample: p, facts: facts, ok: err == nil && facts.start == p.start}
	}
	attempted := make([]bool, len(pending))
	relaunched := make(map[int]processSample, len(pending))
	for progress := true; progress; {
		progress = false
		for i, audited := range pending {
			if attempted[i] {
				continue
			}
			owner := 0
			if audited.Service.Domain == "pid" {
				if owner = current[audited.Service.Owner]; owner == 0 {
					continue
				}
			}
			attempted[i] = true
			for j, c := range inspected {
				if c.ok && startedAfter(c.sample.start, audited.Start) && launchedBy(ctx, agents, uid, audited.Service, owner, c.sample.pid, c.facts) {
					current[audited.PID] = c.sample.pid
					relaunched[audited.PID] = c.sample
					inspected = slices.Delete(inspected, j, j+1)
					progress = true
					break
				}
			}
		}
	}
	residual := make([]processSample, 0, len(inspected))
	for _, c := range inspected {
		residual = append(residual, c.sample)
	}
	return residual, relaunched
}

// startedAfter compares kernel start tokens ("sec:usec" on macOS).
func startedAfter(later, earlier string) bool {
	a, b := strings.Split(later, ":"), strings.Split(earlier, ":")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, errX := strconv.ParseInt(a[i], 10, 64)
		y, errY := strconv.ParseInt(b[i], 10, 64)
		if errX != nil || errY != nil {
			return false
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// describeServices records launchd provenance for audited processes that are
// verifiably system LaunchAgents or system XPC services. Anything else keeps
// no record: it may still exit without refusal, but no replacement is accepted.
func describeServices(ctx context.Context, agents agentInspector, uid int, b GUIBaseline) GUIBaseline {
	owners := make([]int, 0, len(b.Processes))
	for _, p := range b.Processes {
		owners = append(owners, p.PID)
	}
	hints := newServiceHints(agents, uid, owners)
	out := b
	out.Processes = slices.Clone(b.Processes)
	for i, p := range out.Processes {
		if ctx.Err() != nil {
			break
		}
		if s, ok := describeService(ctx, agents, uid, p, hints); ok {
			out.Processes[i].Service = s
		}
	}
	return out
}

// serviceHints names the launchd service a PID may be: the label next to it
// in the `services` table of launchctl print of the job's gui or user domain,
// or of an audited owner's pid domain (an XPC service). A table is only a
// hint; describeService takes authority from launchctl print of that exact
// service. Each domain is printed at most once.
type serviceHints struct {
	agents agentInspector
	uid    int
	owners []int
	tables map[string]map[int]string
}

func newServiceHints(agents agentInspector, uid int, owners []int) *serviceHints {
	return &serviceHints{agents: agents, uid: uid, owners: owners, tables: make(map[string]map[int]string)}
}

func (h *serviceHints) table(ctx context.Context, target string) map[int]string {
	services, ok := h.tables[target]
	if !ok {
		if d, err := h.agents.domain(ctx, target); err == nil && d.Target == target {
			services = d.Services
		}
		h.tables[target] = services
	}
	return services
}

// find returns the domain, pid-domain owner and label listed for pid: the gui
// domain, else the user domain, else the one audited owner whose pid domain
// lists it. A PID listed by several owners has no hint.
func (h *serviceHints) find(ctx context.Context, pid int) (domain string, owner int, label string, ok bool) {
	for _, domain := range []string{"gui", "user"} {
		if label, ok := h.table(ctx, domain+"/"+strconv.Itoa(h.uid))[pid]; ok {
			return domain, 0, label, true
		}
	}
	for _, o := range h.owners {
		if o == pid {
			continue
		}
		if l, listed := h.table(ctx, "pid/"+strconv.Itoa(o))[pid]; listed {
			if ok {
				return "", 0, "", false
			}
			owner, label, ok = o, l, true
		}
	}
	return "pid", owner, label, ok
}

// describeService finds the launchd service whose domain table lists p.PID,
// then requires the full relaunch rule to hold for the audited instance
// itself. The recorded inherited environment is the one launchctl prints for
// that instance.
func describeService(ctx context.Context, agents agentInspector, uid int, p ProcessIdentity, hints *serviceHints) (LaunchdService, bool) {
	facts, err := agents.process(p.PID)
	if err != nil || facts.start != p.Start {
		return LaunchdService{}, false
	}
	domain, owner, label, ok := hints.find(ctx, p.PID)
	if !ok || !validLaunchdLabel(label) {
		return LaunchdService{}, false
	}
	s := LaunchdService{Domain: domain, Owner: owner, Label: label, Executable: facts.executable, LaunchSHA256: facts.launch}
	snapshot, err := agents.service(ctx, s.target(uid, owner))
	if err != nil || snapshot.PID != p.PID {
		return LaunchdService{}, false
	}
	s.Path, s.InheritedSHA256 = snapshot.Path, inheritedDigest(snapshot.Inherited)
	return s, s.valid(p.PID) && launchedBy(ctx, agents, uid, s, owner, p.PID, facts)
}

// launchAgentInherited returns the inherited environment launchctl prints for
// p (inheritedEnvironment), whose provenance is a verified gui- or user-domain
// system LaunchAgent, after binding p's launch to launchd's record of that
// service: the exec path is its `program` and argv its `arguments` (or just
// the program when launchd infers it), as measured for all 151 running system
// LaunchAgents on macOS 26.6 and for Finder and Dock on macOS 27.0. Kernel
// facts are read again and must still carry p's start and recorded launch
// digest, which binds them to the described instance; launchd's record must
// still report p with the recorded inherited environment.
func launchAgentInherited(ctx context.Context, agents agentInspector, uid int, p ProcessIdentity) (string, bool) {
	s := p.Service
	if s.Domain != "gui" && s.Domain != "user" || s.serviceType() != "LaunchAgent" {
		return "", false
	}
	facts, err := agents.process(p.PID)
	if err != nil || facts.start != p.Start || facts.launch != s.LaunchSHA256 {
		return "", false
	}
	target := s.target(uid, 0)
	snapshot, err := agents.service(ctx, target)
	if err != nil || snapshot.Target != target || snapshot.PID != p.PID || snapshot.Path != s.Path || snapshot.Type != "LaunchAgent" || inheritedDigest(snapshot.Inherited) != s.InheritedSHA256 {
		return "", false
	}
	argv := snapshot.Arguments
	if argv == nil {
		argv = []string{snapshot.Program}
	}
	if snapshot.Program == "" || facts.program != snapshot.Program || facts.argv != strings.Join(argv, "\x00") {
		return "", false
	}
	return inheritedEnvironment(snapshot.Inherited), true
}

// domainReferences returns, per launchd domain, the inherited environment
// launchctl prints for the selected system LaunchAgents there (Finder, a
// required anchor, is one in gui). A domain whose selected agents disagree has
// no reference, so reset adopts nothing in it. Without a selected user-domain
// agent, user falls back to the gui reference minus its one SSH_AUTH_SOCK
// entry: launchd prints SSH_AUTH_SOCK as the gui (Aqua) domain environment and
// no inherited environment for user-domain agents (trustevaluationagent on
// macOS 26.6 and 27.0).
func domainReferences(ctx context.Context, agents agentInspector, uid int, b GUIBaseline) map[string]string {
	envs := make(map[string][]string, 2)
	for _, p := range b.Processes {
		if env, ok := launchAgentInherited(ctx, agents, uid, p); ok {
			envs[p.Service.Domain] = append(envs[p.Service.Domain], env)
		}
	}
	references := make(map[string]string, 2)
	for domain, list := range envs {
		if !slices.ContainsFunc(list, func(env string) bool { return env != list[0] }) {
			references[domain] = list[0]
		}
	}
	if gui, ok := references["gui"]; ok && len(envs["user"]) == 0 {
		entries := strings.Split(gui, "\x00")
		sockets := 0
		entries = slices.DeleteFunc(entries, func(e string) bool {
			socket := strings.HasPrefix(e, "SSH_AUTH_SOCK=")
			if socket {
				sockets++
			}
			return socket
		})
		if sockets == 1 {
			references["user"] = strings.Join(entries, "\x00")
		}
	}
	return references
}

// adoption is worker-reset's rule for unselected system LaunchAgents: Apple
// helpers in the job session that launchd starts on demand (MachServices) or
// keeps alive. Terminating one only makes launchd start it again when a
// surviving client looks it up, so a reset that refused every such respawn
// could not settle; one excluded from the selection would always loop.
//
// A process qualifies only if it passes the full relaunch rule against
// launchd's own record of the SIP-protected /System/Library/LaunchAgents plist
// in the job's gui or user domain (describeService: platform binary, recorded
// executable, PPID 1, launchd path and type, re-read binding), was exec'd
// with exactly the program and arguments of that record, and launchctl prints
// for it exactly the inherited environment of the selected LaunchAgents of
// its domain (launchAgentInherited, domainReferences). That last check is
// what a selected process's recorded inherited environment does: a job's
// `launchctl setenv` appears there and is refused. XPC services and anything
// in a pid domain never qualify.
//
// An unselected instance running at reset start that qualifies has its
// provenance recorded before cleanup and is terminated like every other
// unselected process (terminate); from then on launchd's relaunch of it is
// verified exactly as for a selected process, during reset or after it. A new
// process absent from reset's first snapshot that qualifies is adopted as it
// runs. adopted lists both. Outside reset nothing is adopted: there the
// baseline stays the closed audited set.
type adoption struct {
	initial   map[int]string
	terminate map[int]string
	reference map[string]string
	adopted   []ProcessIdentity
}

// qualifies returns p with its provenance when p is an adoptable system
// LaunchAgent (see adoption). hints holds no pid-domain owners.
func (a *adoption) qualifies(ctx context.Context, agents agentInspector, uid int, p processSample, hints *serviceHints) (ProcessIdentity, bool) {
	id := ProcessIdentity{PID: p.pid, Start: p.start}
	s, ok := describeService(ctx, agents, uid, id, hints)
	if !ok {
		return id, false
	}
	id.Service = s
	env, ok := launchAgentInherited(ctx, agents, uid, id)
	reference, known := a.reference[s.Domain]
	return id, ok && known && env == reference
}

// launchAgents moves new qualifying candidates out of the residual set.
func (a *adoption) launchAgents(ctx context.Context, agents agentInspector, uid int, candidates []processSample) ([]processSample, []ProcessIdentity) {
	var residual []processSample
	var adopted []ProcessIdentity
	hints := newServiceHints(agents, uid, nil)
	for _, c := range candidates {
		if start, present := a.initial[c.pid]; !present || start != c.start {
			if p, ok := a.qualifies(ctx, agents, uid, c, hints); ok {
				adopted = append(adopted, p)
				continue
			}
		}
		residual = append(residual, c)
	}
	return residual, adopted
}

// launchArguments is one process's KERN_PROCARGS2 launch: the launch digest
// and the exec path and argv strings (NUL-joined) it covers.
type launchArguments struct {
	digest, program, argv string
}

// launchIdentity digests KERN_PROCARGS2 up to the end of argv: argc, exec
// path, NUL padding, then argc argument strings. Whatever follows is never
// read: the environment, which the kernel omits for a CS_RESTRICT process
// while SIP is enabled (the buffer then ends after argv), and the per-launch
// apple[] strings.
func launchIdentity(raw []byte) (launchArguments, error) {
	bad := errors.New("unrecognized process launch arguments")
	if len(raw) < 4 {
		return launchArguments{}, bad
	}
	argc := int(binary.NativeEndian.Uint32(raw))
	executable, rest, ok := bytes.Cut(raw[4:], []byte{0})
	if !ok || len(executable) == 0 || argc < 1 || argc > 4096 {
		return launchArguments{}, bad
	}
	h := sha256.New()
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field(executable)
	field([]byte(strconv.Itoa(argc)))
	rest = bytes.TrimLeft(rest, "\x00")
	argv := make([][]byte, 0, argc)
	for range argc {
		var arg []byte
		if arg, rest, ok = bytes.Cut(rest, []byte{0}); !ok {
			return launchArguments{}, bad
		}
		field(arg)
		argv = append(argv, arg)
	}
	return launchArguments{digest: hex.EncodeToString(h.Sum(nil)), program: string(executable), argv: string(bytes.Join(argv, []byte{0}))}, nil
}

// launchdEnvironment reads the root `environment` launchctl prints for the
// job's gui and user domains: what `launchctl setenv` there changes for every
// later launch.
func launchdEnvironment(ctx context.Context, agents agentInspector, uid int) (*LaunchdEnvironment, error) {
	var env LaunchdEnvironment
	for _, d := range []struct {
		domain string
		into   *map[string]string
	}{{"gui", &env.GUI}, {"user", &env.User}} {
		target := d.domain + "/" + strconv.Itoa(uid)
		printed, err := agents.domain(ctx, target)
		if err != nil || printed.Target != target {
			return nil, errors.Join(err, errors.New("job launchd domain environment unavailable"))
		}
		*d.into = printed.Environment
		if *d.into == nil {
			*d.into = map[string]string{}
		}
	}
	return &env, nil
}
