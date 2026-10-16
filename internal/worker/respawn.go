package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
// the kernel executable path and the exact exec path, argv and environment.
type LaunchdService struct {
	Domain       string `json:"domain"`
	Owner        int    `json:"owner,omitempty"`
	Label        string `json:"label"`
	Path         string `json:"path"`
	Executable   string `json:"executable"`
	LaunchSHA256 string `json:"launch_sha256"`
}

// agentProcess holds kernel facts about one live PID. label is only the
// XPC_SERVICE_NAME hint from the launch environment; authority comes from
// launchd's own service record.
type agentProcess struct {
	start      string
	uid        int
	ppid       int
	executable string
	platform   bool
	label      string
	launch     string
	// program, argv and env are the launch strings launch digests
	// (launchArguments); adoption compares them with launchd's record.
	program, argv, env string
}

// agentInspector is the read-only native seam: kernel facts, launchctl print
// for one exact service target, and launchd's responsible-PID hint.
type agentInspector interface {
	process(pid int) (agentProcess, error)
	service(ctx context.Context, target string) (launchctlprint.Snapshot, error)
	responsible(ctx context.Context, pid int) (int, error)
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
	if !validLaunchdLabel(s.Label) || !systemPath(s.Executable) || !validLaunchDigest(s.LaunchSHA256) {
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

// launchedBy reports whether pid, with kernel facts already read, is launchd's
// running instance of s and was launched from exactly the recorded executable,
// argv and environment. The facts are read again after launchctl answers and
// must be identical, binding that answer to this process instance rather than
// to a reused PID.
func launchedBy(ctx context.Context, agents agentInspector, uid int, s LaunchdService, owner, pid int, facts agentProcess) bool {
	if facts.uid != uid || facts.ppid != 1 || !facts.platform || facts.executable != s.Executable || facts.launch != s.LaunchSHA256 {
		return false
	}
	target := s.target(uid, owner)
	snapshot, err := agents.service(ctx, target)
	if err != nil || snapshot.Target != target || snapshot.PID != pid || snapshot.Path != s.Path || snapshot.Type != s.serviceType() {
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
	audited := make(map[int]bool, len(b.Processes))
	for _, p := range b.Processes {
		audited[p.PID] = true
	}
	out := b
	out.Processes = slices.Clone(b.Processes)
	for i, p := range out.Processes {
		if ctx.Err() != nil {
			break
		}
		if s, ok := describeService(ctx, agents, uid, p, audited); ok {
			out.Processes[i].Service = s
		}
	}
	return out
}

// describeService discovers which launchd domain reports p.PID for the label
// hinted by its launch environment, then requires the full relaunch rule to
// hold for the audited instance itself.
func describeService(ctx context.Context, agents agentInspector, uid int, p ProcessIdentity, audited map[int]bool) (LaunchdService, bool) {
	facts, err := agents.process(p.PID)
	if err != nil || facts.start != p.Start || !validLaunchdLabel(facts.label) {
		return LaunchdService{}, false
	}
	s := LaunchdService{Label: facts.label, Executable: facts.executable, LaunchSHA256: facts.launch}
	owner := 0
	found := false
	for _, domain := range []string{"gui", "user"} {
		s.Domain = domain
		if snapshot, err := agents.service(ctx, s.target(uid, 0)); err == nil && snapshot.PID == p.PID {
			s.Path, found = snapshot.Path, true
			break
		}
	}
	if !found {
		if owner, err = agents.responsible(ctx, p.PID); err != nil || !audited[owner] {
			return LaunchdService{}, false
		}
		s.Domain, s.Owner = "pid", owner
		snapshot, err := agents.service(ctx, s.target(uid, owner))
		if err != nil || snapshot.PID != p.PID {
			return LaunchdService{}, false
		}
		s.Path = snapshot.Path
	}
	return s, s.valid(p.PID) && launchedBy(ctx, agents, uid, s, owner, p.PID, facts)
}

// launchAgentEnvironment returns the domain environment (domainEnvironment)
// of p, whose provenance is a verified gui- or user-domain system LaunchAgent,
// after binding p's whole launch to launchd's record of that service: the
// exec path is its `program` and argv its `arguments` (or just the program
// when launchd infers it), as measured for all 151 running system
// LaunchAgents on macOS 26.6. Kernel facts are read again and must still
// carry p's start and recorded launch digest, which binds them to the
// described instance; launchd's record must still report p.
func launchAgentEnvironment(ctx context.Context, agents agentInspector, uid int, p ProcessIdentity) (string, bool) {
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
	if err != nil || snapshot.Target != target || snapshot.PID != p.PID || snapshot.Path != s.Path || snapshot.Type != "LaunchAgent" {
		return "", false
	}
	argv := snapshot.Arguments
	if argv == nil {
		argv = []string{snapshot.Program}
	}
	if snapshot.Program == "" || facts.program != snapshot.Program || facts.argv != strings.Join(argv, "\x00") {
		return "", false
	}
	return domainEnvironment(facts.env, snapshot.Environment)
}

// domainReferences returns, per launchd domain, the domain environment of the
// selected system LaunchAgents there (Finder, a required anchor, is one in
// gui). A domain whose selected agents disagree has no reference, so reset
// adopts nothing in it. Without a selected user-domain agent, user falls back
// to the gui reference minus the one SSH_AUTH_SOCK entry: launchd adds
// SSH_AUTH_SOCK only for the Aqua (gui) domain and otherwise launches both
// domains with the same per-user environment, in the same order (measured
// on macOS 26.6 across 138 gui and 13 user system LaunchAgents).
func domainReferences(ctx context.Context, agents agentInspector, uid int, b GUIBaseline) map[string]string {
	envs := make(map[string][]string, 2)
	for _, p := range b.Processes {
		if env, ok := launchAgentEnvironment(ctx, agents, uid, p); ok {
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
		if sockets == 1 && len(entries) != 0 {
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
// with exactly the program and arguments of that record, and was launched
// with exactly the domain environment of the selected LaunchAgents of its
// domain (launchAgentEnvironment, domainReferences). That last check is what
// a selected process's pinned launch digest does: a job's `launchctl setenv`
// reaches every later launch and is refused. XPC services and anything in a
// pid domain never qualify.
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
// LaunchAgent (see adoption).
func (a *adoption) qualifies(ctx context.Context, agents agentInspector, uid int, p processSample) (ProcessIdentity, bool) {
	id := ProcessIdentity{PID: p.pid, Start: p.start}
	s, ok := describeService(ctx, agents, uid, id, nil)
	if !ok {
		return id, false
	}
	id.Service = s
	env, ok := launchAgentEnvironment(ctx, agents, uid, id)
	reference, known := a.reference[s.Domain]
	return id, ok && known && env == reference
}

// launchAgents moves new qualifying candidates out of the residual set.
func (a *adoption) launchAgents(ctx context.Context, agents agentInspector, uid int, candidates []processSample) ([]processSample, []ProcessIdentity) {
	var residual []processSample
	var adopted []ProcessIdentity
	for _, c := range candidates {
		if start, present := a.initial[c.pid]; !present || start != c.start {
			if p, ok := a.qualifies(ctx, agents, uid, c); ok {
				adopted = append(adopted, p)
				continue
			}
		}
		residual = append(residual, c)
	}
	return residual, adopted
}

// launchArguments is one process's KERN_PROCARGS2 launch: the XPC_SERVICE_NAME
// label hint, the launch digest, and the exec path, argv and environment
// strings (NUL-joined) it covers.
type launchArguments struct {
	label, digest, program, argv, env string
}

// launchIdentity digests KERN_PROCARGS2: argc, exec path, NUL padding, argc
// argument strings, then environment strings up to the first empty string.
// The apple[] strings after it (pointer munge, ports, boot hashes) vary per
// launch and are excluded. launchctl setenv in the job's domain changes it.
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
	out := launchArguments{program: string(executable)}
	argv := make([][]byte, 0, argc)
	for range argc {
		var arg []byte
		if arg, rest, ok = bytes.Cut(rest, []byte{0}); !ok {
			return launchArguments{}, bad
		}
		field(arg)
		argv = append(argv, arg)
	}
	var environment [][]byte
	for {
		var entry []byte
		if entry, rest, ok = bytes.Cut(rest, []byte{0}); !ok {
			return launchArguments{}, bad
		}
		if len(entry) == 0 {
			break
		}
		field(entry)
		environment = append(environment, entry)
		if value, found := bytes.CutPrefix(entry, []byte("XPC_SERVICE_NAME=")); found {
			out.label = string(value)
		}
	}
	out.digest = hex.EncodeToString(h.Sum(nil))
	out.argv = string(bytes.Join(argv, []byte{0}))
	out.env = string(bytes.Join(environment, []byte{0}))
	return out, nil
}

// domainEnvironment removes from a LaunchAgent's launch environment what
// launchd adds for that one service, its own `environment` dictionary (own)
// and XPC_FLAGS, leaving what launchd takes from its domain: the per-user
// defaults (PATH, LOGNAME, USER, HOME, SHELL, TMPDIR, SSH_AUTH_SOCK in gui)
// plus anything `launchctl setenv` put there. Measured on macOS 26.6, that
// remainder is identical, in order, for every running system LaunchAgent of a
// domain (150 gui, 13 user); setenv of a dictionary key or of XPC_FLAGS does
// not reach the process, while a new name or TMPDIR does. Every dictionary
// entry must appear exactly once with its value, and XPC_FLAGS exactly once.
func domainEnvironment(env string, own map[string]string) (string, bool) {
	if own == nil || env == "" {
		return "", false
	}
	matched := make(map[string]bool, len(own))
	flags := false
	var rest []string
	for _, entry := range strings.Split(env, "\x00") {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return "", false
		}
		if want, owned := own[key]; owned {
			if value != want || matched[key] {
				return "", false
			}
			matched[key] = true
			continue
		}
		if key == "XPC_FLAGS" && !flags && xpcFlags(value) {
			flags = true
			continue
		}
		rest = append(rest, entry)
	}
	if len(matched) != len(own) || !flags || len(rest) == 0 {
		return "", false
	}
	return strings.Join(rest, "\x00"), true
}

// xpcFlags accepts launchd's per-service XPC_FLAGS value (observed: 1, 9, 19,
// 8019): 1 to 16 lowercase hexadecimal digits.
func xpcFlags(value string) bool {
	if value == "" || len(value) > 16 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
