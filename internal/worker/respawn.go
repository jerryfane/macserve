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
// Domain "gui" is a LaunchAgent whose plist is the SIP-protected
// /System/Library/LaunchAgents/<label>.plist. Domain "user" is a per-user XPC
// service and "pid" an XPC service inside Owner's per-process domain; both
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

func (s LaunchdService) serviceType() string {
	if s.Domain == "gui" {
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
		return s.Owner == 0 && xpcBundle(s.Path, s.Executable)
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
// relaunch of an absent audited process. Agents are resolved before pid-domain
// XPC children, so a child is accepted only inside the domain of a present
// audited owner or of that owner's verified relaunch, never a job process.
func respawned(ctx context.Context, agents agentInspector, uid int, b GUIBaseline, absent map[int]string, candidates []processSample) []processSample {
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
		return candidates
	}
	slices.SortStableFunc(pending, func(a, b ProcessIdentity) int {
		return boolInt(a.Service.Domain == "pid") - boolInt(b.Service.Domain == "pid")
	})
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
	for _, audited := range pending {
		owner := 0
		if audited.Service.Domain == "pid" {
			if owner = current[audited.Service.Owner]; owner == 0 {
				continue
			}
		}
		for i, c := range inspected {
			if c.ok && startedAfter(c.sample.start, audited.Start) && launchedBy(ctx, agents, uid, audited.Service, owner, c.sample.pid, c.facts) {
				current[audited.PID] = c.sample.pid
				inspected = slices.Delete(inspected, i, i+1)
				break
			}
		}
	}
	residual := make([]processSample, 0, len(inspected))
	for _, c := range inspected {
		residual = append(residual, c.sample)
	}
	return residual
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

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
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

// launchIdentity digests KERN_PROCARGS2: argc, exec path, NUL padding, argc
// argument strings, then environment strings up to the first empty string.
// The apple[] strings after it (pointer munge, ports, boot hashes) vary per
// launch and are excluded. launchctl setenv in the job's domain changes it.
func launchIdentity(raw []byte) (label, digest string, err error) {
	bad := errors.New("unrecognized process launch arguments")
	if len(raw) < 4 {
		return "", "", bad
	}
	argc := int(binary.NativeEndian.Uint32(raw))
	executable, rest, ok := bytes.Cut(raw[4:], []byte{0})
	if !ok || len(executable) == 0 || argc < 1 || argc > 4096 {
		return "", "", bad
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
	for range argc {
		var arg []byte
		if arg, rest, ok = bytes.Cut(rest, []byte{0}); !ok {
			return "", "", bad
		}
		field(arg)
	}
	for {
		var env []byte
		if env, rest, ok = bytes.Cut(rest, []byte{0}); !ok {
			return "", "", bad
		}
		if len(env) == 0 {
			break
		}
		field(env)
		if value, found := bytes.CutPrefix(env, []byte("XPC_SERVICE_NAME=")); found {
			label = string(value)
		}
	}
	return label, hex.EncodeToString(h.Sum(nil)), nil
}
