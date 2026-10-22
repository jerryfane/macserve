package worker

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Developer-tool launches (v0.1.14). After quiesce terminates a build's
// processes, launchd starts the CoreSimulator and CoreDevice stack again on
// its own in the job's user domain and in pid domains (macOS 27.0, Xcode 27:
// CoreSimulatorService, CoreDeviceService, SimulatorTrampoline,
// SimLaunchHost-arm64, remotepairingd; extensionkitservice and the DeviceFS
// extension in fskit_agent's pid domain; SimAudio/SimStreamProcessorService in
// CoreSimulatorService's). Their binaries are Apple platform binaries outside
// SIP (/Library/Developer/PrivateFrameworks) or in /Library/Apple, so
// appleLaunch cannot admit them, and as residual processes every build would
// disable the worker at the next admission.
//
// Outside reset, a job-UID process that is neither audited, a verified
// relaunch nor an Apple-defined launch is a developer-tool launch, tolerated
// like an Apple-defined launch, only if launchd's record proves all of this
// (developerToolLaunch):
//   - kernel: the sampled start, the job UID, PPID 1 and a valid platform
//     binary (csops); the executable lies under /System (not /System/Volumes),
//     /Library/Apple/System/Library or /Library/Developer/PrivateFrameworks,
//     is not a shell, interpreter or Terminal, and hostguard's toolchain
//     policy holds for its whole path: root-owned, no symlinks, not world
//     writable, group writable only for admin directories the job is not in;
//   - launchd: the job's gui or user domain lists the PID as an XPCService, or
//     the pid domain of an owner verified in the same census (a present or
//     relaunched audited launchd service, an Apple-defined launch or another
//     developer-tool launch) lists it as an XPCService or Extension, and
//     launchctl print of that exact service reports the PID (a Submitted job
//     is neither type);
//   - bundle: launchd's path is a .xpc or .appex bundle under the same roots
//     with the same toolchain policy, the executable is its
//     Contents/MacOS/<CFBundleExecutable>, and launchd's `bundle id`, the
//     label (or its `original` for an instance <original>.<UUID>) and the
//     bundle's root-owned Info.plist CFBundleIdentifier are the same; the exec
//     path and argv are launchd's program and arguments;
//   - environment: launchd's inherited environment is the domain environment
//     recorded at reset (gui, user), or for a pid domain exactly launchd's XPC
//     environment of the job account: HOME, PATH=/usr/bin:/bin:/usr/sbin:/sbin
//     and TMPDIR, the job's DARWIN_USER_TEMP_DIR;
//   - overrides: neither the gui nor the user `disabled services` table lists
//     the label or original.
//
// Not covered, deliberately: /Library/Developer/CoreSimulator, whose runtime
// volumes run simulator processes (launchd_sim) executing apps the job built,
// and the Xcode bundle, which runs no launchd service (ibtoold is a build
// child in no launchd domain). Those stay residual.
//
// Threat. The job cannot change these binaries, bundles or Info.plists (root
// owned and outside every job-writable directory, SIP for /System and
// /Library/Apple); it can only ask launchd to start them through XPC, which
// it can do whether or not the census tolerates the result. launchd runs
// Apple's code with the bundle's fixed argv and an environment the job did
// not set. This is the residual-risk class of Apple-defined launches: state
// these services keep in the job home (~/Library/Developer/CoreSimulator,
// CoreDevice), and their entitlements used for the job while it runs (paired
// devices, simulator creation). Quiesce signals them with the residual
// processes without waiting for them to stay gone, and nothing joins the
// baseline. A booted simulator's processes stay contamination unless the
// engine's own device lifecycle stopped them.
//
// developerToolRoots are the only executable and bundle roots: /System minus
// /System/Volumes (never /usr, /bin or /sbin, whose code runners and tools
// such as /sbin/mount launchd never runs as a bundle), SIP-protected
// /Library/Apple/System/Library and root-owned /Library/Developer/PrivateFrameworks.
var developerToolRoots = []string{"/System/", "/Library/Apple/System/Library/", "/Library/Developer/PrivateFrameworks/"}

// toleratedChildWait bounds how long admission waits for residual processes
// that are all direct children of tolerated launches (CoreDeviceService runs a
// short /sbin/mount when launchd restarts it). They are never tolerated: if
// one outlives the wait, admission refuses without quarantine.
const toleratedChildWait = 30 * time.Second

var errToleratedChildPersists = errors.New("a child process of a tolerated launchd service outlived the admission wait; retry admission")

func developerToolPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	if strings.HasPrefix(path, "/System/Volumes/") {
		return false
	}
	for _, root := range developerToolRoots {
		if strings.HasPrefix(path, root) {
			return true
		}
	}
	return false
}

// listing returns the domain, pid-domain owner and label for pid: the gui
// domain, else the user domain, else the first of owners whose pid domain
// lists it. launchctl print of the exact target then decides.
func (h *serviceHints) listing(ctx context.Context, pid int, owners []int) (domain string, owner int, label string, ok bool) {
	for _, d := range []string{"gui", "user"} {
		if label, ok := h.table(ctx, d+"/"+strconv.Itoa(h.uid))[pid]; ok {
			return d, 0, label, true
		}
	}
	for _, o := range owners {
		if o == pid {
			continue
		}
		if label, ok := h.table(ctx, "pid/"+strconv.Itoa(o))[pid]; ok {
			return "pid", o, label, true
		}
	}
	return "", 0, "", false
}

// xpcEnvironment is launchd's pid-domain XPC environment of the job account,
// read once per census.
func (h *serviceHints) xpcEnvironment(ctx context.Context) (map[string]string, error) {
	if !h.xpcRead {
		h.xpcEnv, h.xpcErr = h.agents.xpcEnvironment(ctx, h.uid)
		h.xpcRead = true
	}
	return h.xpcEnv, h.xpcErr
}

// developerToolLaunch returns the launchd target of p when p is a
// developer-tool launch (see above), else why not. owners are the verified
// processes whose pid domains may list p.
func developerToolLaunch(ctx context.Context, agents agentInspector, uid int, env LaunchdEnvironment, hints *serviceHints, owners []int, p processSample) (string, error) {
	facts, err := agents.process(p.pid)
	if err != nil {
		return "", fmt.Errorf("process facts: %w", err)
	}
	if facts.start != p.start || facts.uid != uid || facts.ppid != 1 || !facts.platform {
		return "", errors.New("not a platform binary launched by launchd as the job user")
	}
	if !developerToolPath(facts.executable) || codeRunner(facts.executable) {
		return "", fmt.Errorf("executable %q is outside the developer-tool roots", facts.executable)
	}
	if err := agents.toolchain(facts.executable, false, uid); err != nil {
		return "", fmt.Errorf("executable %q: %w", facts.executable, err)
	}
	domain, owner, label, ok := hints.listing(ctx, p.pid, owners)
	if !ok || !validLaunchdLabel(label) {
		return "", errors.New("not listed by the job's launchd domains or a verified owner's pid domain")
	}
	target := domain + "/" + strconv.Itoa(uid) + "/" + label
	if domain == "pid" {
		target = "pid/" + strconv.Itoa(owner) + "/" + label
	}
	snapshot, err := agents.service(ctx, target)
	if err != nil || snapshot.Target != target || snapshot.PID != p.pid {
		return target, errors.Join(err, errors.New("launchd does not report this PID for the service"))
	}
	if snapshot.Type != "XPCService" && (domain != "pid" || snapshot.Type != "Extension") {
		return target, fmt.Errorf("launchd type %q is not an XPC service or extension", snapshot.Type)
	}
	bundle := snapshot.Path
	if !developerToolPath(bundle) || !strings.HasSuffix(bundle, ".xpc") && !strings.HasSuffix(bundle, ".appex") {
		return target, fmt.Errorf("launchd path %q is not a bundle under the developer-tool roots", bundle)
	}
	if filepath.Dir(facts.executable) != bundle+"/Contents/MacOS" {
		return target, errors.New("executable is not the bundle's")
	}
	if err := agents.toolchain(bundle, true, uid); err != nil {
		return target, fmt.Errorf("bundle %q: %w", bundle, err)
	}
	argv := snapshot.Arguments
	if argv == nil {
		argv = []string{snapshot.Program}
	}
	if snapshot.Program != facts.executable || facts.program != snapshot.Program || facts.argv != strings.Join(argv, "\x00") {
		return target, errors.New("exec path or argv differs from launchd's program and arguments")
	}
	defined := label
	if snapshot.Original != "" {
		suffix, ok := strings.CutPrefix(label, snapshot.Original+".")
		if !ok || !validLaunchdLabel(snapshot.Original) || !instanceID.MatchString(suffix) {
			return target, fmt.Errorf("launchd instance %q of %q is not <original>.<UUID>", label, snapshot.Original)
		}
		defined = snapshot.Original
	}
	if snapshot.BundleID != defined {
		return target, fmt.Errorf("launchd bundle id %q is not the service label %q", snapshot.BundleID, defined)
	}
	id, executable, err := agents.bundleInfo(ctx, bundle)
	if err != nil || id != defined || executable != filepath.Base(facts.executable) {
		return target, errors.Join(err, errors.New("bundle Info.plist differs from launchd's record"))
	}
	var reference map[string]string
	switch domain {
	case "gui":
		reference = env.GUI
	case "user":
		reference = env.User
	case "pid":
		if reference, err = hints.xpcEnvironment(ctx); err != nil {
			return target, fmt.Errorf("job XPC environment: %w", err)
		}
	}
	if !maps.Equal(snapshot.Inherited, reference) {
		return target, errors.New("inherited environment differs from the job's launchd environment")
	}
	for _, d := range []string{"gui", "user"} {
		printed := hints.print(ctx, d+"/"+strconv.Itoa(uid))
		if printed.Target == "" || !printed.DisabledComplete {
			return target, fmt.Errorf("%s domain overrides unavailable", d)
		}
		for _, l := range []string{label, defined} {
			if state, listed := printed.Disabled[l]; listed {
				return target, fmt.Errorf("%s domain overrides %s (%s)", d, l, state)
			}
		}
	}
	again, err := agents.process(p.pid)
	if err != nil || again != facts {
		return target, errors.New("process changed during verification")
	}
	return target, nil
}

// refusal is why a residual process is not a tolerated launch: the launchd
// target a rule found for it (if any) and each rule's last error.
type refusal struct {
	target               string
	apple, developerTool error
}

// toleratedLaunches moves every Apple-defined and developer-tool launch out of
// candidates and returns, by PID, why each remaining one was refused.
// audited are present or relaunched audited launchd services, which may own
// pid domains; tolerated launches verified earlier in the same call are
// owners too, so passes repeat until none is added.
func toleratedLaunches(ctx context.Context, agents agentInspector, uid int, env LaunchdEnvironment, audited []int, candidates []processSample) (residual, tolerated []processSample, refused map[int]refusal) {
	hints := newServiceHints(agents, uid, nil)
	refused = make(map[int]refusal)
	var owners []int
	for _, c := range candidates {
		if target, err := appleLaunch(ctx, agents, uid, env, hints, c); err == nil {
			tolerated = append(tolerated, c)
			owners = append(owners, c.pid)
		} else {
			residual = append(residual, c)
			refused[c.pid] = refusal{target: target, apple: err}
		}
	}
	for progress := len(residual) != 0; progress; {
		progress = false
		verified := slices.Concat(owners, audited)
		for i := 0; i < len(residual); {
			c := residual[i]
			if target, err := developerToolLaunch(ctx, agents, uid, env, hints, verified, c); err != nil {
				r := refused[c.pid]
				if r.target == "" {
					r.target = target
				}
				r.developerTool = err
				refused[c.pid] = r
				i++
				continue
			}
			delete(refused, c.pid)
			tolerated = append(tolerated, c)
			owners = append(owners, c.pid)
			residual = slices.Delete(residual, i, i+1)
			progress = true
		}
	}
	return residual, tolerated, refused
}
