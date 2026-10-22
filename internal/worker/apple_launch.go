package worker

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Apple-defined launches (v0.1.14). A build makes launchd start Apple
// on-demand LaunchAgents in the job's gui or user domain that the audited
// baseline never contained: on macOS 27.0 an Xcode build looks up the
// MachServices of com.apple.accessibility.heard (which then respawns every
// second) and com.apple.BTServer.cloudpairing. Before v0.1.14 the census
// called them contamination and every real build quarantined the worker.
//
// Outside reset, a job-UID process outside the baseline that is not a
// verified relaunch of an audited process is an Apple-defined launch, not
// residual, only if launchd's own record proves all of this (appleLaunch):
//   - kernel: the sampled start, the job UID, PPID 1, a valid platform binary
//     at a system path whose file is SF_RESTRICTED, root-owned and not group or
//     other writable, and not a shell, interpreter or Terminal (codeRunner);
//   - launchd: the gui or user domain's services table names the PID, and
//     launchctl print of that exact service reports the PID, type LaunchAgent
//     (never Submitted) and a path directly in /System/Library/LaunchAgents;
//   - plist: that plist is itself SIP-restricted, names the label, is not
//     Disabled, has no BundleProgram, and its Program and ProgramArguments
//     are the program and arguments launchd reports; an instance of a
//     MultipleInstances service (launchd prints `original`, the label is
//     <original>.<UUID>, as for the mdworker_shared instances Spotlight
//     starts while a build writes files) is checked against the original
//     label's plist, which must set MultipleInstances;
//   - exec: the KERN_PROCARGS2 exec path is exactly that program (string
//     equality, before any cleaning), a system path that resolves to the
//     kernel executable, and the argv is those arguments (see launchdProgram
//     for Apple's programs with redundant separators);
//   - environment: the inherited environment launchd reports for the
//     service is the domain environment recorded at reset, which the census
//     has just required to be unchanged: no `launchctl setenv` was in effect
//     when launchd spawned it;
//   - overrides: neither domain's `disabled services` table lists the label
//     or original label (`launchctl enable` of an agent Apple's plist
//     disables, or a disable).
//
// Kernel facts are read again after launchd and the plist answer and must be
// identical, binding the answer to this process instance. Anything else stays
// residual: a `launchctl submit`, a home plist under an Apple label, a
// launchd path elsewhere, a program or argv override, a setenv, an
// enable/disable override, or a binary outside SIP.
//
// Threat. A job can always make launchd start any Apple on-demand agent in
// its own domains by looking up one of its MachServices, and have it do XPC
// work for it while the job runs; no check before or after prevents that,
// and quarantining afterwards only made every build disable the worker.
// What the rule proves is that the process is Apple's SIP binary exec'd by
// launchd from Apple's SIP plist with Apple's argv and no setenv or enable
// override: the code that would run for that lookup in any login session.
// That is the same exposure as the launchd relaunches of audited agents the
// census has tolerated since v0.1.9, with stronger cleanup: quiesce signals
// every Apple-defined launch like a residual process (launchd may start it
// again on the next lookup, so its absence is never required), and nothing
// is added to the baseline, so each instance is verified from scratch by
// every census. Not covered, as for audited relaunches: state such agents
// read from the job home (preferences, caches), which a job can write; an
// agent's own entitlements used on the job's behalf while it runs; and a
// pending `launchctl debug --environment` for the agent's next spawn, which
// launchctl print does not report as inherited environment.
const maxLaunchdPlistBytes = 1 << 20

const systemLaunchAgents = "/System/Library/LaunchAgents"

// instanceID is the launchd instance suffix of a MultipleInstances service
// label (LaunchInstanceID), as printed on macOS 27.0.
var instanceID = regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$`)

// appleLaunch returns the launchd target of p when p is an Apple-defined
// launch (see above), else why not.
func appleLaunch(ctx context.Context, agents agentInspector, uid int, env LaunchdEnvironment, hints *serviceHints, p processSample) (string, error) {
	facts, err := agents.process(p.pid)
	if err != nil {
		return "", fmt.Errorf("process facts: %w", err)
	}
	if facts.start != p.start || facts.uid != uid || facts.ppid != 1 || !facts.platform {
		return "", errors.New("not a platform binary launched by launchd as the job user")
	}
	if !systemPath(facts.executable) || codeRunner(facts.executable) {
		return "", fmt.Errorf("executable %q is not a system agent", facts.executable)
	}
	if err := agents.restricted(facts.executable); err != nil {
		return "", fmt.Errorf("executable %q: %w", facts.executable, err)
	}
	domain, _, label, ok := hints.find(ctx, p.pid)
	if !ok || domain != "gui" && domain != "user" || !validLaunchdLabel(label) {
		return "", errors.New("not listed by the job's gui or user launchd domain")
	}
	reference := env.GUI
	if domain == "user" {
		reference = env.User
	}
	target := domain + "/" + strconv.Itoa(uid) + "/" + label
	snapshot, err := agents.service(ctx, target)
	if err != nil || snapshot.Target != target || snapshot.PID != p.pid {
		return target, errors.Join(err, errors.New("launchd does not report this PID for the service"))
	}
	if snapshot.Type != "LaunchAgent" || filepath.Dir(snapshot.Path) != systemLaunchAgents || filepath.Clean(snapshot.Path) != snapshot.Path || !strings.HasSuffix(snapshot.Path, ".plist") {
		return target, fmt.Errorf("launchd type %q path %q is not a system LaunchAgent plist", snapshot.Type, snapshot.Path)
	}
	argv := snapshot.Arguments
	if argv == nil {
		argv = []string{snapshot.Program}
	}
	if facts.program != snapshot.Program || facts.argv != strings.Join(argv, "\x00") {
		return target, fmt.Errorf("exec path %q or argv differs from launchd's program %q and arguments", facts.program, snapshot.Program)
	}
	if program, ok := launchdProgram(snapshot.Program); !ok || !systemPath(program) {
		return target, fmt.Errorf("launchd program %q is not a system path", snapshot.Program)
	}
	// launchd's program may name the executable through a framework's
	// immutable system symlinks (ATS.framework/Support/fontd).
	if resolved, err := agents.resolve(snapshot.Program); err != nil || filepath.Clean(resolved) != facts.executable {
		return target, errors.Join(err, fmt.Errorf("launchd program %q does not resolve to the executable", snapshot.Program))
	}
	if !maps.Equal(snapshot.Inherited, reference) {
		return target, errors.New("inherited environment differs from the domain environment recorded at reset")
	}
	// An instance of a MultipleInstances service carries launchd's
	// `original` label: <original>.<instance UUID> (mdworker_shared).
	defined, instance := label, false
	if snapshot.Original != "" {
		suffix, ok := strings.CutPrefix(label, snapshot.Original+".")
		if !ok || !validLaunchdLabel(snapshot.Original) || !instanceID.MatchString(suffix) {
			return target, fmt.Errorf("launchd instance %q of %q is not <original>.<UUID>", label, snapshot.Original)
		}
		defined, instance = snapshot.Original, true
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
	data, err := agents.plist(ctx, snapshot.Path)
	if err != nil {
		return target, fmt.Errorf("plist %s: %w", snapshot.Path, err)
	}
	program, arguments, multiple, err := agentPlist(data, defined)
	if err != nil {
		return target, fmt.Errorf("plist %s: %w", snapshot.Path, err)
	}
	if instance && !multiple {
		return target, errors.New("launchd instance of a service whose plist does not allow MultipleInstances")
	}
	if program != snapshot.Program || !slices.Equal(arguments, argv) {
		return target, errors.New("launchd program or arguments differ from the plist")
	}
	again, err := agents.process(p.pid)
	if err != nil || again != facts {
		return target, errors.New("process changed during verification")
	}
	return target, nil
}

// agentPlist returns the program and argv launchd execs for the XML launchd
// plist data, which must name label, and whether it sets MultipleInstances.
// Program defaults to ProgramArguments[0] and argv to [Program]. A Disabled
// plist, a BundleProgram or any value of an unexpected type refuses.
func agentPlist(data []byte, label string) (string, []string, bool, error) {
	fields, err := plistDict(data)
	if err != nil {
		return "", nil, false, err
	}
	if name := fields["Label"]; !plistString(name) || name.Text != label {
		return "", nil, false, errors.New("plist names another label")
	}
	if disabled, ok := fields["Disabled"]; ok && disabled.XMLName.Local != "false" {
		return "", nil, false, errors.New("plist is disabled")
	}
	if _, ok := fields["BundleProgram"]; ok {
		return "", nil, false, errors.New("BundleProgram is not verified")
	}
	var argv []string
	if args, ok := fields["ProgramArguments"]; ok {
		if args.XMLName.Local != "array" || len(args.Children) == 0 {
			return "", nil, false, errors.New("invalid ProgramArguments")
		}
		for _, arg := range args.Children {
			if !plistString(arg) {
				return "", nil, false, errors.New("invalid ProgramArguments")
			}
			argv = append(argv, arg.Text)
		}
	}
	program := ""
	if p, ok := fields["Program"]; ok {
		if !plistString(p) {
			return "", nil, false, errors.New("invalid Program")
		}
		program = p.Text
	} else if len(argv) != 0 {
		program = argv[0]
	}
	if _, ok := launchdProgram(program); !ok {
		return "", nil, false, errors.New("plist program is not an absolute path without . or .. components")
	}
	if argv == nil {
		argv = []string{program}
	}
	multiple, ok := fields["MultipleInstances"]
	if ok && multiple.XMLName.Local != "true" && multiple.XMLName.Local != "false" {
		return "", nil, false, errors.New("invalid MultipleInstances")
	}
	return program, argv, ok && multiple.XMLName.Local == "true", nil
}

func plistString(v servicePlistValue) bool {
	return v.XMLName.Local == "string" && len(v.Children) == 0
}

// plistDict returns the root dictionary of the XML plist data by key; a
// repeated or malformed key refuses.
func plistDict(data []byte) (map[string]servicePlistValue, error) {
	var root servicePlistValue
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if root.XMLName.Local != "plist" || len(root.Children) != 1 || root.Children[0].XMLName.Local != "dict" {
		return nil, errors.New("unsupported plist")
	}
	children := root.Children[0].Children
	if len(children)%2 != 0 {
		return nil, errors.New("invalid plist dictionary")
	}
	fields := map[string]servicePlistValue{}
	for i := 0; i < len(children); i += 2 {
		key := children[i]
		if key.XMLName.Local != "key" || len(key.Children) != 0 {
			return nil, errors.New("invalid plist key")
		}
		if _, exists := fields[key.Text]; exists {
			return nil, errors.New("duplicate plist key")
		}
		fields[key.Text] = children[i+1]
	}
	return fields, nil
}

// bundleIdentity returns CFBundleIdentifier and CFBundleExecutable of the XML
// Info.plist data.
func bundleIdentity(data []byte) (string, string, error) {
	fields, err := plistDict(data)
	if err != nil {
		return "", "", err
	}
	id, exe := fields["CFBundleIdentifier"], fields["CFBundleExecutable"]
	if !plistString(id) || !plistString(exe) || id.Text == "" || exe.Text == "" || strings.Contains(exe.Text, "/") {
		return "", "", errors.New("Info.plist lacks a bundle identifier or executable")
	}
	return id.Text, exe.Text, nil
}
