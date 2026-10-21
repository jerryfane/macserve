package worker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Baseline executable policy (v0.1.13). Agent-driven requalification after a
// reboot audits a GUI baseline nobody reviews by eye, so the processes it
// trusts are checked by kernel facts instead of an exact process list, which
// changes on every boot because Apple helpers start on demand.
//
// Every audited baseline process must run an executable that is:
//   - a regular file with the SIP SF_RESTRICTED flag, owned by root and not
//     group or other writable (only the OS installer can create or change it);
//   - not a shell, interpreter or console that runs code supplied at run time.
//
// Launchd provenance (label, SIP plist or system XPC bundle, launch and
// inherited digests) is enforced separately by validateBaseline. The no-switch
// flow never needs a Terminal in the job session, so it is refused here.
var codeRunners = []string{
	"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
	"/System/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor",
	"/System/Applications/Automator.app/Contents/MacOS/Automator",
	"/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc",
}

// codeRunnerDirs hold shells and interpreters (sh, zsh, python3, perl, ruby,
// osascript, swift, ...). /usr/sbin and /usr/libexec hold daemons and agents.
var codeRunnerDirs = []string{"/bin/", "/sbin/", "/usr/bin/"}

func codeRunner(path string) bool {
	if slices.Contains(codeRunners, path) {
		return true
	}
	for _, dir := range codeRunnerDirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	return false
}

// baselineExecutables returns, for each audited process, the executable it
// runs now (kernel path of the same PID and start) or, for an exited entry
// with launchd provenance, the executable launchd would relaunch. An exited
// entry without provenance cannot run again as an audited process.
func baselineExecutables(b GUIBaseline, agents agentInspector) (map[int]string, error) {
	paths := make(map[int]string, len(b.Processes))
	for _, p := range b.Processes {
		facts, err := agents.kernel(p.PID)
		if err == nil && facts.start == p.Start {
			if facts.uid != int(b.JobUID) {
				return nil, fmt.Errorf("audited PID %d now runs as uid %d", p.PID, facts.uid)
			}
			paths[p.PID] = facts.executable
			continue
		}
		if p.Service.Domain != "" {
			paths[p.PID] = p.Service.Executable
		}
	}
	return paths, nil
}

func checkBaselinePolicy(b GUIBaseline, agents agentInspector, restricted func(string) error) error {
	paths, err := baselineExecutables(b, agents)
	if err != nil {
		return err
	}
	var failures []error
	for _, p := range b.Processes {
		path, ok := paths[p.PID]
		if !ok {
			continue
		}
		if path == "" || codeRunner(path) {
			failures = append(failures, fmt.Errorf("audited PID %d runs %q: shells, interpreters and Terminal are not trusted baseline processes", p.PID, path))
			continue
		}
		if err := restricted(path); err != nil {
			failures = append(failures, fmt.Errorf("audited PID %d runs %q: %w", p.PID, path, err))
		}
	}
	return errors.Join(failures...)
}

// CheckBaselinePolicy loads the protected current-boot GUI baseline and applies
// the baseline executable policy with live kernel facts. It is read-only.
func CheckBaselinePolicy(ctx context.Context, baselinePath string, jobUID uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := loadBaseline(baselinePath, jobUID)
	if err != nil {
		return err
	}
	if err := checkBaselinePolicy(b, nativeAgents{}, sipRestrictedExecutable); err != nil {
		return fmt.Errorf("GUI baseline executable policy: %w", err)
	}
	return nil
}
