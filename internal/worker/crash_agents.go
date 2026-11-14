package worker

import (
	"slices"
)

// Crash agents (v0.1.56, #146). When a process of the job account crashes
// (herdrup's crash tests crash their app on purpose; a failing UI test
// crashes too), ReportCrash has launchd start the macOS crash dialog, Problem
// Reporter, in the job's GUI session, and within a third of a second two XPC
// services start beside it: CascadeSets' SetStoreUpdateService and
// SpeechSynthesisServerXPC (Studio, v0.1.55, 2026-11-14). The dialog waits for
// a click that never comes, so it outlives the job. None of the three is an
// Apple-defined launch (Problem Reporter is an application, not a
// LaunchAgent) or a developer-tool launch (the XPC services belong to a pid
// domain whose owner, the dialog, the census never verifies), so each was an
// unattributed process: a lane finalizing beside other jobs deferred its
// verdict and drained the engine, and every lane waited for the slowest job
// and the idle Recover (30-40 minutes of idle lanes per crash).
//
// A crash agent is an instance whose kernel facts prove all of this
// (crashAgent): the job UID, PPID 1 (launchd spawned it), a valid platform
// binary, an executable that is exactly one of crashAgentExecutables (the
// kernel's PROC_PIDPATHINFO path, string equality) and is SIP-restricted, and
// a start inside a running job's crashWindow: after the job began and, once
// its lane quiesce has begun, before the latest one did. Lane attribution
// treats such an instance as that job's (laneCensus): it is neither residue
// nor a reason to refuse a lane admission. That job's lane quiesce terminates
// it (QuiesceJob), with the same signals, survivor rule and settle bound as
// the job's own processes; a job that ends alone ends with the full quiesce,
// which signals it like any residual process. Each lane quiesce takes only
// the instances started before it began, so a sibling that keeps crashing
// cannot keep it going, and an instance no running job's window covers any
// more is residue.
//
// Terminated, not tolerated. The tolerated sets (appleLaunch,
// developerToolLaunch) admit only launches whose launchd record proves
// Apple's own definition, and they serve every job. The dialog has no such
// record, and tolerating the two XPC services would mean trusting their pid
// domain's owner, the dialog, as a launchd service owner. Terminating all
// three is narrower: nothing joins any tolerated set, the account is left
// with no process of theirs, and nothing is lost: ReportCrash has written
// the crash report before the dialog shows it, and the XPC services are
// stateless on-demand services that launchd starts again on the next lookup.
//
// Everything else stays as before: any other unattributed process, a crash
// agent no running job's window covers (it started before every running
// job, or after the last lane quiesce of every job that began before it),
// or a look-alike that fails any fact (another path, a copy outside SIP, a
// process the job forked itself, a non-platform binary) is residue, which
// defers the verdict and drains the engine, and a full quiesce or admission
// refuses it as before.
var crashAgentExecutables = map[string]bool{
	"/System/Library/CoreServices/Problem Reporter.app/Contents/MacOS/Problem Reporter":                                                                                                                    true,
	"/System/Library/PrivateFrameworks/CascadeSets.framework/Versions/A/XPCServices/SetStoreUpdateService.xpc/Contents/MacOS/SetStoreUpdateService":                                                        true,
	"/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/SpeechSynthesis.framework/Versions/A/XPCServices/SpeechSynthesisServerXPC.xpc/Contents/MacOS/SpeechSynthesisServerXPC": true,
}

// crashAgents returns the crash agents (see above) among samples that no job
// labels (labelled) and that started inside one of windows. Without kernel
// facts (no agents seam) there are none.
func (r *nativeRunner) crashAgents(samples []processSample, labelled map[processInstance]bool, windows []crashWindow) []processSample {
	if r.scope == nil || r.scope.agents == nil || len(windows) == 0 {
		return nil
	}
	var out []processSample
	for _, p := range samples {
		if p.uid != r.scope.uid || p.zombie || p.parent != 1 || p.pid <= 1 || labelled[processInstance{p.pid, p.start}] {
			continue
		}
		started, ok := startTime(p.start)
		if !ok || !slices.ContainsFunc(windows, func(w crashWindow) bool { return w.covers(started) }) {
			continue
		}
		if r.crashAgent(p) {
			out = append(out, p)
		}
	}
	return out
}

// crashAgent reports whether the kernel's facts for p's instance prove a
// crash agent of the job account.
func (r *nativeRunner) crashAgent(p processSample) bool {
	facts, err := r.scope.agents.kernel(p.pid)
	if err != nil || facts.start != p.start || facts.uid != r.scope.uid || facts.ppid != 1 || !facts.platform || !crashAgentExecutables[facts.executable] {
		return false
	}
	return r.scope.agents.restricted(facts.executable) == nil
}
