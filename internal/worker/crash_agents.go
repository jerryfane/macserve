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
// A crash agent is a process the census leaves residual (crashResidue,
// laneCensus) whose kernel facts prove all of this (appleAgent): the job
// UID, PPID 1 (launchd spawned it), a valid platform binary, an executable
// that is exactly one of crashAgentExecutables (the kernel's
// PROC_PIDPATHINFO path, string equality) and is SIP-restricted, and a start
// inside a running job's crashWindow: after the job began and, once its lane
// quiesce has begun, before the latest one did. The census comes first: an
// instance of one of these executables that is a verified launchd relaunch
// of an audited process or a tolerated Apple-defined or developer-tool launch
// serves every job and is never a crash agent, and without a loaded baseline
// (its launchd domain environment) there is none. Lane attribution treats a
// crash agent as that job's (laneCensus): it is neither residue nor a reason
// to refuse a lane admission. That job's lane quiesce terminates it
// (QuiesceJob), with the same signals, survivor rule and settle bound as the
// job's own processes; a job that ends alone ends with the full quiesce,
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

// Shared agents (#155, Studio v0.1.58/v0.1.60 worker logs). Three more kinds
// of Apple per-user agent start beside running jobs and outlive them, but
// unlike the crash dialog they serve whichever job needs them, so no
// finalizing job may stop them while another one runs:
//
//   - Spotlight's mdworker, which mds has launchd start as the job UID to
//     index files any job wrote (10:45:41Z: pid 79899 drained the engine 22 s
//     after it started).
//   - WebKit's out-of-process services, which a web view in any job's GUI
//     session starts together: the GPU process alone outlived its client
//     and deferred j_645b8263 at 13:18:15Z (pid 99327, started 13:17:01Z),
//     and the GPU, two WebContent and the Networking process started within
//     80 ms of each other and drained the engine on 2026-11-13 (16:51:39Z).
//     The same pid 99327 is the likely unattributed process beside which an
//     exited audited agent made j_7841d25a's lane admission unverifiable at
//     13:17:13Z (see laneCensus). They are XPC services of the sealed OS
//     cryptex: the kernel's executable path is the
//     /System/Volumes/Preboot/Cryptexes/OS one (the /System path launchd
//     names is a SIP symlink into it), whose files are SF_RESTRICTED like
//     /System's (osCryptex), so the same exact-path and SIP facts apply. A
//     copy in the App cryptex or anywhere else is a look-alike.
//   - The Lighthouse SELF ingestor extensions (ExtensionKit, on the sealed
//     system volume): GMSSELFIngestor, IFTelemetrySELFIngestor,
//     BiomeSELFIngestor and AppleIntelligenceReportingSELFIngestor started
//     within 270 ms of each other at 16:39:00Z on 2026-11-15 as XPC services
//     of the job UID and deferred j_ce4ce15b, j_c5e942db and j_bc451b92
//     (16:40-16:50Z). Which job's activity requested them is not knowable.
//
// A shared agent has a crash agent's kernel facts (appleAgent) with an
// executable that is exactly one of sharedAgentExecutables, and a start in
// the current busy period (laneTracker.busySince): after the first of the
// jobs that have run without a break since the account was last idle. The
// census comes first, as for crash agents. Lane attribution leaves it out
// of the residue (laneCensus): it neither defers a verdict, drains the
// engine nor refuses a lane admission. No lane quiesce signals it: its
// client may be a sibling that still runs (a web view's GPU process, the
// indexing of a sibling's files), and nothing attributes it to the
// finalizing job or proves its client gone. The account is cleaned of it
// at the next idle point: the job that finalizes alone ends with the full
// quiesce, and the idle Recover applies it too, which signal it like any
// residual process. A shared agent started before the busy period began
// and every look-alike is residue as before.
//
// Not tolerated: the tolerated sets serve every job across idle points;
// a shared agent serves only the jobs of its busy period. mdworker runs
// importer plug-ins as the job UID, and the WebKit services' owner is a web
// view's process the census never verifies. All of them are on-demand
// services launchd starts again on the next request, so ending them at idle
// loses nothing.
//
// The worker does not try to keep Spotlight away from the job's files: a
// .metadata_never_index file inside a folder is no longer honoured by
// current macOS (only at a volume root), a .noindex workspace name would
// still leave the simulator data in the job account's home indexed, and
// Spotlight's privacy list is a system setting.
var sharedAgentExecutables = map[string]bool{
	"/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker":                                   true,
	osCryptex + "System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.GPU.xpc/Contents/MacOS/com.apple.WebKit.GPU":               true,
	osCryptex + "System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent": true,
	osCryptex + "System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking": true,
	"/System/Library/ExtensionKit/Extensions/GMSSELFIngestor.appex/Contents/MacOS/GMSSELFIngestor":                                                             true,
	"/System/Library/ExtensionKit/Extensions/IFTelemetrySELFIngestor.appex/Contents/MacOS/IFTelemetrySELFIngestor":                                             true,
	"/System/Library/ExtensionKit/Extensions/BiomeSELFIngestor.appex/Contents/MacOS/BiomeSELFIngestor":                                                         true,
	"/System/Library/ExtensionKit/Extensions/AppleIntelligenceReportingSELFIngestor.appex/Contents/MacOS/AppleIntelligenceReportingSELFIngestor":               true,
}

// crashAgents returns the crash agents (see above) among samples, which the
// caller has taken from the census's residual processes or is about to
// judge with it, that no job labels (labelled) and that started inside one
// of windows. Without kernel facts (no agents seam) or a loaded baseline
// there are none.
func (r *nativeRunner) crashAgents(samples []processSample, labelled map[processInstance]bool, windows []crashWindow) []processSample {
	return r.appleAgents(samples, labelled, windows, crashAgentExecutables)
}

// sharedAgents returns the shared agents (see above) among samples, taken
// from the census's residual processes, that no job labels (labelled) and
// that started in the current busy period; none while no job runs.
func (r *nativeRunner) sharedAgents(samples []processSample, labelled map[processInstance]bool) []processSample {
	since, busy := r.laneTracker().busySince()
	if !busy {
		return nil
	}
	return r.appleAgents(samples, labelled, []crashWindow{{from: since}}, sharedAgentExecutables)
}

// appleAgents returns the instances among samples, unlabelled and started
// inside one of windows, whose kernel facts prove one of executables
// (appleAgent).
func (r *nativeRunner) appleAgents(samples []processSample, labelled map[processInstance]bool, windows []crashWindow, executables map[string]bool) []processSample {
	if r.scope == nil || r.scope.agents == nil || r.scope.baseline.Launchd == nil || len(windows) == 0 {
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
		if r.appleAgent(p, executables) {
			out = append(out, p)
		}
	}
	return out
}

// appleAgent reports whether the kernel's facts for p's instance prove a
// launchd-started Apple process of the job account running exactly one of
// executables, SIP-restricted.
func (r *nativeRunner) appleAgent(p processSample, executables map[string]bool) bool {
	facts, err := r.scope.agents.kernel(p.pid)
	if err != nil || facts.start != p.start || facts.uid != r.scope.uid || facts.ppid != 1 || !facts.platform || !executables[facts.executable] {
		return false
	}
	return r.scope.agents.restricted(facts.executable) == nil
}
