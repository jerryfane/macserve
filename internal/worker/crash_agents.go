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
// Three more kinds of Apple per-user agent start the same way and are
// handled as crash agents (#155, Studio v0.1.58/v0.1.60 worker logs):
//
//   - Spotlight's mdworker, which mds has launchd start as the job UID to
//     index files the job wrote (10:45:41Z: pid 79899 drained the engine 22 s
//     after it started). It loads Spotlight importer plug-ins as the job UID,
//     so it must not outlive the jobs it indexed for; mds starts it again on
//     demand.
//   - WebKit's out-of-process services, which a web view in the job's GUI
//     session starts together: the GPU process alone outlived its client
//     and deferred j_645b8263 at 13:18:15Z (pid 99327, started 13:17:01Z),
//     and the GPU, two WebContent and the Networking process started within
//     80 ms of each other and drained the engine on 2026-11-13 (16:51:39Z).
//     The same pid 99327 is the likely unattributed process beside which an
//     exited audited agent made j_7841d25a's lane admission unverifiable at
//     13:17:13Z (see laneCensus). They are XPC services of the
//     sealed OS cryptex: the kernel's executable path is the
//     /System/Volumes/Preboot/Cryptexes/OS one (the /System path launchd
//     names is a SIP symlink into it), whose files are SF_RESTRICTED like
//     /System's (osCryptex), so the same exact-path and SIP facts apply. A
//     copy in the App cryptex or anywhere else is a look-alike.
//   - The Lighthouse SELF ingestor extensions (ExtensionKit, on the sealed
//     system volume): GMSSELFIngestor, IFTelemetrySELFIngestor,
//     BiomeSELFIngestor and AppleIntelligenceReportingSELFIngestor started
//     within 270 ms of each other at 16:39:00Z on 2026-11-15 as XPC services
//     of the job UID and deferred j_ce4ce15b, j_c5e942db and j_bc451b92
//     (16:40-16:50Z). They are on-demand telemetry ingestors that launchd
//     starts again on the next request.
//
// A crash agent is a process the census leaves residual (crashResidue,
// laneCensus) whose kernel facts prove all of this (crashAgent): the job
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
// domain's owner, the dialog, as a launchd service owner. Tolerating
// mdworker by its path would let a process that runs importer plug-ins as
// the job UID serve every later job, and the WebKit services' owner is a
// web view's process the census never verifies either. Terminating all of
// them is narrower: nothing joins any tolerated set, the account is left
// with no process of theirs, and nothing is lost: ReportCrash has written
// the crash report before the dialog shows it, the XPC services are
// stateless on-demand services that launchd starts again on the next
// lookup (the SELF ingestors too), and mds starts mdworker again for
// whatever it has left to index.
//
// The worker does not try to keep Spotlight away from the job's files: a
// .metadata_never_index file inside a folder is no longer honoured by
// current macOS (only at a volume root), a .noindex workspace name would
// still leave the simulator data in the job account's home indexed, and
// Spotlight's privacy list is a system setting. The lane cleanup is what
// keeps the account clean.
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
	// #155: Spotlight's per-user importer, WebKit's OS-cryptex services and
	// the Lighthouse SELF ingestor extensions.
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
