package maintenance

import "time"

// healthLifetime is how long one published observation stays valid. With a
// 10 s probe cadence it must outlast health.ProbeFailureLimit (3) consecutive
// probes that failed without evidence (seen on the Studio under build load:
// the third starts at +30 s and publishes within its 8 s bound), so that count
// rather than expiry decides when failed probes cancel active work, and stay
// within the controller's 45 s acceptance window (internal/health). It is also
// the bound on how long a republished last valid health keeps active work.
const healthLifetime = 40 * time.Second

// censusBudget bounds one background byte census (see censusTracker). Under
// heavy builds a census of the workspaces and job home has outlasted the 8 s
// probe for minutes; it now keeps running instead of failing each probe.
const censusBudget = 120 * time.Second

// censusMaxAge is how long a completed successful census may stand in for one
// still running. It is the worst-case age of the accounted bytes and of the
// census's mount and special-file checks in published health.
const censusMaxAge = 150 * time.Second

// guiBaselineBudget bounds one background GUI-baseline observation (see
// guiBaselineTracker). With three simulators booting on the Studio (#108) it
// outlasted every 8 s probe for more than 40 s; unloaded it takes 2-3 s.
const guiBaselineBudget = 30 * time.Second

// guiBaselineMaxAge is how long a completed clean GUI-baseline observation may
// stand in for one still running: the worst-case age, at a probe's GUI-baseline
// step, of the boot identity, the audited-process and launchd-environment
// checks and the exited audited processes in published health (their process
// table is read at the start of the observation, at most guiBaselineBudget
// before it completes). The next observation starts at the first probe after
// one completes, within the 10 s cadence plus the time that probe takes to
// reach the step (its first persistence-status read: 3 s seen under load, 5 s
// bound), and completes within guiBaselineBudget, so observations that keep
// completing within their budget never leave a probe without one. Every fact
// other than these and the census's is observed afresh by each probe.
const guiBaselineMaxAge = 45 * time.Second

// probeReserve is the part of a probe's 8 s budget kept for the checks that
// follow a background observation (persistence status, coexistence,
// protected-record rereads) when a probe stops waiting for a running one and
// uses the last.
const probeReserve = 4 * time.Second
