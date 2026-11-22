package maintenance

import "time"

// healthLifetime is how long one published record stays valid, within the
// controller's 45 s acceptance window (internal/health). Every record the
// daemon publishes gets its own, so a daemon that stops publishing cancels
// active work within it whatever the last record said.
const healthLifetime = 40 * time.Second

// DefaultProbeOutage is Config.ProbeOutageSeconds when unset: how long after
// the last valid health probes that fail without evidence (withoutEvidence)
// may carry its facts, blocking admission only, before the next one
// publishes invalid health, which cancels active work. Three heavy jobs
// (load 53 on 36 cores) made probes time out for over 40 s and the expiry
// of the last valid health cancelled all three, which then could not be
// cleaned up under the same load (Studio 2026-11-18 09:50Z, #194). Ten
// minutes outlasts such a load peak; an outage longer than that is treated
// as lost maintenance.
const DefaultProbeOutage = 10 * time.Minute

// censusBudget bounds one background byte census (see censusTracker). Under
// heavy builds a census of the workspaces and job home has outlasted the 8 s
// probe for minutes; it now keeps running instead of failing each probe.
const censusBudget = 120 * time.Second

// censusMaxAge is how long a completed successful census may stand in for one
// still running. It is the worst-case age of the accounted bytes and of the
// census's mount and special-file checks in published health.
const censusMaxAge = 150 * time.Second

// censusInterval is the least time between the starts of two byte censuses
// while the latest one is usable. Started at every probe, the full walk of
// the workspaces and job home (~73 GB) ran back to back and cost the daemon
// about one CPU core around the clock, competing with the jobs it guards
// (Studio 2026-11-22, #215). The next census starts at the first probe after
// censusInterval, so with the probe cadence P (10 s) and a census taking R,
// accounted bytes are now up to about censusInterval + P + R old instead of
// R. That stays within censusMaxAge while R stays under about 80 s; a census
// slower than that now leaves probes inconclusive until it completes, where
// back to back it did so only beyond censusMaxAge. Inconclusive is never a
// finding: it blocks admission and cancels nothing within the probe outage
// bound.
const censusInterval = 60 * time.Second

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
