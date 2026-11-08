package maintenance

import "time"

// healthLifetime is how long one published observation stays valid. With a
// 10 s probe cadence it must outlast two consecutive inconclusive probes (seen
// on the Studio under build load: the third probe then starts at +30 s and
// finishes within its 8 s bound), and stay within the controller's 45 s
// acceptance window (internal/health).
const healthLifetime = 40 * time.Second

// censusBudget bounds one background byte census (see censusTracker). Under
// heavy builds a census of the workspaces and job home has outlasted the 8 s
// probe for minutes; it now keeps running instead of failing each probe.
const censusBudget = 120 * time.Second

// censusMaxAge is how long a completed successful census may stand in for one
// still running. It is the worst-case age of the accounted bytes and of the
// census's mount and special-file checks in published health; every other
// fact in health is observed afresh by each probe.
const censusMaxAge = 150 * time.Second
