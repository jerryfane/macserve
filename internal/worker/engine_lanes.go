package worker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// Engine lane state. With Options.Lanes == 1 the engine runs one job at a
// time and every job owns the whole job account, exactly as before lanes:
// admission, preflight and final cleanup quiesce every non-baseline job-UID
// process. With more lanes:
//
//   - a job that starts while no other job runs ("solo") is admitted by the
//     full admission and preflight quiesce, and no other job starts until
//     that preflight ends;
//   - a job that starts beside others is admitted by LaneAdmission: other
//     jobs' processes are not residual, and an unattributed process refuses
//     (drain) instead of quarantining;
//   - a job whose finalization begins while no other job runs ends with the
//     full quiesce and admission (idle verdict "clean"), and no other job
//     starts until it ends;
//   - a job whose finalization begins beside others stops only its own
//     simulator and labelled processes (QuiesceJob) and then counts
//     unattributed processes: none gives idle verdict "not_required"; any
//     gives "deferred", an unverified cleanup, and drains the engine;
//   - while draining no job starts; Recover, which runs only when no job
//     runs, applies the full quiesce and admission and then admits again.
//
// simulator_script and ios_archive jobs run only alone (model.Kind.Exclusive).

type laneEntry struct {
	start     time.Time
	exclusive bool
}

type laneSpan struct {
	job        string
	start, end time.Time
}

// lanes is the configured concurrency, at least 1.
func (e *Engine) lanes() int { return max(e.options.Lanes, 1) }

// laneMode reports whether jobs may overlap.
func (e *Engine) laneMode() bool { return e.lanes() > 1 }

// changedLocked wakes every enter waiting for the account; mu is held.
func (e *Engine) changedLocked() {
	close(e.changed)
	e.changed = make(chan struct{})
}

// enter admits job into a lane. solo reports that no other job runs, so the
// job holds the whole account until releaseAccount. It waits while another
// job holds the account for a full-account step.
func (e *Engine) enter(ctx context.Context, job model.Job) (solo bool, err error) {
	for {
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return false, ErrClosed
		}
		if e.recovering {
			e.mu.Unlock()
			return false, ErrBusy
		}
		if _, dup := e.running[job.ID]; dup {
			e.mu.Unlock()
			return false, ErrBusy
		}
		if !e.laneMode() {
			if len(e.running) != 0 {
				e.mu.Unlock()
				return false, ErrBusy
			}
		} else {
			if e.drain != "" {
				reason := e.drain
				e.mu.Unlock()
				return false, fmt.Errorf("%w: %s", ErrDrain, reason)
			}
			exclusive := job.Request.Kind.Exclusive()
			for _, other := range e.running {
				exclusive = exclusive || other.exclusive
			}
			if len(e.running) >= e.lanes() || len(e.running) != 0 && exclusive {
				e.mu.Unlock()
				return false, ErrBusy
			}
		}
		if e.accountHeld == "" {
			solo = len(e.running) == 0
			e.running[job.ID] = &laneEntry{start: e.options.Now(), exclusive: job.Request.Kind.Exclusive()}
			if solo && e.laneMode() {
				e.accountHeld = job.ID
			}
			e.mu.Unlock()
			return solo, nil
		}
		wait := e.changed
		e.mu.Unlock()
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-wait:
		}
	}
}

// releaseAccount ends jobID's hold on the whole account, if it has one.
func (e *Engine) releaseAccount(jobID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.accountHeld == jobID {
		e.accountHeld = ""
		e.changedLocked()
	}
}

// holdAccountIfAlone takes the whole account for jobID's finalization when no
// other job runs, reporting whether it did.
func (e *Engine) holdAccountIfAlone(jobID string) bool {
	if !e.laneMode() {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.accountHeld == jobID {
		return true
	}
	if len(e.running) != 1 || e.running[jobID] == nil || e.accountHeld != "" {
		return false
	}
	e.accountHeld = jobID
	return true
}

// leave removes jobID from its lane and records its execution span.
func (e *Engine) leave(jobID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.running[jobID]
	if entry == nil {
		return
	}
	delete(e.running, jobID)
	now := e.options.Now()
	e.spans = append(e.spans, laneSpan{job: jobID, start: entry.start, end: now})
	// Keep only spans that can still overlap a running job.
	oldest := now
	for _, r := range e.running {
		if r.start.Before(oldest) {
			oldest = r.start
		}
	}
	e.spans = slices.DeleteFunc(e.spans, func(s laneSpan) bool { return len(e.running) == 0 || s.end.Before(oldest) })
	if e.accountHeld == jobID {
		e.accountHeld = ""
	}
	// e.verified[jobID] outlives the job: the client seals VerifiedTree after
	// Execute returns, and RemoveExport forgets it once delivery is acked.
	e.changedLocked()
}

// overlaps lists every job that ran in the engine while jobID did, with the
// overlap in whole seconds, sorted by job ID.
func (e *Engine) overlaps(jobID string) []Overlap {
	e.mu.Lock()
	defer e.mu.Unlock()
	entry := e.running[jobID]
	out := []Overlap{}
	if entry == nil {
		return out
	}
	now := e.options.Now()
	add := func(id string, start, end time.Time) {
		from := start
		if entry.start.After(from) {
			from = entry.start
		}
		if id == jobID || end.Before(from) {
			return
		}
		out = append(out, Overlap{JobID: id, Seconds: int64(end.Sub(from) / time.Second)})
	}
	for id, r := range e.running {
		add(id, r.start, now)
	}
	for _, s := range e.spans {
		add(s.job, s.start, s.end)
	}
	slices.SortFunc(out, func(a, b Overlap) int { return strings.Compare(a.JobID, b.JobID) })
	return out
}

// setDrain stops new jobs until Recover verifies the idle account.
func (e *Engine) setDrain(reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.drain == "" {
		e.drain = reason
	}
	e.idlePending = true
}

// LaneReady reports whether a new job could start beside the running ones:
// ErrDrain when the engine drains or an unattributed job-account process is
// present (which then drains it), ErrBusy when every lane is taken or an
// exclusive job runs. With one lane or no job running it is nil: the next
// start is admitted by the full admission. A passing census is reused for
// laneReadyReuse.
func (e *Engine) LaneReady(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ErrClosed
	}
	if e.drain != "" {
		reason := e.drain
		e.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrDrain, reason)
	}
	running := len(e.running)
	exclusive := false
	for _, r := range e.running {
		exclusive = exclusive || r.exclusive
	}
	fresh := e.options.Now().Sub(e.readyAt) < laneReadyReuse
	e.mu.Unlock()
	if !e.laneMode() || running == 0 {
		return nil
	}
	if running >= e.lanes() || exclusive {
		return ErrBusy
	}
	if fresh {
		return nil
	}
	lanes, ok := e.options.Runner.(laneRunner)
	if !ok {
		return ErrBusy
	}
	residue, err := lanes.Residue(ctx)
	if err != nil {
		return err
	}
	if residue != 0 {
		e.setDrain(fmt.Sprintf("%d unattributed job-account process(es) while jobs run", residue))
		return fmt.Errorf("%w: unattributed job-account process(es)", ErrDrain)
	}
	e.mu.Lock()
	e.readyAt = e.options.Now()
	e.mu.Unlock()
	return nil
}

const laneReadyReuse = 15 * time.Second

// Running reports how many jobs execute now.
func (e *Engine) Running() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.running)
}

// laneRunner is the runner's lane interface; New refuses lanes without it.
func (e *Engine) laneRunner() laneRunner {
	lanes, _ := e.options.Runner.(laneRunner)
	return lanes
}

// accountQuiesce stops job processes for jobID: every non-baseline job-UID
// process when jobID holds the whole account (or with one lane, or for
// recovery's jobID ""), else only jobID's labelled processes.
func (e *Engine) accountQuiesce(ctx context.Context, jobID string) error {
	if jobID == "" || !e.laneMode() || e.holdsAccount(jobID) {
		return e.options.Runner.Quiesce(ctx)
	}
	return e.laneRunner().QuiesceJob(ctx, jobID)
}

func (e *Engine) holdsAccount(jobID string) bool {
	if !e.laneMode() {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.accountHeld == jobID
}

var errLaneResidue = errors.New("unattributed job-account processes remained while other jobs ran; cleanup is verified when the worker is idle")

// siblingManifests reports whether every resource manifest in names belongs
// to another running job: any other manifest is unrecovered state.
func (e *Engine) siblingManifests(jobID string, names []string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, name := range names {
		id, ok := strings.CutSuffix(name, ".json")
		if !ok || id == jobID || e.running[id] == nil {
			return false
		}
	}
	return true
}

// laneResidue counts unattributed job-account processes after a job's lane
// quiesce beside running jobs. Any, or a failed count, leaves the job's
// cleanup unverified until the idle quiesce (errLaneResidue).
func (e *Engine) laneResidue(ctx context.Context, result *Result) error {
	n, err := e.laneRunner().Residue(ctx)
	if err != nil {
		return errors.Join(ErrCleanup, err)
	}
	result.Concurrency.UnattributedResidue = n
	if n != 0 {
		return errLaneResidue
	}
	return nil
}

// finishLane records jobID's lane verdict before it leaves: its overlaps,
// and its idle verdict. A cleanup that is not verified drains the engine,
// and a job that ended beside others leaves the full-account check to the
// next idle Recover. A verified cleanup of a job alone is that idle check.
func (e *Engine) finishLane(jobID string, alone bool, result *Result) {
	c := result.Concurrency
	c.OverlappedJobs = e.overlaps(jobID)
	if !alone && result.CleanupOK && e.checkQuarantine() != nil {
		// Another job's survivor quarantined the account while this one ran.
		result.CleanupOK = false
	}
	switch {
	case !result.CleanupOK:
		c.IdleVerdict = IdleDeferred
	case alone:
		c.IdleVerdict = IdleClean
	default:
		c.IdleVerdict = IdleNotRequired
	}
	if !e.laneMode() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !result.CleanupOK {
		if e.drain == "" {
			e.drain = "job " + jobID + " cleanup unverified"
		}
		e.idlePending = true
	} else if alone {
		e.drain, e.idlePending = "", false
	} else {
		e.idlePending = true
	}
}
