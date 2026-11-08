package maintenance

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// censusKey names what one byte census measured. A result for another key
// (the job account or its home changed) is never reused.
type censusKey struct {
	roots   string
	jobHome string
	jobUID  uint32
}

type censusResult struct {
	key      censusKey
	bytes    int64
	err      error
	finished time.Time
}

// censusTracker decouples the byte census from the 8 s probe. Under a heavy
// build the census of the workspaces and job home (a full lstat walk at launchd
// ProcessType=Background) can take longer than the probe for minutes at a
// time; when every probe then timed out, health expired and the controller
// cancelled the running job although nothing was wrong.
//
// Each probe starts a census if none is running and waits for it until the
// probe's own deadline, so a census that finishes in time is used fresh, as
// before. A census that is still running keeps running in the background with
// its own budget (censusBudget) and is not restarted by later probes. While it
// runs, a probe may use the last completed successful census if it finished
// within censusMaxAge. A completed census that found something (a mount
// crossing, a special file, a bound) is reported by every probe until a newer
// census completes. An inconclusive census (budget exceeded, CoreDevice mount
// changed) is never reused.
type censusTracker struct {
	parent  context.Context
	run     func(ctx context.Context, roots []string, jobHome string, jobUID uint32) (int64, error)
	now     func() time.Time
	budget  time.Duration
	maxAge  time.Duration
	reserve time.Duration // probe time kept for the checks after the census
	mu      sync.Mutex
	running *censusRun
	latest  *censusResult
	usable  *censusResult // latest successful, conclusive result
}

type censusRun struct {
	key  censusKey
	done chan struct{}
	res  censusResult
}

func newCensusTracker(parent context.Context) *censusTracker {
	return &censusTracker{parent: parent, run: accountBytes, now: time.Now, budget: censusBudget, maxAge: censusMaxAge, reserve: censusProbeReserve}
}

func censusInconclusive(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, errCoreDeviceMountChanged)
}

// start begins a census for key unless one is running; it returns the running one.
func (t *censusTracker) start(key censusKey, roots []string) *censusRun {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running != nil {
		return t.running
	}
	r := &censusRun{key: key, done: make(chan struct{})}
	t.running = r
	ctx, cancel := context.WithTimeout(t.parent, t.budget)
	go func() {
		defer cancel()
		bytes, err := t.run(ctx, roots, key.jobHome, key.jobUID)
		res := censusResult{key: key, bytes: bytes, err: err, finished: t.now()}
		t.mu.Lock()
		r.res = res
		t.latest = &res
		if err == nil {
			t.usable = &res
		}
		t.running = nil
		t.mu.Unlock()
		close(r.done)
	}()
	return r
}

// account returns the accounted bytes for one probe. It waits for the running
// census only until reserve before the probe's deadline, so the probe still has
// time for its remaining checks when it falls back to the last census.
func (t *censusTracker) account(ctx context.Context, roots []string, jobHome string, jobUID uint32) (int64, error) {
	key := censusKey{roots: strings.Join(roots, "\x00"), jobHome: jobHome, jobUID: jobUID}
	r := t.start(key, roots)
	t.mu.Lock()
	latest := t.latest
	t.mu.Unlock()
	if latest != nil && latest.key == key && latest.err != nil && !censusInconclusive(latest.err) {
		return -1, latest.err
	}
	if r.key == key {
		wait := ctx
		if deadline, ok := ctx.Deadline(); ok {
			var cancel context.CancelFunc
			wait, cancel = context.WithDeadline(ctx, deadline.Add(-t.reserve))
			defer cancel()
		}
		select {
		case <-r.done:
			if r.res.err == nil {
				return r.res.bytes, nil
			}
			if !censusInconclusive(r.res.err) {
				return -1, r.res.err
			}
		case <-wait.Done():
		}
	}
	t.mu.Lock()
	usable := t.usable
	t.mu.Unlock()
	if usable != nil && usable.key == key && t.now().Sub(usable.finished) <= t.maxAge {
		return usable.bytes, nil
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	// No current census evidence: report it as inconclusive, never as a finding.
	return -1, context.DeadlineExceeded
}
