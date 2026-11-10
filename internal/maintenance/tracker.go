package maintenance

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// background holds the daemon's slow observations, which outlive one probe
// (see tracker). A nil background runs each of them within the probe's own
// context, as Check and Inspect do.
type background struct {
	census   *censusTracker
	baseline *guiBaselineTracker
}

func newBackground(parent context.Context) *background {
	return &background{census: newCensusTracker(parent), baseline: newGUIBaselineTracker(parent)}
}

// tracker decouples one slow observation from the 8 s probe: the byte census
// (censusTracker) and the GUI-baseline process check (guiBaselineTracker).
// Under heavy builds or booting simulators either can take longer than the
// probe for minutes at a time; when every probe then timed out, health
// expired and the controller cancelled the running job although nothing was
// wrong.
//
// Each probe starts an observation if none is running and waits for it until
// reserve before the probe's own deadline, so an observation that finishes in
// time is used fresh, as before. One that is still running keeps running in
// the background with its own budget and is not restarted by later probes.
// While it runs, a probe may use the last completed conclusive observation of
// the same key if it finished within maxAge. A completed observation that
// found something (any error inconclusive does not accept) is reported by
// every probe until a newer observation of that key completes. An
// inconclusive observation (budget exceeded, or one inconclusive accepts) is
// never reused. A probe without a usable observation is inconclusive, never a
// finding, and its error names the observation.
type tracker[K comparable, T any] struct {
	name         string // names the observation in an inconclusive probe's error
	parent       context.Context
	now          func() time.Time
	budget       time.Duration
	maxAge       time.Duration
	reserve      time.Duration // probe time kept for the checks after the observation
	inconclusive func(error) bool
	mu           sync.Mutex
	running      *trackedRun[K, T]
	latest       *trackedResult[K, T]
	usable       *trackedResult[K, T] // latest successful, conclusive result
}

type trackedResult[K comparable, T any] struct {
	key      K
	value    T
	err      error
	finished time.Time
}

type trackedRun[K comparable, T any] struct {
	key  K
	done chan struct{}
	res  trackedResult[K, T]
}

// start begins an observation for key unless one is running; it returns the
// running one.
func (t *tracker[K, T]) start(key K, run func(context.Context) (T, error)) *trackedRun[K, T] {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running != nil {
		return t.running
	}
	r := &trackedRun[K, T]{key: key, done: make(chan struct{})}
	t.running = r
	ctx, cancel := context.WithTimeout(t.parent, t.budget)
	go func() {
		defer cancel()
		value, err := run(ctx)
		res := trackedResult[K, T]{key: key, value: value, err: err, finished: t.now()}
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

// observe returns the observation for one probe. It waits for the running
// observation only until reserve before the probe's deadline, so the probe
// still has time for its remaining checks when it falls back to the last one.
func (t *tracker[K, T]) observe(ctx context.Context, key K, run func(context.Context) (T, error)) (T, error) {
	var none T
	r := t.start(key, run)
	if err := t.finding(key); err != nil {
		return none, err
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
				return r.res.value, nil
			}
			if !t.inconclusive(r.res.err) {
				return none, r.res.err
			}
		case <-wait.Done():
		}
	}
	// One that completed with a finding while this probe waited is reported,
	// not masked by an older clean one.
	if err := t.finding(key); err != nil {
		return none, err
	}
	t.mu.Lock()
	usable := t.usable
	t.mu.Unlock()
	if usable != nil && usable.key == key && t.now().Sub(usable.finished) <= t.maxAge {
		return usable.value, nil
	}
	if err := ctx.Err(); err != nil {
		return none, fmt.Errorf("%s: %w", t.name, err)
	}
	// No current evidence: report it as inconclusive, never as a finding.
	return none, fmt.Errorf("%s: none completed conclusively within %v: %w", t.name, t.maxAge, context.DeadlineExceeded)
}

// finding returns the error of the latest completed observation of key if it
// found something.
func (t *tracker[K, T]) finding(key K) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if l := t.latest; l != nil && l.key == key && l.err != nil && !t.inconclusive(l.err) {
		return l.err
	}
	return nil
}
