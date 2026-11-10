package maintenance

import (
	"context"
	"errors"
	"strings"
	"time"
)

// censusKey names what one byte census measured. A result for another key
// (the job account or its home changed) is never reused.
type censusKey struct {
	roots   string
	jobHome string
	jobUID  uint32
}

// censusTracker runs the byte census in the background (see tracker). Under a
// heavy build the census of the workspaces and job home (a full lstat walk at
// launchd ProcessType=Background) can take longer than the probe for minutes
// at a time. A census runs for up to censusBudget; a probe may use the last
// completed successful census if it finished within censusMaxAge. A completed
// census that found something (a mount crossing, a special file, a bound) is
// reported by every probe until a newer census completes. An inconclusive
// census (budget exceeded, CoreDevice mount changed) is never reused.
type censusTracker struct {
	tracker[censusKey, int64]
	run func(ctx context.Context, roots []string, jobHome string, jobUID uint32) (int64, error)
}

func newCensusTracker(parent context.Context) *censusTracker {
	return &censusTracker{
		tracker: tracker[censusKey, int64]{name: "mutable census", parent: parent, now: time.Now, budget: censusBudget, maxAge: censusMaxAge, reserve: probeReserve, inconclusive: censusInconclusive},
		run:     accountBytes,
	}
}

func censusInconclusive(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, errAcceptedMountChanged)
}

// account returns the accounted bytes for one probe.
func (t *censusTracker) account(ctx context.Context, roots []string, jobHome string, jobUID uint32) (int64, error) {
	key := censusKey{roots: strings.Join(roots, "\x00"), jobHome: jobHome, jobUID: jobUID}
	bytes, err := t.observe(ctx, key, func(ctx context.Context) (int64, error) { return t.run(ctx, roots, jobHome, jobUID) })
	if err != nil {
		return -1, err
	}
	return bytes, nil
}
