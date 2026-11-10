package maintenance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jerryfane/macserve/internal/worker"
)

// guiBaselineKey names what one GUI-baseline observation checked: the
// protected baseline and persistence records, by content, and the job account.
// An observation of other records is never reused: observeGUIBaselineOf reads
// both records before and after worker.ObserveGUIBaseline loads them, as a
// probe rereads them around its own checks (inspect).
type guiBaselineKey struct {
	baselinePath, persistencePath     string
	baselineSHA256, persistenceSHA256 string
	jobUID                            uint32
}

type guiBaseline struct {
	boot   string
	exited []worker.ProcessIdentity
}

// guiBaselineTracker runs worker.ObserveGUIBaseline in the background (see
// tracker). The check verifies the launchd records of the job GUI session's
// processes with some 250-280 launchctl runs; on the Studio (#108) that took
// 2-3 s, but 6.5 s to more than 7.5 s of the 8 s probe while simulators
// booted, so every probe for over 40 s ran out of time, health expired and
// the job was cancelled. An
// observation runs for up to guiBaselineBudget; a probe may use the last
// completed clean one if it finished within guiBaselineMaxAge. A completed
// observation that found something (a changed or reused audited process, a
// changed launchd environment or persistence record) is reported by every
// probe until a newer observation completes. Only an observation that ran out
// of time is inconclusive, and it is never reused.
type guiBaselineTracker struct {
	tracker[guiBaselineKey, guiBaseline]
	run func(ctx context.Context, key guiBaselineKey) (string, []worker.ProcessIdentity, error)
}

func newGUIBaselineTracker(parent context.Context) *guiBaselineTracker {
	return &guiBaselineTracker{
		tracker: tracker[guiBaselineKey, guiBaseline]{name: "GUI baseline", parent: parent, now: time.Now, budget: guiBaselineBudget, maxAge: guiBaselineMaxAge, reserve: probeReserve, inconclusive: guiBaselineInconclusive},
		run:     observeGUIBaselineOf,
	}
}

func guiBaselineInconclusive(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// observeGUIBaselineOf runs worker.ObserveGUIBaseline for the records key
// names; a record that differs before or after is a finding.
func observeGUIBaselineOf(ctx context.Context, key guiBaselineKey) (string, []worker.ProcessIdentity, error) {
	if err := key.unchanged(); err != nil {
		return "", nil, err
	}
	boot, exited, err := worker.ObserveGUIBaseline(ctx, key.baselinePath, key.persistencePath, key.jobUID)
	if err != nil {
		return "", nil, err
	}
	return boot, exited, key.unchanged()
}

func (k guiBaselineKey) unchanged() error {
	for p, want := range map[string]string{k.baselinePath: k.baselineSHA256, k.persistencePath: k.persistenceSHA256} {
		b, err := protectedRead(p)
		if err != nil || digest(b) != want {
			return fmt.Errorf("approval input changed: %s", p)
		}
	}
	return nil
}

// check returns the boot identity and exited audited processes for one probe;
// baseline and persistence are the records the probe read from path and
// persistencePath.
func (t *guiBaselineTracker) check(ctx context.Context, path, persistencePath string, baseline, persistence []byte, uid uint32) (string, []worker.ProcessIdentity, error) {
	key := guiBaselineKey{baselinePath: path, persistencePath: persistencePath, baselineSHA256: digest(baseline), persistenceSHA256: digest(persistence), jobUID: uid}
	g, err := t.observe(ctx, key, func(ctx context.Context) (guiBaseline, error) {
		boot, exited, err := t.run(ctx, key)
		return guiBaseline{boot: boot, exited: exited}, err
	})
	return g.boot, g.exited, err
}
