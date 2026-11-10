package maintenance

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCensus lets a test decide when each census finishes and with what.
type fakeCensus struct {
	mu      sync.Mutex
	started int
	release chan censusOutcome
}

type censusOutcome struct {
	bytes int64
	err   error
}

func newFakeCensus() *fakeCensus { return &fakeCensus{release: make(chan censusOutcome)} }

func (f *fakeCensus) run(ctx context.Context, _ []string, _ string, _ uint32) (int64, error) {
	f.mu.Lock()
	f.started++
	f.mu.Unlock()
	select {
	case o := <-f.release:
		return o.bytes, o.err
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

func (f *fakeCensus) starts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestTracker(t *testing.T) (*censusTracker, *fakeCensus, *fakeClock) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := newFakeCensus()
	clock := &fakeClock{now: time.Date(2026, 11, 7, 17, 0, 0, 0, time.UTC)}
	tr := newCensusTracker(ctx)
	tr.run = f.run
	tr.now = clock.Now
	tr.reserve = 150 * time.Millisecond
	return tr, f, clock
}

var censusRoots = []string{"/Library/macserve/var", "/Users/job"}

func probe(tr *censusTracker, wait time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return tr.account(ctx, censusRoots, "/Users/job", 6202)
}

// probeLeavesTime is a 200 ms probe that also reports whether its context was
// still live when the census step returned: the checks after the census
// (inspect.go) need it.
func probeLeavesTime(tr *censusTracker) (int64, error, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got, err := tr.account(ctx, censusRoots, "/Users/job", 6202)
	return got, err, ctx.Err() == nil
}

// finish completes the running census and waits until the tracker recorded it.
func finish(t *testing.T, tr *censusTracker, f *fakeCensus, o censusOutcome) {
	t.Helper()
	f.release <- o
	deadline := time.Now().Add(5 * time.Second)
	for {
		tr.mu.Lock()
		idle := tr.running == nil
		tr.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("census result was not recorded")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCensusFinishingWithinTheProbeIsUsedFresh(t *testing.T) {
	tr, f, _ := newTestTracker(t)
	go func() { f.release <- censusOutcome{bytes: 100} }()
	got, err := probe(tr, 5*time.Second)
	if err != nil || got != 100 {
		t.Fatalf("got %d, %v; want 100", got, err)
	}
	go func() { f.release <- censusOutcome{bytes: 200} }()
	got, err = probe(tr, 5*time.Second)
	if err != nil || got != 200 {
		t.Fatalf("second probe got %d, %v; want a fresh 200", got, err)
	}
	if f.starts() != 2 {
		t.Fatalf("census started %d times, want once per probe", f.starts())
	}
}

// The Studio failure: a census slower than the probe for longer than health
// lives. Probes must keep reporting the last completed census within
// censusMaxAge instead of timing out until health expires.
func TestSlowCensusDoesNotStarveProbes(t *testing.T) {
	tr, f, clock := newTestTracker(t)
	if _, err := probe(tr, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first probe with no census yet: %v, want inconclusive", err)
	}
	finish(t, tr, f, censusOutcome{bytes: 4096})
	// The next census is slow: every probe for the next 2 minutes times out on it.
	for elapsed := time.Duration(0); elapsed <= 120*time.Second; elapsed += 10 * time.Second {
		got, err, live := probeLeavesTime(tr)
		if err != nil || got != 4096 {
			t.Fatalf("probe at +%s: got %d, %v; want the last census 4096", elapsed, got, err)
		}
		if !live {
			t.Fatalf("probe at +%s: the census step used up the probe's context; the rest of the probe cannot run", elapsed)
		}
		clock.advance(10 * time.Second)
	}
	if f.starts() != 2 {
		t.Fatalf("census started %d times; a running census must not be restarted", f.starts())
	}
	clock.advance(censusMaxAge)
	// #108: a bare "context deadline exceeded" could not be placed against its
	// stage; the inconclusive census names itself.
	if _, err := probe(tr, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "mutable census") {
		t.Fatalf("probe after censusMaxAge: %v, want inconclusive naming the census", err)
	}
	finish(t, tr, f, censusOutcome{bytes: 8192})
	go func() { f.release <- censusOutcome{bytes: 9000} }()
	if got, err := probe(tr, 5*time.Second); err != nil || got != 9000 {
		t.Fatalf("after the slow census: got %d, %v; want fresh 9000", got, err)
	}
}

func TestCensusFindingIsReportedUntilANewerCensus(t *testing.T) {
	tr, f, _ := newTestTracker(t)
	finding := errors.New("mutable mount crossing")
	go func() { f.release <- censusOutcome{bytes: 100} }()
	if _, err := probe(tr, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// A census that finds something after its probe gave up.
	if _, err := probe(tr, 10*time.Millisecond); err != nil {
		t.Fatalf("probe during slow census: %v", err)
	}
	finish(t, tr, f, censusOutcome{bytes: -1, err: finding})
	for i := 0; i < 3; i++ {
		if _, err := probe(tr, 10*time.Millisecond); !errors.Is(err, finding) {
			t.Fatalf("probe %d after the finding: %v; a finding must not be masked by an older census", i, err)
		}
	}
	finish(t, tr, f, censusOutcome{bytes: 300})
	go func() { f.release <- censusOutcome{bytes: 400} }()
	if got, err := probe(tr, 5*time.Second); err != nil || got != 400 {
		t.Fatalf("after a clean census: got %d, %v", got, err)
	}
}

func TestInconclusiveCensusIsNeverReused(t *testing.T) {
	tr, f, _ := newTestTracker(t)
	if _, err := probe(tr, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	finish(t, tr, f, censusOutcome{bytes: 5, err: errAcceptedMountChanged})
	if _, err := probe(tr, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v; an inconclusive census is neither a finding nor evidence", err)
	}
}

func TestCensusForAnotherJobAccountIsNotReused(t *testing.T) {
	tr, f, _ := newTestTracker(t)
	go func() { f.release <- censusOutcome{bytes: 100} }()
	if _, err := probe(tr, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := tr.account(ctx, censusRoots, "/Users/other", 6300); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v; another job account must not use this census", err)
	}
}
