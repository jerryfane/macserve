package maintenance

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/worker"
)

type guiOutcome struct {
	boot   string
	exited []worker.ProcessIdentity
	err    error
}

// fakeGUIBaseline lets a test decide when each observation finishes and with what.
type fakeGUIBaseline struct {
	mu      sync.Mutex
	started int
	release chan guiOutcome
}

func (f *fakeGUIBaseline) run(ctx context.Context, _ guiBaselineKey) (string, []worker.ProcessIdentity, error) {
	f.mu.Lock()
	f.started++
	f.mu.Unlock()
	select {
	case o := <-f.release:
		return o.boot, o.exited, o.err
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
}

func (f *fakeGUIBaseline) starts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started
}

func newTestGUIBaselineTracker(t *testing.T) (*guiBaselineTracker, *fakeGUIBaseline, *fakeClock) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &fakeGUIBaseline{release: make(chan guiOutcome)}
	clock := &fakeClock{now: time.Date(2026, 11, 10, 10, 18, 24, 0, time.UTC)}
	tr := newGUIBaselineTracker(ctx)
	tr.run = f.run
	tr.now = clock.Now
	tr.reserve = 150 * time.Millisecond
	return tr, f, clock
}

var testBaseline, testPersistence = []byte(`{"processes":[812]}`), []byte(`{"persistence":1}`)

// checkBaseline is one probe's GUI-baseline step with the given time left; it
// also reports whether the probe's context was still live afterwards.
func checkBaseline(tr *guiBaselineTracker, wait time.Duration, baseline []byte) (string, []worker.ProcessIdentity, error, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	boot, exited, err := tr.check(ctx, "/baseline.json", "/persistence.json", baseline, testPersistence, 6202)
	return boot, exited, err, ctx.Err() == nil
}

// finishGUI completes the running observation and waits until the tracker
// recorded it.
func finishGUI(t *testing.T, tr *guiBaselineTracker, f *fakeGUIBaseline, o guiOutcome) {
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
			t.Fatal("GUI-baseline result was not recorded")
		}
		time.Sleep(time.Millisecond)
	}
}

// #108, Studio 2026-11-10 10:18-10:19 (three simulators booting): with the
// GUI-baseline check inside the probe, every probe for 41 s ran out of time in
// it, health expired and the controller cancelled the job. A check slower than
// the probe for longer than health lives must leave each probe the last clean
// observation and time for its remaining checks.
func TestSlowGUIBaselineDoesNotStarveProbes(t *testing.T) {
	tr, f, clock := newTestGUIBaselineTracker(t)
	exited := []worker.ProcessIdentity{{PID: 812, Start: "1762769904:118"}}
	go func() { f.release <- guiOutcome{boot: "boot-1", exited: exited} }()
	if boot, _, err, _ := checkBaseline(tr, 5*time.Second, testBaseline); err != nil || boot != "boot-1" {
		t.Fatalf("observation finishing within the probe: got %q, %v", boot, err)
	}
	for elapsed := time.Duration(0); elapsed <= healthLifetime; elapsed += 10 * time.Second {
		boot, got, err, live := checkBaseline(tr, 200*time.Millisecond, testBaseline)
		if err != nil || boot != "boot-1" || !reflect.DeepEqual(got, exited) {
			t.Fatalf("probe at +%s: got %q %v, %v; want the last clean observation", elapsed, boot, got, err)
		}
		if !live {
			t.Fatalf("probe at +%s: the GUI-baseline step used up the probe's context", elapsed)
		}
		clock.advance(10 * time.Second)
	}
	if f.starts() != 2 {
		t.Fatalf("observation started %d times; a running one must not be restarted", f.starts())
	}
	finishGUI(t, tr, f, guiOutcome{boot: "boot-1"})
	go func() { f.release <- guiOutcome{boot: "boot-1"} }()
	if _, got, err, _ := checkBaseline(tr, 5*time.Second, testBaseline); err != nil || got != nil {
		t.Fatalf("after the slow observation: got %v, %v; want a fresh one", got, err)
	}
}

// Guard: a GUI-baseline check that stays inconclusive still fails closed. No
// valid health is published from an observation older than guiBaselineMaxAge,
// and invalid health replaces the last valid record once it expires.
func TestGUIBaselineInconclusiveBeyondMaxAgeFailsClosed(t *testing.T) {
	tr, f, clock := newTestGUIBaselineTracker(t)
	go func() { f.release <- guiOutcome{boot: "boot-1"} }()
	if _, _, err, _ := checkBaseline(tr, 5*time.Second, testBaseline); err != nil {
		t.Fatal(err)
	}
	clean := clock.Now()
	// The next observation never completes. Replay the daemon loop's decision
	// at the 10 s cadence (Run): a valid probe publishes, an inconclusive one
	// keeps the last valid health only until it expires.
	var last health.Health
	for {
		now := clock.Now()
		if now.Sub(clean) > 10*time.Minute {
			t.Fatal("invalid health was never published")
		}
		_, _, err, _ := checkBaseline(tr, 10*time.Millisecond, testBaseline)
		if err == nil {
			if now.Sub(clean) > guiBaselineMaxAge {
				t.Fatalf("valid health at +%s from an observation older than %s", now.Sub(clean), guiBaselineMaxAge)
			}
			last = health.Health{BoundaryValidated: true, CheckedAt: now, ExpiresAt: now.Add(healthLifetime)}
		} else {
			if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "GUI baseline") {
				t.Fatalf("got %v; want an inconclusive probe naming the GUI baseline", err)
			}
			if !keepLastValid(err, last, now) {
				if bound := guiBaselineMaxAge + healthLifetime + 10*time.Second; now.Sub(clean) > bound {
					t.Fatalf("invalid health published at +%s, later than %s", now.Sub(clean), bound)
				}
				return
			}
		}
		clock.advance(10 * time.Second)
	}
}

// An observation is evidence only for the records it checked, and a finding is
// never masked by an older clean observation.
func TestGUIBaselineNeverReusedAcrossFindingsOrRecords(t *testing.T) {
	tr, f, _ := newTestGUIBaselineTracker(t)
	go func() { f.release <- guiOutcome{boot: "boot-1"} }()
	if _, _, err, _ := checkBaseline(tr, 5*time.Second, testBaseline); err != nil {
		t.Fatal(err)
	}
	reset := []byte(`{"processes":[812,977]}`)
	if _, _, err, _ := checkBaseline(tr, 10*time.Millisecond, reset); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v; an observation of the previous baseline record must not stand in for a new one", err)
	}
	finishGUI(t, tr, f, guiOutcome{boot: "boot-1"})
	if _, _, err, _ := checkBaseline(tr, 10*time.Millisecond, reset); err != nil {
		t.Fatalf("probe during the next observation: %v", err)
	}
	finding := errors.New("GUI baseline process changed; worker-reset required")
	finishGUI(t, tr, f, guiOutcome{err: finding})
	valid := health.Health{BoundaryValidated: true, ExpiresAt: time.Now().Add(time.Minute)}
	for i := range 3 {
		_, _, err, _ := checkBaseline(tr, 10*time.Millisecond, reset)
		if !errors.Is(err, finding) {
			t.Fatalf("probe %d after the finding: %v; a finding must not be masked by an older observation", i, err)
		}
		if keepLastValid(err, valid, time.Now()) {
			t.Fatalf("probe %d: a GUI-baseline finding kept the last valid health", i)
		}
	}
}
