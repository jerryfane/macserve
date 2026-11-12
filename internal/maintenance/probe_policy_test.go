package maintenance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/worker"
)

// probeStep is one probe of a replayed run loop: when it starts (from the
// first probe), how long it takes and its error (nil: a valid observation).
type probeStep struct {
	start, took time.Duration
	err         error
}

// gateAt is what the controller derives at now from a published record: its
// blockers and whether one cancels active work.
type gateAt struct {
	blockers []string
	cancel   bool
	failures int
}

// replayPublications runs the run loop's publication decision (Run) over
// steps and returns the gate the controller derives from each published
// record when it is published. A failed probe's own record is the 13:22
// signature (#108): the empty Observation with the failed persistence-status
// read.
func replayPublications(t *testing.T, steps []probeStep) []gateAt {
	t.Helper()
	start, q, e, o := approvedFixture()
	var r probeRecord
	var gates []gateAt
	for _, s := range steps {
		done := start.Add(s.start + s.took)
		h, err := Evaluate(done, q, e, o)
		if err != nil {
			t.Fatal(err)
		}
		if s.err != nil {
			h, _ = Evaluate(done, Qualification{}, BoundaryEvidence{}, Observation{Persistence: worker.PersistenceAttestationMetadata{Valid: false}})
		}
		published := r.publication(h, s.err, done)
		g := gateAt{failures: published.ProbeFailures}
		for _, b := range health.HealthBlockers(published, done, o.JobUID, o.Profiles, 1) {
			g.blockers = append(g.blockers, b.Name)
			g.cancel = g.cancel || b.Cancel
		}
		gates = append(gates, g)
	}
	return gates
}

var (
	// aclKilled is the persistence-status read whose protected-input ACL
	// inspection was killed at its deadline (Studio 2026-11-10 08:45:12Z).
	aclKilled      = fmt.Errorf("cannot inspect protected input ACL: %w: %w", errors.New("signal: killed"), context.DeadlineExceeded)
	probeDeadline  = fmt.Errorf("mutable census /Users/macservejob: %w", context.DeadlineExceeded)
	baselineChange = errors.New("GUI baseline process changed; worker-reset required")
)

// The v0.1.44 recurrence (#108, 13:22:12Z): two failed probes about 10 s
// apart, then valid health. Each failed probe blocks admission without
// cancelling the running job, and its failed persistence-status read is
// counted as a probe failure, not reported as a persistence violation.
func TestTwoFailedProbesBlockAdmissionWithoutCancelling(t *testing.T) {
	gates := replayPublications(t, []probeStep{
		{0, 3 * time.Second, nil},
		{10 * time.Second, 7 * time.Second, aclKilled},
		{20 * time.Second, 8 * time.Second, probeDeadline},
		{30 * time.Second, 4 * time.Second, nil},
	})
	for i, g := range gates[1:3] {
		if g.cancel || g.failures != i+1 || strings.Join(g.blockers, ",") != "maintenance_probe_failed" {
			t.Fatalf("failed probe %d: %+v", i+1, g)
		}
	}
	if last := gates[3]; last.cancel || last.failures != 0 || len(last.blockers) != 0 {
		t.Fatalf("valid probe after failures: %+v", last)
	}
}

// Probes that fail without evidence block admission and keep active work
// while the last valid health is in force, however many in a row; once it
// has expired the next one publishes invalid health with the count, which
// cancels. Studio v0.1.47, 2026-11-12: valid health 12:27:46, failed probes
// 12:27:58, 12:28:07, 12:28:17 (the third cancelled both lanes), a valid
// probe again 12:28:26 before expiry.
func TestFailedProbesCancelOnlyAtExpiry(t *testing.T) {
	gates := replayPublications(t, []probeStep{
		{0, 3 * time.Second, nil},
		{10 * time.Second, 8 * time.Second, probeDeadline},
		{20 * time.Second, 8 * time.Second, aclKilled},
		{30 * time.Second, 8 * time.Second, probeDeadline},
		{40 * time.Second, 8 * time.Second, probeDeadline},
	})
	if g := gates[2]; g.cancel || g.failures != 2 {
		t.Fatalf("second failed probe: %+v", g)
	}
	if g := gates[3]; g.cancel || g.failures != 3 || strings.Join(g.blockers, ",") != "maintenance_probe_failed" {
		t.Fatalf("third failed probe before expiry: %+v", g)
	}
	if g := gates[4]; !g.cancel || g.failures != 4 || g.blockers[0] != "isolation_unavailable" {
		t.Fatalf("failed probe after expiry: %+v", g)
	}
}

// Guard (passes before #53 by design): a finding cancels at once, and the
// last valid health it replaced is forgotten, so a later failure without
// evidence cannot bring it back; the last valid health's expiry stays the
// bound however few probes failed (here a probe that overran the cadence).
func TestFindingsAndExpiryStillCancelAtOnce(t *testing.T) {
	gates := replayPublications(t, []probeStep{
		{0, 3 * time.Second, nil},
		{10 * time.Second, 2 * time.Second, baselineChange},
		{20 * time.Second, 8 * time.Second, probeDeadline},
	})
	for i, g := range gates[1:] {
		if !g.cancel || g.failures != 0 || g.blockers[0] != "isolation_unavailable" {
			t.Fatalf("probe %d after a finding: %+v", i+1, g)
		}
	}
	gates = replayPublications(t, []probeStep{
		{0, 3 * time.Second, nil},
		{40 * time.Second, 8 * time.Second, probeDeadline},
	})
	if g := gates[1]; !g.cancel || g.failures != 1 || g.blockers[0] != "isolation_unavailable" {
		t.Fatalf("failed probe after the last valid health expired: %+v", g)
	}
}

// Only the closed list of failures without evidence is counted; anything else,
// including the daemon's own shutdown and look-alike text, is a finding.
func TestWithoutEvidenceIsAClosedList(t *testing.T) {
	for _, err := range []error{probeDeadline, aclKilled, fmt.Errorf("census: %w", errAcceptedMountChanged), fmt.Errorf("coexisting: %w", errCoexistingServiceRestarting)} {
		if !withoutEvidence(err) {
			t.Errorf("%v: counted as a finding", err)
		}
	}
	for _, err := range []error{
		baselineChange,
		context.Canceled,
		// Run's wrapping of any probe error while the daemon stops.
		fmt.Errorf("maintenance stopping: %v", probeDeadline),
		errors.New("context deadline exceeded"),
		errors.New("cannot inspect protected input ACL: signal: killed"),
		errors.New("persistence authority or attestation changed during status read"),
		errors.New("maintenance qualification or live observation mismatch"),
	} {
		if withoutEvidence(err) {
			t.Errorf("%v: counted as a failure without evidence", err)
		}
	}
}
