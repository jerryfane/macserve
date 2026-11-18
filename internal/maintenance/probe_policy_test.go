package maintenance

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/worker"
)

// documentedProbeOutage is the documented default probe outage bound
// (probe_outage_seconds unset; docs/configuration.md).
const documentedProbeOutage = 10 * time.Minute

// probeStep is one probe of a replayed run loop: when it starts (from the
// first probe), how long it takes and its error (nil: a valid observation,
// measuring accounted bytes of service disk; 0 means the fixture's).
type probeStep struct {
	start, took time.Duration
	err         error
	accounted   int64
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
		observed := o
		if s.accounted != 0 {
			observed.AccountedBytes = s.accounted
		}
		h, err := Evaluate(done, q, e, observed)
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

// outage is a valid probe at 0, then probes every 10 s until last that each
// fail without evidence (the probe's deadline, or a protected-input ACL
// inspection killed at it, as on the Studio).
func outage(last time.Duration) []probeStep {
	steps := []probeStep{{0, 3 * time.Second, nil, 0}}
	for at := 10 * time.Second; at <= last; at += 10 * time.Second {
		err := probeDeadline
		if at%(20*time.Second) == 0 {
			err = aclKilled
		}
		steps = append(steps, probeStep{at, 8 * time.Second, err, 0})
	}
	return steps
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
		{0, 3 * time.Second, nil, 0},
		{10 * time.Second, 7 * time.Second, aclKilled, 0},
		{20 * time.Second, 8 * time.Second, probeDeadline, 0},
		{30 * time.Second, 4 * time.Second, nil, 0},
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

// Studio v0.1.49, 2026-11-13 11:01:24Z: `launchctl print` of a configured
// coexisting service exited but its pipes did not close within WaitDelay
// (exec.ErrWaitDelay), a timing failure of the inspection, not a finding. It
// published invalid health and cancelled the running job; the next probe was
// clean. It must republish the last valid health and only block admission.
func TestCoexistingServiceWaitDelayBlocksAdmissionWithoutCancelling(t *testing.T) {
	c, f := coexistenceInputs()
	f["print system/org.example.gateway"] = coexistenceReply{err: exec.ErrWaitDelay}
	_, waitDelay := observeCoexistenceWithCommands(context.Background(), c, f.command, f.command)
	if waitDelay == nil {
		t.Fatal("coexistence observation ignored the WaitDelay failure")
	}
	gates := replayPublications(t, []probeStep{
		{0, 3 * time.Second, nil, 0},
		{10 * time.Second, 2 * time.Second, waitDelay, 0},
		{20 * time.Second, 3 * time.Second, nil, 0},
	})
	if g := gates[1]; g.cancel || g.failures != 1 || strings.Join(g.blockers, ",") != "maintenance_probe_failed" {
		t.Fatalf("WaitDelay probe: %+v (%v)", g, waitDelay)
	}
	if g := gates[2]; g.cancel || g.failures != 0 || len(g.blockers) != 0 {
		t.Fatalf("valid probe after WaitDelay: %+v", g)
	}
}

// Studio v0.1.69, 2026-11-18 09:49-09:50Z (#194): three heavy jobs (load 53
// on 36 cores) made the protected-input ACL inspection and the GUI-baseline
// check time out five probes in a row. The last valid health expired at
// 09:50:21, the next probe published invalid health and the controller
// cancelled all three running jobs (isolation_unavailable), whose cleanup
// then failed under the same load: an owner restart. Probes that only run
// out of time block admission and never cancel for as long as the probe
// outage bound (10 minutes by default) after the last valid health, however
// many in a row, and a valid probe ends the outage.
func TestProbeTimeoutsWithinOutageBoundNeverCancel(t *testing.T) {
	steps := outage(documentedProbeOutage - 10*time.Second)
	steps = append(steps, probeStep{documentedProbeOutage, 3 * time.Second, nil, 0})
	gates := replayPublications(t, steps)
	for i, g := range gates[1 : len(gates)-1] {
		if g.cancel || g.failures != i+1 || strings.Join(g.blockers, ",") != "maintenance_probe_failed" {
			t.Fatalf("failed probe %d at +%v: %+v", i+1, steps[i+1].start, g)
		}
	}
	if last := gates[len(gates)-1]; last.cancel || last.failures != 0 || len(last.blockers) != 0 {
		t.Fatalf("valid probe after the outage: %+v", last)
	}
}

// Guard (passes before #194 by design): probes that keep failing without
// evidence past the probe outage bound publish invalid health, which
// cancels, naming only what is known: isolation_unavailable and the failed
// probes, never a disk or memory blocker nothing measured (the 09:50Z
// record named service_disk_budget_exceeded and host_memory_pressure with
// 377 GB free and no memory pressure).
func TestProbeOutageBeyondBoundCancels(t *testing.T) {
	steps := outage(documentedProbeOutage + 30*time.Second)
	gates := replayPublications(t, steps)
	for i, g := range gates[1:] {
		if steps[i+1].start+steps[i+1].took < documentedProbeOutage {
			continue
		}
		if !g.cancel || g.failures != i+1 || g.blockers[0] != "isolation_unavailable" {
			t.Fatalf("failed probe %d at +%v, past the outage bound: %+v", i+1, steps[i+1].start, g)
		}
	}
}

// The invalid health published after the outage bound names no blocker for
// a fact it did not measure.
func TestInvalidHealthNamesOnlyMeasuredBlockers(t *testing.T) {
	gates := replayPublications(t, outage(documentedProbeOutage+10*time.Second))
	if g := gates[len(gates)-1]; !g.cancel || strings.Join(g.blockers, ",") != "isolation_unavailable,maintenance_probe_failed,persistence_attestation_unavailable" {
		t.Fatalf("invalid health after the outage bound: %+v", g)
	}
}

// Guard (passes before #53 and #194 by design): a finding cancels at once,
// and the last valid health it replaced is forgotten, so a later failure
// without evidence cannot bring it back; a measured breach in the last valid
// health (service disk over budget) keeps cancelling while probes time out.
func TestFindingsAndMeasuredBreachesStillCancel(t *testing.T) {
	gates := replayPublications(t, []probeStep{
		{0, 3 * time.Second, nil, 0},
		{10 * time.Second, 2 * time.Second, baselineChange, 0},
		{20 * time.Second, 8 * time.Second, probeDeadline, 0},
	})
	for i, g := range gates[1:] {
		if !g.cancel || g.failures != 0 || g.blockers[0] != "isolation_unavailable" {
			t.Fatalf("probe %d after a finding: %+v", i+1, g)
		}
	}
	gates = replayPublications(t, []probeStep{
		{0, 3 * time.Second, nil, health.ServiceBudget(1) + 1},
		{10 * time.Second, 8 * time.Second, probeDeadline, 0},
		{20 * time.Second, 8 * time.Second, aclKilled, 0},
	})
	for i, g := range gates {
		if !g.cancel || !slices.Contains(g.blockers, "service_disk_budget_exceeded") {
			t.Fatalf("probe %d after a measured disk breach: %+v", i, g)
		}
	}
}

// Only the closed list of failures without evidence is counted; anything else,
// including the daemon's own shutdown and look-alike text, is a finding.
func TestWithoutEvidenceIsAClosedList(t *testing.T) {
	for _, err := range []error{probeDeadline, aclKilled, fmt.Errorf("census: %w", errAcceptedMountChanged), fmt.Errorf("coexisting: %w", errCoexistingServiceRestarting), fmt.Errorf("coexisting: %w", exec.ErrWaitDelay)} {
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
		errors.New("exec: WaitDelay expired before I/O complete"),
		&exec.ExitError{},
	} {
		if withoutEvidence(err) {
			t.Errorf("%v: counted as a failure without evidence", err)
		}
	}
}
