package maintenance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/worker"
)

func TestPeriodicPersistenceScanDoesNotBlockHealthOrOverlap(t *testing.T) {
	now, q, evidence, observation := approvedFixture()
	ctx, cancel := context.WithTimeout(context.Background(), worker.PersistenceOperationTimeout)
	defer cancel()
	started := make(chan time.Duration, 1)
	release := make(chan struct{})
	defer close(release)
	monitor := persistenceMonitor{verify: func(ctx context.Context, _ worker.Options) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			started <- 0
		} else {
			started <- time.Until(deadline)
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}}
	observation.Persistence.LastVerified = now.Add(-6 * time.Hour)
	monitor.schedule(ctx, now, worker.Options{}, observation.Persistence, nil)
	select {
	case remaining := <-started:
		if remaining < 539*time.Second || remaining > 540*time.Second || remaining <= worker.PersistenceFullScanTimeout {
			t.Fatalf("operation deadline truncates collector/publication or is unbounded: %v", remaining)
		}
	case <-time.After(time.Second):
		t.Fatal("due full scan did not start")
	}
	// Neither a running scan nor an old verification timestamp is a TTL-based
	// refusal. Fresh cheap admission checks remain the worker's responsibility.
	if h, err := Evaluate(now, q, evidence, observation); err != nil || !h.BoundaryValidated || !h.PersistenceLastVerified.Equal(observation.Persistence.LastVerified) {
		t.Fatalf("background scan blocked health or claimed fresh verification: %+v %v", h, err)
	}
	first := monitor.done
	monitor.schedule(ctx, now.Add(12*time.Hour), worker.Options{}, observation.Persistence, nil)
	if monitor.done != first {
		t.Fatal("overlapping full scan started")
	}
}

func TestPeriodicPersistenceMismatchPausesUntilReview(t *testing.T) {
	now, q, evidence, observation := approvedFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lastVerified := now.Add(-6 * time.Hour)
	observation.Persistence.LastVerified = lastVerified
	monitor := persistenceMonitor{verify: func(context.Context, worker.Options) error {
		observation.Persistence.Valid = false
		observation.Persistence.NeedsReview = true
		observation.Persistence.RevokedAt = now
		return errors.New("persistence mismatch")
	}}
	monitor.schedule(ctx, now, worker.Options{}, observation.Persistence, nil)
	select {
	case <-monitor.done:
	case <-time.After(time.Second):
		t.Fatal("periodic scan did not complete")
	}
	for _, at := range []time.Time{now, now.Add(24 * time.Hour)} {
		monitor.schedule(ctx, at, worker.Options{}, observation.Persistence, nil)
		if monitor.done != nil {
			t.Fatal("maintenance attempted to heal a revoked attestation")
		}
		health, err := Evaluate(now, q, evidence, observation)
		if err == nil || health.BoundaryValidated || health.PersistenceValid || !health.PersistenceNeedsReview || !health.PersistenceLastVerified.Equal(lastVerified) {
			t.Fatalf("mismatch retained admission or lost last verification: %+v %v", health, err)
		}
	}
}

func TestMissingAttestationStartsScanWithoutClaimingReadiness(t *testing.T) {
	now, q, evidence, observation := approvedFixture()
	observation.Persistence = worker.PersistenceAttestationMetadata{}
	if health, err := Evaluate(now, q, evidence, observation); err == nil || health.BoundaryValidated {
		t.Fatal("missing attestation admitted")
	}
	called := make(chan struct{})
	monitor := persistenceMonitor{verify: func(context.Context, worker.Options) error { close(called); return nil }}
	monitor.schedule(context.Background(), now, worker.Options{}, observation.Persistence, errors.New("missing"))
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("missing attestation did not schedule initial full scan")
	}
	<-monitor.done
}

func TestFreshAttestationDefersPeriodicScanForSixHours(t *testing.T) {
	now, _, _, observation := approvedFixture()
	called := make(chan struct{})
	monitor := persistenceMonitor{verify: func(context.Context, worker.Options) error { close(called); return nil }}
	monitor.schedule(context.Background(), now.Add(6*time.Hour-time.Nanosecond), worker.Options{}, observation.Persistence, nil)
	if monitor.done != nil {
		t.Fatal("full scan scheduled before six hours")
	}
	monitor.schedule(context.Background(), now.Add(6*time.Hour), worker.Options{}, observation.Persistence, nil)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("six-hour scan not scheduled")
	}
	<-monitor.done
}

func TestPeriodicPersistenceCancellationFinishesBeforeMonitorExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	monitor := persistenceMonitor{verify: func(ctx context.Context, _ worker.Options) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}}
	monitor.schedule(ctx, time.Now(), worker.Options{}, worker.PersistenceAttestationMetadata{}, errors.New("missing"))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scan did not start")
	}
	cancel()
	select {
	case <-monitor.done:
	case <-time.After(time.Second):
		t.Fatal("cancelled scan outlived monitor shutdown")
	}
	monitor.schedule(ctx, time.Now().Add(24*time.Hour), worker.Options{}, worker.PersistenceAttestationMetadata{}, errors.New("missing"))
	if monitor.done != nil {
		t.Fatal("cancelled monitor started another scan")
	}
}
