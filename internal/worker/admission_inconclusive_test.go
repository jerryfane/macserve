package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// sequenceAdmission fails each Admission call with the next entry of failures,
// then passes.
type sequenceAdmission struct {
	fakeRunner
	failures []error
}

func (r *sequenceAdmission) Admission(context.Context) error {
	if len(r.failures) == 0 {
		return nil
	}
	err := r.failures[0]
	r.failures = r.failures[1:]
	return err
}

func inconclusiveRecord(t *testing.T, e *Engine) *AdmissionInconclusive {
	t.Helper()
	record, err := ReadAdmissionInconclusive(e.options.Root)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func noQuarantine(t *testing.T, e *Engine) {
	t.Helper()
	if _, err := e.root.Lstat(quarantineRecord); !os.IsNotExist(err) {
		t.Fatalf("persisting tolerated child quarantined the worker: %v", err)
	}
}

// A child of a tolerated launch that outlives admission's wait keeps the
// worker refusing work. Each refusal is recorded durably (not quarantine) for
// health and admin state, and the next admission that passes, a job's
// post-quiesce admission or worker-reset removes the record.
func TestPersistingToleratedChildIsRecordedWithoutQuarantine(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	runner := &sequenceAdmission{failures: []error{errToleratedChildPersists, errToleratedChildPersists}}
	engine := engineFixture(t, runner)
	engine.options.Now = func() time.Time { return now }

	if err := engine.Recover(ctx); !errors.Is(err, errToleratedChildPersists) || errors.Is(err, ErrRecovery) {
		t.Fatalf("recover = %v", err)
	}
	noQuarantine(t, engine)
	first := inconclusiveRecord(t, engine)
	if first == nil || first.Reason != errToleratedChildPersists.Error() || !first.Since.Equal(now) || !first.CheckedAt.Equal(now) {
		t.Fatalf("record %+v", first)
	}
	now = now.Add(time.Minute)
	job := fixtureJob(t, model.Build)
	source, archive := sourceFixture(t)
	if _, err := engine.Execute(ctx, job, source, bytes.NewReader(archive), nil); !errors.Is(err, errToleratedChildPersists) {
		t.Fatalf("execute = %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("refused job launched commands")
	}
	noQuarantine(t, engine)
	if again := inconclusiveRecord(t, engine); again == nil || !again.Since.Equal(first.Since) || !again.CheckedAt.Equal(now) {
		t.Fatalf("repeated refusal record %+v", again)
	}
	// The child exited: the next admission passes and removes the record.
	if err := engine.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if record := inconclusiveRecord(t, engine); record != nil {
		t.Fatalf("admitted worker kept %+v", record)
	}

	// After a job, quiesce runs and the admission that follows refuses: the
	// job's cleanup is unverified and the record is written.
	runner.failures = []error{nil, errToleratedChildPersists}
	result, err := engine.Execute(ctx, fixtureJob(t, model.Build), source, bytes.NewReader(archive), nil)
	if !errors.Is(err, errToleratedChildPersists) || result.CleanupOK || errors.Is(err, ErrContamination) {
		t.Fatalf("post-job admission: cleanup %v: %v", result.CleanupOK, err)
	}
	noQuarantine(t, engine)
	if inconclusiveRecord(t, engine) == nil {
		t.Fatal("post-job refusal not recorded")
	}
	// worker-reset terminates the child and removes the record.
	if err := engine.reset(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if record := inconclusiveRecord(t, engine); record != nil {
		t.Fatalf("reset kept %+v", record)
	}
}

// Any other refusal leaves the record as it was: it reports only the
// persisting child.
func TestOtherAdmissionRefusalsDoNotTouchInconclusiveRecord(t *testing.T) {
	ctx := context.Background()
	runner := &sequenceAdmission{failures: []error{errRelaunchUnverified, errToleratedChildPersists, errRelaunchUnverified}}
	engine := engineFixture(t, runner)
	if err := engine.Recover(ctx); !errors.Is(err, errRelaunchUnverified) {
		t.Fatal(err)
	}
	if record := inconclusiveRecord(t, engine); record != nil {
		t.Fatalf("other refusal recorded %+v", record)
	}
	if err := engine.Recover(ctx); !errors.Is(err, errToleratedChildPersists) {
		t.Fatal(err)
	}
	if err := engine.Recover(ctx); !errors.Is(err, errRelaunchUnverified) {
		t.Fatal(err)
	}
	if inconclusiveRecord(t, engine) == nil {
		t.Fatal("record removed by an admission that did not pass")
	}
}

// Maintenance publishes only a well-formed record; anything else is an
// observation error (invalid health), never an absent record.
func TestReadAdmissionInconclusiveRefusesMalformedRecord(t *testing.T) {
	engine := engineFixture(t, &fakeRunner{})
	for _, data := range []string{`{"reason":""}`, `{"reason":"x","since":"2026-01-02T00:00:00Z","checked_at":"2026-01-01T00:00:00Z"}`, `{"reason":"x","since":"2026-01-02T00:00:00Z","checked_at":"2026-01-02T00:00:00Z","extra":1}`, `[]`} {
		if err := durableFile(engine.root, admissionInconclusiveRecord, []byte(data)); err != nil {
			t.Fatal(err)
		}
		if record, err := ReadAdmissionInconclusive(engine.options.Root); err == nil {
			t.Fatalf("%s read as %+v", data, record)
		}
	}
}
