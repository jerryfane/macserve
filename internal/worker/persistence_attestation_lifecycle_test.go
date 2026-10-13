package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func holdAttestationPublication(t *testing.T, options Options) func() {
	t.Helper()
	lock, err := os.OpenFile(filepath.Join(filepath.Dir(options.PersistencePath), persistenceAttestationFile+".lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			lock.Close()
		})
	}
	t.Cleanup(release)
	return release
}

func TestPersistenceFullScanSerializesAcrossProcesses(t *testing.T) {
	const childPath = "MACSERVE_TEST_ATTESTATION_CONTENDER"
	if path := os.Getenv(childPath); path != "" {
		options := Options{PersistencePath: path}
		record, _, err := readAttestation(options)
		if err != nil {
			t.Fatal(err)
		}
		options.JobUID, options.JobGID = record.Binding.JobUID, record.Binding.JobGID
		options.OwnerUID, options.ControllerUID = record.Binding.OwnerUID, record.Binding.ControllerUID
		options.HelperPath = record.Binding.HelperPath
		expected, _, err := readPersistence(path, options.JobUID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		calls := 0
		err = verifyPersistenceAttestation(ctx, options, false, func(context.Context, Options) (PersistenceManifest, error) {
			calls++
			return expected, nil
		})
		if !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
			t.Fatalf("overlapping process must time out without collecting or publishing: calls=%d err=%v", calls, err)
		}
		return
	}

	options, expected := attestationFixture(t)
	attestFixture(t, options, expected, false)
	entered, release := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	go func() {
		finished <- verifyPersistenceAttestation(context.Background(), options, false, func(context.Context, Options) (PersistenceManifest, error) {
			close(entered)
			<-release
			return expected, nil
		})
	}()
	select {
	case <-entered:
	case err := <-finished:
		t.Fatalf("first scan did not enter collector: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("first scan did not enter collector")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestPersistenceFullScanSerializesAcrossProcesses$", "-test.v")
	cmd.Env = append(os.Environ(), childPath+"="+options.PersistencePath)
	output, contenderErr := cmd.CombinedOutput()
	unblock()
	firstErr := <-finished
	if contenderErr != nil {
		t.Fatalf("cross-process scan exclusion failed: %v\n%s", contenderErr, output)
	}
	if firstErr != nil {
		t.Fatalf("contending invocation damaged active scan: %v", firstErr)
	}
	status, err := PersistenceAttestationStatus(options)
	if err != nil || !status.Valid || status.NeedsReview {
		t.Fatalf("lock contention revoked healthy authority: %+v %v", status, err)
	}
}

func TestPersistenceStaleScanCannotRevokeNewerRevision(t *testing.T) {
	for _, outcome := range []string{"success", "mismatch", "unavailable"} {
		t.Run(outcome, func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			var published []byte
			err := verifyPersistenceAttestation(context.Background(), options, false, func(context.Context, Options) (PersistenceManifest, error) {
				// Publish a later verified revision at the real atomic publication
				// boundary while this scanner still owns its older snapshot.
				if err := withAttestationLock(options, func(root *os.Root) error {
					record, _, err := readAttestation(options)
					if err != nil {
						return err
					}
					record.LastVerified = record.LastVerified.Add(time.Second)
					return writeAttestation(root, record)
				}); err != nil {
					t.Fatal(err)
				}
				_, data, err := readAttestation(options)
				if err != nil {
					t.Fatal(err)
				}
				published = data
				switch outcome {
				case "mismatch":
					return PersistenceManifest{}, ErrContamination
				case "unavailable":
					return PersistenceManifest{}, errors.New("collector unavailable")
				default:
					return expected, nil
				}
			})
			if err == nil {
				t.Fatal("stale scan published over a newer revision")
			}
			record, after, err := readAttestation(options)
			if err != nil || !record.Valid || !bytes.Equal(published, after) {
				t.Fatalf("stale %s scan revoked or rewrote newer authority: %+v %v", outcome, record.PersistenceAttestationMetadata, err)
			}
		})
	}
}

func TestPersistenceAttestationReasonPrecedence(t *testing.T) {
	t.Run("positive evidence outranks unavailable", func(t *testing.T) {
		options, expected := attestationFixture(t)
		attestFixture(t, options, expected, false)
		for _, cause := range []error{errors.New("collector unavailable"), ErrContamination, errors.New("later unavailable")} {
			if err := revokePersistenceAttestation(options, cause); err != nil {
				t.Fatal(err)
			}
		}
		status, err := PersistenceAttestationStatus(options)
		if err != nil || status.Valid || !status.NeedsReview || status.Reason != "mismatch" {
			t.Fatalf("positive mismatch lost to a weaker reason: %+v %v", status, err)
		}
	})
	for _, cause := range []error{errors.New("collector unavailable"), ErrContamination} {
		t.Run("review survives "+cause.Error(), func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			if err := markPersistenceReviewed(options); err != nil {
				t.Fatal(err)
			}
			_, reviewed, err := readAttestation(options)
			if err != nil {
				t.Fatal(err)
			}
			if err := revokePersistenceAttestation(options, cause); err != nil {
				t.Fatal(err)
			}
			err = verifyPersistenceAttestation(context.Background(), options, true, func(context.Context, Options) (PersistenceManifest, error) {
				return PersistenceManifest{}, cause
			})
			if !errors.Is(err, cause) {
				t.Fatalf("reset did not report its scan failure: %v", err)
			}
			record, after, err := readAttestation(options)
			if err != nil || record.Valid || record.Reason != "reset_required" || !bytes.Equal(reviewed, after) {
				t.Fatalf("automatic failure downgraded reviewed reset marker: %+v %v", record.PersistenceAttestationMetadata, err)
			}
			attestFixture(t, options, expected, true)
		})
	}
}

func TestPersistencePublicationLockHonorsScanDeadline(t *testing.T) {
	options, expected := attestationFixture(t)
	attestFixture(t, options, expected, false)
	_, before, err := readAttestation(options)
	if err != nil {
		t.Fatal(err)
	}
	release := holdAttestationPublication(t, options)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	type result struct {
		err   error
		calls int
	}
	finished := make(chan result, 1)
	go func() {
		calls := 0
		err := verifyPersistenceAttestation(ctx, options, false, func(context.Context, Options) (PersistenceManifest, error) {
			calls++
			return expected, nil
		})
		finished <- result{err: err, calls: calls}
	}()
	select {
	case got := <-finished:
		if !errors.Is(got.err, context.DeadlineExceeded) || got.calls != 0 {
			t.Fatalf("contended publication lock ignored deadline: calls=%d err=%v", got.calls, got.err)
		}
	case <-time.After(2 * time.Second):
		release()
		<-finished
		t.Fatal("publication lock blocked beyond caller deadline")
	}
	release()
	_, after, err := readAttestation(options)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("canceled lock waiter changed attestation: %v", err)
	}
}

func TestPersistenceEightStatusReadsDoNotWaitForPublisher(t *testing.T) {
	options, expected := attestationFixture(t)
	attestFixture(t, options, expected, false)
	release := holdAttestationPublication(t, options)
	finished := make(chan error, 1)
	go func() {
		for tick := range 8 {
			probe := options
			if tick == 7 {
				probe.OwnerUID++
			}
			status, err := PersistenceAttestationStatus(probe)
			if err != nil {
				finished <- fmt.Errorf("tick %d: %w", tick, err)
				return
			}
			if tick < 7 && (!status.Valid || status.NeedsReview) || tick == 7 && (status.Valid || status.Reason != "authority_changed") {
				finished <- fmt.Errorf("tick %d lost atomic authority binding: %+v", tick, status)
				return
			}
		}
		finished <- nil
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		release()
		<-finished
		t.Fatal("eight read-only status ticks waited for a writer lock")
	}
}
