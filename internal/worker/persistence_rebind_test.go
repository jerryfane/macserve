package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func storedAttestation(t *testing.T, options Options) []byte {
	t.Helper()
	_, data, err := readAttestation(options)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func editAttestation(t *testing.T, options Options, edit func(*persistenceAttestation)) {
	t.Helper()
	if err := withAttestationLock(options, func(root *os.Root) error {
		record, _, err := readAttestation(options)
		if err != nil {
			return err
		}
		edit(&record)
		return writeAttestation(root, record)
	}); err != nil {
		t.Fatal(err)
	}
}

func noScan(t *testing.T) func(context.Context, Options) (PersistenceManifest, error) {
	return func(context.Context, Options) (PersistenceManifest, error) {
		t.Fatal("refused rebind reached the full scan")
		return PersistenceManifest{}, nil
	}
}

// The strict rebind accepts a stored attestation that differs from the live
// binding only in Build, and publishes the live binding after a full scan.
func TestRebindBuildOnlyBuildDiffers(t *testing.T) {
	options, expected := attestationFixture(t)
	attestFixture(t, options, expected, false)
	editAttestation(t, options, func(r *persistenceAttestation) { r.Binding.Build = "previous-build" })
	if status, err := PersistenceAttestationStatus(options); err != nil || status.Valid || status.Reason != "authority_changed" {
		t.Fatalf("build change not reported before rebind: %+v %v", status, err)
	}
	calls := 0
	if err := rebindPersistenceBuild(context.Background(), options, func(context.Context, Options) (PersistenceManifest, error) {
		calls++
		return expected, nil
	}); err != nil || calls != 1 {
		t.Fatalf("build-only rebind: calls=%d err=%v", calls, err)
	}
	record, _, err := readAttestation(options)
	if err != nil || !record.Valid || record.Binding.Build != persistenceAttestationBuild {
		t.Fatalf("rebind did not publish the live build: %+v %v", record, err)
	}
	if status, err := PersistenceAttestationStatus(options); err != nil || !status.Valid || status.NeedsReview {
		t.Fatalf("rebound status: %+v %v", status, err)
	}
	// An unchanged binding is a plain full scan.
	calls = 0
	if err := rebindPersistenceBuild(context.Background(), options, func(context.Context, Options) (PersistenceManifest, error) {
		calls++
		return expected, nil
	}); err != nil || calls != 1 {
		t.Fatalf("unchanged rebind: calls=%d err=%v", calls, err)
	}
}

// Every binding difference other than Build refuses before the scan and
// leaves the stored record byte-identical. The explicit full scan
// (VerifyPersistenceAttestation) rebinds the same boot difference silently.
func TestRebindBuildRefusesEveryOtherBindingDifference(t *testing.T) {
	stored := map[string]func(*persistenceAttestation){
		"boot":            func(r *persistenceAttestation) { r.Binding.Boot = "previous-boot" },
		"version":         func(r *persistenceAttestation) { r.Binding.Version++ },
		"manifest_sha256": func(r *persistenceAttestation) { r.Binding.ManifestSHA256 = strings.Repeat("0", 64) },
	}
	live := map[string]func(*Options){
		"job_uid":        func(o *Options) { o.JobUID++ },
		"job_gid":        func(o *Options) { o.JobGID++ },
		"owner_uid":      func(o *Options) { o.OwnerUID++ },
		"controller_uid": func(o *Options) { o.ControllerUID++ },
		"helper_path":    func(o *Options) { o.HelperPath = "/protected/other-macserve" },
	}
	check := func(t *testing.T, field string, scanOptions Options, before []byte, options Options) {
		t.Helper()
		err := rebindPersistenceBuild(context.Background(), scanOptions, noScan(t))
		if !errors.Is(err, errPersistenceRebindRefused) || !strings.Contains(err.Error(), field) {
			t.Fatalf("%s difference accepted or unnamed: %v", field, err)
		}
		if after := storedAttestation(t, options); !bytes.Equal(before, after) {
			t.Fatalf("%s refusal changed the stored attestation", field)
		}
	}
	for field, edit := range stored {
		t.Run(field, func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			editAttestation(t, options, func(r *persistenceAttestation) {
				edit(r)
				r.Binding.Build = "previous-build"
			})
			check(t, field, options, storedAttestation(t, options), options)
		})
	}
	for field, edit := range live {
		t.Run(field, func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			changed := options
			edit(&changed)
			check(t, field, changed, storedAttestation(t, options), options)
		})
	}
	t.Run("explicit full scan rebinds boot silently", func(t *testing.T) {
		options, expected := attestationFixture(t)
		attestFixture(t, options, expected, false)
		editAttestation(t, options, func(r *persistenceAttestation) { r.Binding.Boot = "previous-boot" })
		attestFixture(t, options, expected, false)
		if record, _, err := readAttestation(options); err != nil || !record.Valid || record.Binding.Boot == "previous-boot" {
			t.Fatalf("explicit scan behaviour changed: %+v %v", record, err)
		}
	})
}

// A missing or durably revoked attestation is never rebound or cleared.
func TestRebindBuildRefusesMissingAndRevoked(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		options, _ := attestationFixture(t)
		if err := rebindPersistenceBuild(context.Background(), options, noScan(t)); !errors.Is(err, errPersistenceRebindRefused) {
			t.Fatalf("missing attestation rebound: %v", err)
		}
		if data := storedAttestation(t, options); len(data) != 0 {
			t.Fatal("refused rebind published an attestation")
		}
	})
	for _, reason := range []string{"mismatch", "reset_required"} {
		t.Run(reason, func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			editAttestation(t, options, func(r *persistenceAttestation) {
				r.Valid, r.NeedsReview, r.Reason, r.RevokedAt = false, true, reason, r.LastVerified
			})
			before := storedAttestation(t, options)
			if err := rebindPersistenceBuild(context.Background(), options, noScan(t)); !errors.Is(err, errPersistenceAttestationRevoked) {
				t.Fatalf("revoked attestation rebound: %v", err)
			}
			if !bytes.Equal(before, storedAttestation(t, options)) {
				t.Fatal("refused rebind changed a revoked attestation")
			}
		})
	}
}

// After acceptance, a scan that does not match the reviewed manifest revokes
// durably, exactly as the explicit full scan does.
func TestRebindBuildScanMismatchRevokes(t *testing.T) {
	options, expected := attestationFixture(t)
	attestFixture(t, options, expected, false)
	editAttestation(t, options, func(r *persistenceAttestation) { r.Binding.Build = "previous-build" })
	err := rebindPersistenceBuild(context.Background(), options, func(context.Context, Options) (PersistenceManifest, error) {
		return PersistenceManifest{}, nil
	})
	if err == nil {
		t.Fatal("mismatched scan rebound")
	}
	status, err := PersistenceAttestationStatus(options)
	if err != nil || status.Valid || !status.NeedsReview || status.Reason != "mismatch" {
		t.Fatalf("mismatched rebind not revoked: %+v %v", status, err)
	}
}
