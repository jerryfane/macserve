package worker

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func attestationFixture(t *testing.T) (Options, PersistenceManifest) {
	t.Helper()
	root := privateRootFixture(t)
	expected := registrationFixture(t)
	options := Options{PersistencePath: filepath.Join(root, "accepted.json"), JobUID: testJobUID, JobGID: testJobUID, OwnerUID: 501, ControllerUID: 6201, HelperPath: "/protected/macserve"}
	data, err := persistenceBytes(expected)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.PersistencePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	return options, expected
}

func attestFixture(t *testing.T, options Options, expected PersistenceManifest, reset bool) {
	t.Helper()
	calls := 0
	start := time.Now()
	err := verifyPersistenceAttestation(context.Background(), options, reset, func(ctx context.Context, _ Options) (PersistenceManifest, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Before(start.Add(8*time.Minute)) || deadline.After(time.Now().Add(8*time.Minute)) {
			t.Fatalf("full scan must receive its fixed 480s deadline: %v present=%t", deadline, ok)
		}
		return expected, nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("single full verification: calls=%d err=%v", calls, err)
	}
}

func TestPersistenceAttestationInitialResetAndHotNoFullScan(t *testing.T) {
	options, expected := attestationFixture(t)
	status, err := PersistenceAttestationStatus(options)
	if err != nil || status.Valid || status.NeedsReview || status.Reason != "missing" {
		t.Fatalf("initial status: %+v %v", status, err)
	}
	calls := 0
	inspect := func(context.Context, Options, PersistenceManifest) error { calls++; return nil }
	if err := verifyHotPersistence(context.Background(), options, inspect); err == nil || calls != 0 {
		t.Fatalf("missing attestation admitted: calls=%d err=%v", calls, err)
	}
	// Existing accepted v016 authority needs no redundant reaccept on upgrade.
	attestFixture(t, options, expected, true)
	for range 2 {
		if err := verifyHotPersistence(context.Background(), options, inspect); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("hot observations cached: %d", calls)
	}
	status, err = PersistenceAttestationStatus(options)
	if err != nil || !status.Valid || status.NeedsReview || status.LastVerified.IsZero() {
		t.Fatalf("verified status: %+v %v", status, err)
	}
}

func TestPersistenceAttestationMismatchAndUnavailableRevokeDurably(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(strconv.FormatBool(unavailable), func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			before, err := PersistenceAttestationStatus(options)
			if err != nil {
				t.Fatal(err)
			}
			err = verifyPersistenceAttestation(context.Background(), options, false, func(context.Context, Options) (PersistenceManifest, error) {
				if unavailable {
					return PersistenceManifest{}, errors.New("scanner unavailable")
				}
				changed := registrationFixture(t)
				for id, code := range changed.Code {
					code.TreeSHA256 = strings.Repeat("c", 64)
					changed.Code[id] = code
				}
				return changed, nil
			})
			if err == nil || errors.Is(err, ErrContamination) == unavailable {
				t.Fatalf("scan failure classification: %v", err)
			}
			status, err := PersistenceAttestationStatus(options)
			if err != nil || status.Valid || !status.NeedsReview || status.RevokedAt.IsZero() || !status.LastVerified.Equal(before.LastVerified) {
				t.Fatalf("durable revocation: %+v %v", status, err)
			}
			for _, reset := range []bool{false, true} {
				called := false
				err := verifyPersistenceAttestation(context.Background(), options, reset, func(context.Context, Options) (PersistenceManifest, error) { called = true; return expected, nil })
				if err == nil || called {
					t.Fatalf("changed-back state implicitly cleared revocation reset=%t: %v", reset, err)
				}
			}
			if err := markPersistenceReviewed(options); err != nil {
				t.Fatal(err)
			}
			if err := verifyPersistenceAttestation(context.Background(), options, false, func(context.Context, Options) (PersistenceManifest, error) {
				t.Fatal("maintenance may not substitute for explicit reset")
				return expected, nil
			}); err == nil {
				t.Fatal("accepted review alone resumed admission")
			}
			attestFixture(t, options, expected, true)
		})
	}
}

func TestPersistenceAttestationPublicationCannotRaceRevocation(t *testing.T) {
	options, expected := attestationFixture(t)
	attestFixture(t, options, expected, false)
	err := verifyPersistenceAttestation(context.Background(), options, false, func(context.Context, Options) (PersistenceManifest, error) {
		if err := revokePersistenceAttestation(options, ErrContamination); err != nil {
			t.Fatal(err)
		}
		return expected, nil
	})
	if err == nil {
		t.Fatal("scan begun before revocation republished authority")
	}
	status, err := PersistenceAttestationStatus(options)
	if err != nil || status.Valid || status.Reason != "mismatch" {
		t.Fatalf("raced revocation not retained: %+v %v", status, err)
	}
}

func TestHotAdmissionBracketsAttestationAndAcceptedBinding(t *testing.T) {
	for _, change := range []string{"revoke", "manifest", "identity"} {
		t.Run(change, func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			if change == "identity" {
				options.OwnerUID++
			}
			err := verifyHotPersistence(context.Background(), options, func(context.Context, Options, PersistenceManifest) error {
				switch change {
				case "revoke":
					return revokePersistenceAttestation(options, ErrContamination)
				case "manifest":
					expected.OSBuild = "new-reviewed-build"
					data, err := persistenceBytes(expected)
					if err != nil {
						return err
					}
					return os.WriteFile(options.PersistencePath, data, 0600)
				default:
					t.Fatal("stale identity binding reached observation")
					return nil
				}
			})
			if err == nil {
				t.Fatal("stale attestation authorized admission")
			}
			status, statusErr := PersistenceAttestationStatus(options)
			if statusErr != nil || status.Valid || !status.NeedsReview || status.RevokedAt.IsZero() {
				t.Fatalf("authority failure did not durably revoke: %+v %v", status, statusErr)
			}
		})
	}
}

func TestHotRegistrationCensusRejectsNewMissingAndChangedBTM(t *testing.T) {
	expected := registrationFixture(t)
	for _, change := range []string{"new", "missing", "identity", "build"} {
		t.Run(change, func(t *testing.T) {
			current := registrationFixture(t)
			switch change {
			case "new":
				current.Census.Records = append(current.Census.Records, BTMRecord{Fields: map[string]string{"Identifier": "new.record"}})
			case "missing":
				current.Census.Records = current.Census.Records[1:]
			case "identity":
				current.Census.Records[0].Fields["Team Identifier"] = "OTHERTEAM"
			case "build":
				current.OSBuild = "new-build"
			}
			if err := matchPersistenceCensus(expected, current.OSBuild, current.Census); !errors.Is(err, ErrContamination) {
				t.Fatalf("fresh BTM difference admitted: %v", err)
			}
		})
	}
}

func TestHotRegistrationRootsNeverWalkOrHashDescendants(t *testing.T) {
	root := privateRootFixture(t)
	bundle := filepath.Join(root, "Fixture.app")
	if err := os.Mkdir(bundle, 0755); err != nil {
		t.Fatal(err)
	}
	// The full scanner rejects this descendant. Hot checks intentionally do
	// not follow it or inspect its ACL/mode/content, even after it changes.
	poison := filepath.Join(bundle, "unreviewed-descendant")
	if err := os.Symlink("/does/not/exist", poison); err != nil {
		t.Fatal(err)
	}
	expected := PersistenceManifest{Code: map[string]RegisteredCode{"fixture": {Path: bundle}}}
	seenRoot := false
	err := inspectRegistrationRoots(context.Background(), expected, registrationWritersFixture(), func(_ context.Context, _ registrationWriters, args ...string) error {
		if len(args) != 2 || args[0] != "-ldeb" || strings.HasPrefix(args[1], bundle+"/") {
			t.Fatalf("recursive or descendant ACL command: %q", args)
		}
		seenRoot = seenRoot || args[1] == bundle
		return nil
	})
	if err != nil || !seenRoot {
		t.Fatalf("root-only inspection: root=%t err=%v", seenRoot, err)
	}
}

func TestHotRegistrationRejectsJobWritableRootAncestorAndACL(t *testing.T) {
	for _, target := range []string{"root", "ancestor", "acl"} {
		t.Run(target, func(t *testing.T) {
			root := privateRootFixture(t)
			ancestor := filepath.Join(root, "ancestor")
			bundle := filepath.Join(ancestor, "Fixture.app")
			if err := os.MkdirAll(bundle, 0755); err != nil {
				t.Fatal(err)
			}
			path := bundle
			if target == "ancestor" {
				path = ancestor
			}
			if target != "acl" {
				if err := os.Chmod(path, 0777); err != nil {
					t.Fatal(err)
				}
			}
			err := inspectRegistrationRoots(context.Background(), PersistenceManifest{Code: map[string]RegisteredCode{"fixture": {Path: bundle}}}, registrationWritersFixture(), func(_ context.Context, writers registrationWriters, args ...string) error {
				if target == "acl" && args[1] == ancestor {
					return writers.checkACL(" 0: user:job allow write")
				}
				return nil
			})
			if err == nil {
				t.Fatal("untrusted registration writer admitted")
			}
		})
	}
}

func TestHotRegistrationRefreshesServiceMembershipEveryObservation(t *testing.T) {
	options := Options{OwnerUID: 501, JobUID: 6202, ControllerUID: 6201}
	expected := PersistenceManifest{OSBuild: "fixture"}
	for _, role := range []uint32{options.JobUID, options.ControllerUID} {
		joined := false
		policy := func(context.Context, Options) (registrationWriters, error) {
			err := registrationWriterIdentities(options,
				func(id string) (*user.User, error) {
					return &user.User{Uid: id, Gid: id, Username: "fixture" + id}, nil
				},
				func(name string) (*user.Group, error) {
					return &user.Group{Name: name, Gid: map[string]string{"wheel": "0", "staff": "20", "admin": "80"}[name]}, nil
				},
				func(account *user.User) ([]string, error) { return []string{account.Gid}, nil },
				func(account *user.User, gid string) (bool, error) {
					return joined && account.Uid == strconv.FormatUint(uint64(role), 10) && gid == "80", nil
				})
			return registrationWritersFixture(), err
		}
		observe := func(context.Context, Options) (string, BTMCensus, error) {
			return expected.OSBuild, expected.Census, nil
		}
		acl := func(context.Context, registrationWriters, ...string) error { return nil }
		if err := checkRegistrationAdmission(context.Background(), options, expected, policy, observe, acl); err != nil {
			t.Fatal(err)
		}
		joined = true
		if err := checkRegistrationAdmission(context.Background(), options, expected, policy, observe, acl); err == nil {
			t.Fatalf("new nested admin membership admitted for %d", role)
		}
	}
}

func TestHotAdmissionLegacyRefusalRevokesWithoutClearingQuarantine(t *testing.T) {
	options, expected := attestationFixture(t)
	attestFixture(t, options, expected, false)
	marker := filepath.Join(filepath.Dir(options.PersistencePath), quarantineRecord)
	if err := os.WriteFile(marker, []byte("keep-quarantine"), 0600); err != nil {
		t.Fatal(err)
	}
	err := verifyHotPersistence(context.Background(), options, func(context.Context, Options, PersistenceManifest) error {
		return inspectLoginItems("1\n", "", nil)
	})
	if !errors.Is(err, ErrContamination) {
		t.Fatalf("legacy login item admitted: %v", err)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "keep-quarantine" {
		t.Fatalf("attestation touched quarantine: %q %v", data, err)
	}
	status, err := PersistenceAttestationStatus(options)
	if err != nil || status.Valid || status.Reason != "mismatch" {
		t.Fatalf("legacy mismatch not revoked: %+v %v", status, err)
	}
}

func TestPersistenceAttestationBindsBootAndBuild(t *testing.T) {
	for _, field := range []string{"boot", "build", "schema"} {
		t.Run(field, func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			if err := withAttestationLock(options, func(root *os.Root) error {
				record, _, err := readAttestation(options)
				if err != nil {
					return err
				}
				switch field {
				case "boot":
					record.Binding.Boot = "previous-boot"
				case "build":
					record.Binding.Build = "previous-build"
				case "schema":
					record.Binding.Version++
				}
				return writeAttestation(root, record)
			}); err != nil {
				t.Fatal(err)
			}
			status, err := PersistenceAttestationStatus(options)
			if err != nil || status.Valid || status.Reason != "authority_changed" {
				t.Fatalf("stale binding reported healthy: %+v %v", status, err)
			}
			if err := verifyHotPersistence(context.Background(), options, func(context.Context, Options, PersistenceManifest) error {
				t.Fatal("stale binding reached observation")
				return nil
			}); err == nil {
				t.Fatal("stale binding admitted")
			}
		})
	}
}

func TestPersistenceAttestationCanceledScanCannotPublish(t *testing.T) {
	options, expected := attestationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := verifyPersistenceAttestation(ctx, options, false, func(context.Context, Options) (PersistenceManifest, error) {
		cancel()
		return expected, nil
	})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrContamination) {
		t.Fatalf("canceled scan classification: %v", err)
	}
	status, err := PersistenceAttestationStatus(options)
	if err != nil || status.Valid || !status.NeedsReview || status.Reason != "inspection_unavailable" {
		t.Fatalf("canceled scan published: %+v %v", status, err)
	}
}

func TestNativeAdmissionUsesCheapDeadlineNotFullScanDeadline(t *testing.T) {
	options, _ := attestationFixture(t)
	boot, err := bootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PersistenceDigest(options.PersistencePath, options.JobUID)
	if err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(filepath.Dir(options.PersistencePath), "baseline.json")
	if err := saveBaseline(baselinePath, GUIBaseline{JobUID: options.JobUID, Boot: boot, PersistenceSHA256: digest, Processes: []ProcessIdentity{{PID: 100, Start: "deadline-fixture"}}, Launchd: &LaunchdEnvironment{}}); err != nil {
		t.Fatal(err)
	}
	reached := errors.New("observed cheap inspection deadline")
	start := time.Now()
	runner := &nativeRunner{
		uid: int(options.JobUID), scope: &processScope{},
		baselinePath: baselinePath, persistencePath: options.PersistencePath,
		console: func() error { return nil },
		persistence: func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok || deadline.Before(start.Add(30*time.Second)) || deadline.After(time.Now().Add(30*time.Second)) {
				t.Fatalf("hot admission must receive its fixed 30s deadline: %v present=%t", deadline, ok)
			}
			return reached
		},
	}
	if err := runner.Admission(context.Background()); !errors.Is(err, reached) {
		t.Fatalf("native admission did not reach cheap observer: %v", err)
	}
}

func TestEngineCleanupBudgetRemainsIndependentOfFullScan(t *testing.T) {
	engine := engineFixture(t, &fakeRunner{})
	if engine.options.CleanupTimeout != 2*time.Minute || engine.options.CleanupTimeout <= persistenceAdmissionTimeout {
		t.Fatalf("cleanup must retain 120s for cheap admission and existing finalization: %v", engine.options.CleanupTimeout)
	}
}
