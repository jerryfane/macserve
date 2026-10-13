package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type hotAdmissionRunner struct {
	fakeRunner
	admit func(context.Context) error
}

func (r *hotAdmissionRunner) Admission(ctx context.Context) error { return r.admit(ctx) }

func TestHotAdmissionTransientPreservesAttestationAndRetry(t *testing.T) {
	_, unknownCensus := parseBackgroundItems("unrecognized sfltool output", testJobUID)
	for name, failure := range map[string]error{
		"timeout":                context.DeadlineExceeded,
		"canceled":               context.Canceled,
		"inspection-permission":  syscall.EPERM,
		"unknown-sfltool":        unknownCensus,
		"unknown-login-census":   inspectLoginItems("unknown", "", nil),
		"membership-unavailable": errors.New("registration service account memberships unavailable"),
	} {
		t.Run(name, func(t *testing.T) {
			if failure == nil {
				t.Fatal("fixture must refuse inspection")
			}
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			_, before, err := readAttestation(options)
			if err != nil {
				t.Fatal(err)
			}
			observation := failure
			calls := 0
			runner := &hotAdmissionRunner{admit: func(ctx context.Context) error {
				return verifyHotPersistence(ctx, options, func(context.Context, Options, PersistenceManifest) error {
					calls++
					return observation
				})
			}}
			engine := engineFixture(t, runner)
			if err := engine.admission(context.Background()); !errors.Is(err, failure) || errors.Is(err, ErrContamination) {
				t.Fatalf("transient refusal classification: %v", err)
			}
			record, after, err := readAttestation(options)
			if err != nil || !bytes.Equal(before, after) || !record.Valid {
				t.Fatalf("transient hot refusal mutated durable attestation: %+v %v", record, err)
			}
			if _, err := engine.root.Lstat(quarantineRecord); !os.IsNotExist(err) {
				t.Fatalf("transient hot refusal persisted quarantine: %v", err)
			}
			observation = nil
			if err := engine.admission(context.Background()); err != nil || calls != 2 {
				t.Fatalf("next admission did not freshly retry without reset: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestHotAdmissionPositiveEvidenceRevokesAndQuarantines(t *testing.T) {
	for _, change := range []string{"root", "ancestor", "owner", "acl", "primary-group", "nested-group", "btm", "legacy"} {
		t.Run(change, func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			probe := func(ctx context.Context, options Options, expected PersistenceManifest) error {
				switch change {
				case "root", "ancestor", "owner":
					parent := filepath.Join(filepath.Dir(options.PersistencePath), "registered-parent")
					path := filepath.Join(parent, "Fixture.app")
					if err := os.MkdirAll(path, 0755); err != nil {
						t.Fatal(err)
					}
					if change == "owner" {
						if err := os.Chown(path, int(options.JobUID), int(options.JobGID)); err != nil {
							t.Fatal(err)
						}
					} else {
						target := path
						if change == "ancestor" {
							target = parent
						}
						if err := os.Chmod(target, 0777); err != nil {
							t.Fatal(err)
						}
					}
					roots := PersistenceManifest{Code: map[string]RegisteredCode{"fixture": {Path: path}}}
					return inspectRegistrationRoots(ctx, roots, registrationWritersFixture(), func(context.Context, registrationWriters, ...string) error { return nil })
				case "acl":
					return registrationWritersFixture().checkACL(" 0: group:everyone allow write")
				case "primary-group", "nested-group":
					return registrationWriterIdentities(options,
						func(id string) (*user.User, error) {
							gid := "6202"
							if change == "primary-group" {
								gid = "20"
							}
							return &user.User{Uid: id, Gid: gid, Username: "fixture" + id}, nil
						},
						func(name string) (*user.Group, error) {
							return &user.Group{Gid: map[string]string{"wheel": "0", "staff": "20", "admin": "80"}[name]}, nil
						},
						func(*user.User) ([]string, error) { return []string{"6202"}, nil },
						func(*user.User, string) (bool, error) { return change == "nested-group", nil })
				case "btm":
					current := registrationFixture(t)
					current.Census.Records = append(current.Census.Records, BTMRecord{Fields: map[string]string{"Identifier": "unexpected.record"}})
					return matchPersistenceCensus(expected, current.OSBuild, current.Census)
				default:
					return inspectLoginItems("1", "", nil)
				}
			}
			runner := &hotAdmissionRunner{admit: func(ctx context.Context) error {
				return verifyHotPersistence(ctx, options, probe)
			}}
			engine := engineFixture(t, runner)
			if err := engine.admission(context.Background()); !errors.Is(err, ErrContamination) {
				t.Fatalf("positive evidence lost contamination sentinel: %v", err)
			}
			status, err := PersistenceAttestationStatus(options)
			if err != nil || status.Valid || !status.NeedsReview || status.Reason != "mismatch" {
				t.Fatalf("positive mismatch did not revoke: %+v %v", status, err)
			}
			if _, err := engine.root.Lstat(quarantineRecord); err != nil {
				t.Fatalf("positive mismatch did not quarantine: %v", err)
			}
			if err := verifyHotPersistence(context.Background(), options, func(context.Context, Options, PersistenceManifest) error {
				t.Fatal("revoked attestation reached a later observation")
				return nil
			}); err == nil {
				t.Fatal("positive mismatch was implicitly cleared")
			}
		})
	}
}

func TestHotAdmissionFixedBudgetAndExpiry(t *testing.T) {
	for _, mode := range []string{"background", "long-parent", "short-parent", "expired", "expires-during-inspection"} {
		t.Run(mode, func(t *testing.T) {
			options, expected := attestationFixture(t)
			attestFixture(t, options, expected, false)
			_, before, err := readAttestation(options)
			if err != nil {
				t.Fatal(err)
			}
			parent := context.Background()
			cancel := func() {}
			switch mode {
			case "long-parent":
				parent, cancel = context.WithTimeout(parent, time.Hour)
			case "short-parent":
				parent, cancel = context.WithTimeout(parent, 5*time.Second)
			case "expired":
				parent, cancel = context.WithDeadline(parent, time.Now().Add(-time.Second))
			case "expires-during-inspection":
				parent, cancel = context.WithCancel(parent)
			}
			defer cancel()
			start := time.Now()
			calls := 0
			err = verifyHotPersistence(parent, options, func(ctx context.Context, _ Options, _ PersistenceManifest) error {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || deadline.After(time.Now().Add(30*time.Second)) {
					t.Fatalf("hot observer must have fixed 30s ceiling: %v present=%t", deadline, ok)
				}
				if mode == "background" || mode == "long-parent" {
					if deadline.Before(start.Add(30 * time.Second)) {
						t.Fatalf("hot observer did not receive the full fixed budget: %v", deadline)
					}
				}
				if mode == "short-parent" {
					parentDeadline, _ := parent.Deadline()
					if !deadline.Equal(parentDeadline) {
						t.Fatalf("hot observer renewed short parent budget: %v != %v", deadline, parentDeadline)
					}
				}
				if mode == "expires-during-inspection" {
					cancel()
				}
				return nil
			})
			switch mode {
			case "expired":
				if !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
					t.Fatalf("expired budget reached observer: calls=%d err=%v", calls, err)
				}
			case "expires-during-inspection":
				if !errors.Is(err, context.Canceled) || calls != 1 {
					t.Fatalf("expired observation admitted: calls=%d err=%v", calls, err)
				}
			default:
				if err != nil || calls != 1 {
					t.Fatalf("bounded clean admission refused: calls=%d err=%v", calls, err)
				}
			}
			_, after, readErr := readAttestation(options)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatalf("budget handling mutated attestation: %v", readErr)
			}
		})
	}
}

func TestInspectionCommandUsesShortShareAndRefusesExpiry(t *testing.T) {
	// Use the existing command API and an actual child process: old code gives
	// metadata probes 5s, allowing this 3s command to finish instead of refusing.
	options, expected := attestationFixture(t)
	attestFixture(t, options, expected, false)
	var out string
	err := verifyHotPersistence(context.Background(), options, func(ctx context.Context, _ Options, _ PersistenceManifest) error {
		var err error
		out, _, err = inspectCommand(ctx, nil, "/bin/sh", "-c", "printf partial; exec sleep 3")
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) || out != "partial" {
		t.Fatalf("command did not refuse partial output at its 2s share: out=%q err=%v", out, err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	out, _, err = inspectCommand(ctx, nil, "/bin/sh", "-c", "printf launched")
	if !errors.Is(err, context.DeadlineExceeded) || out != "" {
		t.Fatalf("expired command budget launched or accepted output: out=%q err=%v", out, err)
	}
}

func TestHotRootACLProbesShareOneAllocation(t *testing.T) {
	root := privateRootFixture(t)
	expected := PersistenceManifest{Code: make(map[string]RegisteredCode)}
	for _, name := range []string{"First.app", "Second.app"} {
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
		expected.Code[name] = RegisteredCode{Path: path}
	}
	var firstDeadline time.Time
	calls := 0
	start := time.Now()
	err := inspectRegistrationRoots(context.Background(), expected, registrationWritersFixture(), func(ctx context.Context, _ registrationWriters, _ ...string) error {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Before(start.Add(2*time.Second)) || deadline.After(time.Now().Add(2*time.Second)) {
			t.Fatalf("root ACL census lacks its fixed 2s allocation: %v present=%t", deadline, ok)
		}
		if firstDeadline.IsZero() {
			firstDeadline = deadline
		} else if !deadline.Equal(firstDeadline) {
			t.Fatalf("later root/ancestor renewed ACL budget: %v != %v", deadline, firstDeadline)
		}
		return nil
	})
	if err != nil || calls < 2 {
		t.Fatalf("root/ancestor census incomplete: calls=%d err=%v", calls, err)
	}
}
