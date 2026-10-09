package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

func TestLaunchAgentInspectionRefusesEntriesAndUnknownPaths(t *testing.T) {
	for _, mode := range []string{"absent", "empty", "entry", "symlink", "not-directory", "missing-home"} {
		t.Run(mode, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "Library", "LaunchAgents")
			if mode != "absent" && mode != "missing-home" {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "symlink":
					if err := os.Symlink(t.TempDir(), path); err != nil {
						t.Fatal(err)
					}
				case "not-directory":
					if err := os.WriteFile(path, nil, 0600); err != nil {
						t.Fatal(err)
					}
				default:
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
					if mode == "entry" {
						if err := os.WriteFile(filepath.Join(path, "delayed.plist"), []byte("scheduled"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if mode == "missing-home" {
				home = filepath.Join(home, "missing")
			}
			err := inspectLaunchAgents(home)
			allowed := mode == "absent" || mode == "empty"
			if (err == nil) != allowed {
				t.Fatalf("inspection %s: %v", mode, err)
			}
			if errors.Is(err, ErrContamination) != (mode == "entry") {
				t.Fatalf("incorrect positive contamination classification: %v", err)
			}
		})
	}
}

func TestPersistenceCensusClassifiesOnlyObservedItems(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		err                   error
		contaminated, allowed bool
	}{
		{"empty-cron", inspectCrontab("", "", nil, "job"), false, true},
		{"cron-entry", inspectCrontab("# scheduled later", "", nil, "job"), true, false},
		{"cron-denied", inspectCrontab("partial", "permission denied", syscall.EPERM, "job"), false, false},
		{"cron-cancel", inspectCrontab("partial", "", context.Canceled, "job"), false, false},
		{"cron-timeout", inspectCrontab("", "crontab: no crontab for job", context.DeadlineExceeded, "job"), false, false},
		{"cron-warning", inspectCrontab("", "unexpected warning", nil, "job"), false, false},
		{"empty-login", inspectLoginItems("0\n", "", nil), false, true},
		{"login-entry", inspectLoginItems("2\n", "", nil), true, false},
		{"login-unknown", inspectLoginItems("", "", nil), false, false},
		{"login-warning", inspectLoginItems("2\n", "denied", nil), false, false},
		{"login-cancel", inspectLoginItems("2\n", "", context.Canceled), false, false},
		{"empty-btm", inspectBackgroundItems("Records for UID 12345 : ABCD-1234\n================\n", testJobUID), false, true},
		{"signed-after", inspectBackgroundItems("Records for UID 12345 : ABCD-1234\nServiceManagement migrated: true\nItems:\nRecords for UID -2 : FFFFEEEE\n#1: System item\n", testJobUID), false, true},
		{"signed-before", inspectBackgroundItems("Records for UID -2 : FFFFEEEE\n#1: System item\nRecords for UID 12345 : ABCD-1234\nServiceManagement migrated: false\nItems: 0\n", testJobUID), false, true},
		{"btm-entry", inspectBackgroundItems("Records for UID 12345 : ABCD-1234\nItems:\n#1: Login Item\n", testJobUID), true, false},
		{"btm-unknown", inspectBackgroundItems("Records for UID 12345 : ABCD-1234\nunknown data\n", testJobUID), false, false},
		{"btm-duplicate", inspectBackgroundItems("Records for UID 12345 : ABCD-1234\nRecords for UID 12345 : ABCD-1234\n", testJobUID), false, false},
		{"btm-missing", inspectBackgroundItems("Records for UID 999 : ABCD-1234\n", testJobUID), false, false},
		{"btm-empty", inspectBackgroundItems("", testJobUID), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (tc.err == nil) != tc.allowed || errors.Is(tc.err, ErrContamination) != tc.contaminated {
				t.Fatalf("classification: %v", tc.err)
			}
		})
	}
}

func TestPreflightCensusNeverSignalsUnexpectedProcesses(t *testing.T) {
	scope := scopeFixture()
	scope.sample = func(context.Context) ([]processSample, error) {
		return []processSample{trustedGUI(), {pid: 200, uid: testJobUID, start: "delayed"}}, nil
	}
	scope.signal = func(context.Context, processSample, syscall.Signal) error {
		t.Fatal("admission killed instead of refusing")
		return nil
	}
	if err := scope.observeQuiet(context.Background()); !errors.Is(err, ErrContamination) {
		t.Fatal("leftover process admitted")
	}
}

func TestAuditRequiresStableExplicitUIDStartAndBootCensus(t *testing.T) {
	for _, mode := range []string{"stable", "unlisted", "reused", "foreign", "disappeared", "boot", "unreadable"} {
		t.Run(mode, func(t *testing.T) {
			calls, boots := 0, 0
			boot := func() (string, error) {
				boots++
				if mode == "boot" && boots == 2 {
					return "new", nil
				}
				return "boot", nil
			}
			sample := func(context.Context) ([]processSample, error) {
				calls++
				p := trustedGUI()
				if calls == 2 {
					switch mode {
					case "unlisted":
						return []processSample{p, {pid: 200, uid: testJobUID, start: "extra"}}, nil
					case "reused":
						p.start = "reused"
					case "foreign":
						p.uid++
					case "disappeared":
						return nil, nil
					case "unreadable":
						return nil, syscall.EPERM
					}
				}
				return []processSample{p}, nil
			}
			baseline, err := auditedBaseline(context.Background(), testJobUID, []int{100}, boot, sample)
			if mode == "stable" {
				if err != nil || baseline.Processes[0].Start != trustedGUI().start || calls != 2 || boots != 2 {
					t.Fatalf("stable census: %+v %v", baseline, err)
				}
			} else if err == nil {
				t.Fatal("changed census adopted")
			}
		})
	}
}

type admissionRunner struct {
	fakeRunner
	failure error
}

func (r *admissionRunner) Admission(context.Context) error { return r.failure }

func TestAdmissionRefusalSurvivesRestartAndBlocksExecution(t *testing.T) {
	runner := &admissionRunner{failure: errors.Join(ErrContamination, errors.New("login item present"))}
	engine := engineFixture(t, runner)
	job := fixtureJob(t, model.Build)
	source, archive := sourceFixture(t)
	if _, err := engine.Execute(context.Background(), job, source, bytes.NewReader(archive), nil); !errors.Is(err, ErrRecovery) {
		t.Fatalf("admission: %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("refused job launched commands")
	}
	options := engine.options
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	runner.failure = nil
	reopened, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Recover(context.Background()); !errors.Is(err, ErrRecovery) {
		t.Fatalf("restart silently cleared quarantine: %v", err)
	}
	if err := reopened.reset(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Recover(context.Background()); err != nil {
		t.Fatalf("reconciled admission remained quarantined: %v", err)
	}
}

func TestResetOnlyRecordedResourcesAndRetainsPendingEvidence(t *testing.T) {
	present := true
	runner := &admissionRunner{fakeRunner: fakeRunner{hook: func(_ context.Context, command Command, out, _ io.Writer) (bool, ProcessResult, error) {
		switch strings.Join(command.Args, " ") {
		case "simctl list devices --json":
			if present {
				io.WriteString(out, `{"devices":{"runtime":[{"udid":"`+ownedUDID+`"}]}}`)
			} else {
				io.WriteString(out, `{"devices":{}}`)
			}
		case "simctl shutdown " + ownedUDID:
		case "simctl delete " + ownedUDID:
			present = false
		default:
			t.Fatalf("unowned resource action: %+v", command)
		}
		return true, ProcessResult{CleanupOK: true}, nil
	}}}
	engine := engineFixture(t, runner)
	if err := durableFile(engine.root, quarantineRecord, []byte(`{"quarantined":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := engine.saveManifest(manifest{JobID: "recorded", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DeviceUDID: ownedUDID}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"recorded", "unrecorded"} {
		if err := engine.workspaces.Mkdir(id, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.exports.Mkdir("recorded", 0700); err != nil {
		t.Fatal(err)
	}
	if err := durableFile(engine.root, "pending.json", []byte(`{"evidence":"pending"}`)); err != nil {
		t.Fatal(err)
	}
	if err := engine.reset(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("recorded simulator survived reset")
	}
	if _, err := engine.workspaces.Stat("recorded"); !os.IsNotExist(err) {
		t.Fatalf("recorded workspace retained: %v", err)
	}
	for _, check := range []struct {
		root *os.Root
		path string
	}{{engine.workspaces, "unrecorded"}, {engine.exports, "recorded"}, {engine.root, "pending.json"}} {
		if _, err := check.root.Stat(check.path); err != nil {
			t.Fatalf("unrelated/pending resource removed: %s: %v", check.path, err)
		}
	}
	if names, err := engine.registryNames(); err != nil || len(names) != 0 {
		t.Fatalf("resolved record retained: %v %v", names, err)
	}
}

func TestResetFailureRetainsOwnedRecordsAndQuarantine(t *testing.T) {
	failure := errors.New("simulator inventory unavailable")
	runner := &admissionRunner{fakeRunner: fakeRunner{hook: func(context.Context, Command, io.Writer, io.Writer) (bool, ProcessResult, error) {
		return true, ProcessResult{CleanupOK: true}, failure
	}}}
	engine := engineFixture(t, runner)
	if err := durableFile(engine.root, quarantineRecord, []byte(`{"quarantined":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := engine.saveManifest(manifest{JobID: "recorded", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DeviceUDID: ownedUDID}); err != nil {
		t.Fatal(err)
	}
	if err := engine.reset(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, failure) {
		t.Fatalf("reconcile failure lost: %v", err)
	}
	var saved manifest
	if err := readJSON(engine.root, "manifests/recorded.json", &saved); err != nil {
		t.Fatal(err)
	}
	if saved.DeviceUDID != ownedUDID {
		t.Fatalf("owned resource erased: %+v", saved)
	}
	if err := engine.Recover(context.Background()); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed reconcile unquarantined: %v", err)
	}
}

func TestLegacyLoginInspectionAndUnavailableNativeAdmissionFailClosed(t *testing.T) {
	runner := &nativeRunner{scope: scopeFixture()}
	if err := runner.Admission(context.Background()); err == nil {
		t.Fatal("missing native persistence inspector admitted job")
	}
	runner.persistence = func(context.Context) error { return nil }
	if err := runner.Admission(context.Background()); err == nil {
		t.Fatal("missing native baseline admitted job")
	}
}

func TestTransientAdmissionDoesNotQuarantine(t *testing.T) {
	for _, failure := range []error{
		context.Canceled, context.DeadlineExceeded, syscall.EPERM,
		errors.New("boot identity changed"),
		errors.New("GUI baseline process disappeared"),
		os.ErrNotExist,
		errors.New("unsupported dumpbtm output"),
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			runner := &admissionRunner{failure: failure}
			engine := engineFixture(t, runner)
			for range 3 {
				if err := engine.Recover(context.Background()); !errors.Is(err, failure) {
					t.Fatalf("pre-claim recovery lost admission refusal: %v", err)
				}
				if _, err := engine.root.Lstat(quarantineRecord); !os.IsNotExist(err) {
					t.Fatalf("pre-claim refusal persisted quarantine: %v", err)
				}
			}
			job := fixtureJob(t, model.Build)
			source, archive := sourceFixture(t)
			if _, err := engine.Execute(context.Background(), job, source, bytes.NewReader(archive), nil); !errors.Is(err, failure) {
				t.Fatalf("transient admission cause lost: %v", err)
			}
			if _, err := engine.root.Lstat(quarantineRecord); !os.IsNotExist(err) {
				t.Fatalf("transient admission persisted quarantine: %v", err)
			}
			if len(runner.commands) != 0 {
				t.Fatal("failed admission launched job")
			}
			runner.failure = nil
			if err := engine.Recover(context.Background()); err != nil {
				t.Fatalf("transient failure prevented retry: %v", err)
			}
			if err := engine.admission(context.Background()); err != nil {
				t.Fatalf("next admission required administrator reset: %v", err)
			}
		})
	}
}

func TestResetClearsOnlyAfterFullCleanRecheck(t *testing.T) {
	for _, mode := range []string{"clean", "btm", "inspect", "cleanup", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			runner := &admissionRunner{}
			engine := engineFixture(t, runner)
			if err := durableFile(engine.root, quarantineRecord, []byte(`{"quarantined":true}`)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := engine.reset(ctx, func(context.Context) error {
				switch mode {
				case "btm":
					runner.failure = inspectBackgroundItems("Records for UID 12345 : ABCD\n#1: Persistent modern registration\n", testJobUID)
				case "inspect":
					runner.failure = syscall.EPERM
				case "cleanup":
					return syscall.EPERM
				case "cancel":
					cancel()
				}
				return nil
			})
			if (err == nil) != (mode == "clean") {
				t.Fatalf("reset outcome: %v", err)
			}
			_, markerErr := engine.root.Lstat(quarantineRecord)
			if mode == "clean" {
				if !os.IsNotExist(markerErr) {
					t.Fatalf("clean reset retained marker: %v", markerErr)
				}
			} else if markerErr != nil {
				t.Fatalf("failed reset removed marker: %v", markerErr)
			}
		})
	}
}

func TestTransientResetDoesNotCreateQuarantine(t *testing.T) {
	engine := engineFixture(t, &admissionRunner{failure: context.DeadlineExceeded})
	if err := engine.reset(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reset inspection error lost: %v", err)
	}
	if _, err := engine.root.Lstat(quarantineRecord); !os.IsNotExist(err) {
		t.Fatalf("failed initial reset manufactured quarantine: %v", err)
	}
}

func TestResetLaunchAgentsDoesNotFollowEntriesOrTouchOtherHome(t *testing.T) {
	home, owner := t.TempDir(), t.TempDir()
	agents := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agents, 0700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(owner, "owner.plist")
	if err := os.WriteFile(protected, []byte("owner registration"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(owner, filepath.Join(agents, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agents, "job.plist"), []byte("job registration"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := resetLaunchAgents(context.Background(), home); err != nil {
		t.Fatal(err)
	}
	if err := inspectLaunchAgents(home); err != nil {
		t.Fatalf("job LaunchAgents remain: %v", err)
	}
	if data, err := os.ReadFile(protected); err != nil || string(data) != "owner registration" {
		t.Fatalf("owner registration changed: %q %v", data, err)
	}
}

func TestCanceledAdmissionContextCannotCreateQuarantine(t *testing.T) {
	runner := &admissionRunner{failure: ErrContamination}
	engine := engineFixture(t, runner)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.admission(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled admission inspected job state: %v", err)
	}
	if _, err := engine.root.Lstat(quarantineRecord); !os.IsNotExist(err) {
		t.Fatalf("canceled admission wrote marker: %v", err)
	}
}

func TestResetPersistenceStopsOnUnobservableCrontab(t *testing.T) {
	home := t.TempDir()
	err := resetPersistence(context.Background(), Options{JobUID: testJobUID, JobGID: 12346}, home, "job",
		func(_ context.Context, _ *syscall.Credential, executable string, args ...string) (string, string, error) {
			if executable != "/usr/bin/crontab" || len(args) != 1 || args[0] != "-l" {
				t.Fatal("reset performed destructive command after failed census")
			}
			return "partial", "permission denied", syscall.EPERM
		})
	if !errors.Is(err, syscall.EPERM) || errors.Is(err, ErrContamination) {
		t.Fatalf("partial failed census classified as observed crontab: %v", err)
	}
}
