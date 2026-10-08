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
		})
	}
}

func TestPersistenceCensusRejectsUnknownAndNonemptyData(t *testing.T) {
	for _, tc := range []struct {
		out, diagnostic string
		err             error
		allowed         bool
	}{
		{"", "", nil, true},
		{"# scheduled later", "", nil, false},
		{"", "permission denied", syscall.EPERM, false},
		{"", "crontab: no crontab for job", context.DeadlineExceeded, false},
		{"", "unexpected warning", nil, false},
	} {
		if err := inspectCrontab(tc.out, tc.diagnostic, tc.err, "job"); (err == nil) != tc.allowed {
			t.Fatalf("crontab inspection: %v", err)
		}
	}
	for _, tc := range []struct {
		data    string
		allowed bool
	}{
		{"Records for UID 12345 : ABCD-1234\n================\n", true},
		{"Records for UID 12345 : ABCD-1234\n#1: Login Item\n", false},
		{"Records for UID 12345 : ABCD-1234\nunknown data\n", false},
		{"Records for UID 12345 : ABCD-1234\nRecords for UID 12345 : ABCD-1234\n", false},
		{"Records for UID 999 : ABCD-1234\n", false},
		{"", false},
	} {
		if err := inspectBackgroundItems(tc.data, testJobUID); (err == nil) != tc.allowed {
			t.Fatalf("background inspection %q: %v", tc.data, err)
		}
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
	if err := scope.observeQuiet(context.Background()); err == nil {
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
	runner := &admissionRunner{failure: errors.New("login item inspection denied")}
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
	if err := reopened.reconcileRecords(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Recover(context.Background()); err != nil {
		t.Fatalf("reconciled admission remained quarantined: %v", err)
	}
}

func TestReconcileOnlyRecordedResourcesAndRetainsPendingEvidence(t *testing.T) {
	var actions []string
	runner := &fakeRunner{hook: func(_ context.Context, command Command, out, _ io.Writer) (bool, ProcessResult, error) {
		actions = append(actions, strings.Join(command.Args, " "))
		if strings.Join(command.Args, " ") == "simctl list devices --json" {
			io.WriteString(out, `{"devices":{"runtime":[{"udid":"`+ownedUDID+`"}]}}`)
		}
		return true, ProcessResult{CleanupOK: true}, nil
	}}
	engine := engineFixture(t, runner)
	if err := engine.markReconciliation(); err != nil {
		t.Fatal(err)
	}
	if err := engine.saveManifest(manifest{JobID: "recorded", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DeviceUDID: ownedUDID, Active: true, ProcessUncertain: true}); err != nil {
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
	if err := engine.reconcileRecords(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(actions, ";"); got != "simctl list devices --json;simctl shutdown "+ownedUDID+";simctl delete "+ownedUDID {
		t.Fatalf("unrecorded simulator action: %s", got)
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

func TestReconcileFailureRetainsUncertaintyAndQuarantine(t *testing.T) {
	failure := errors.New("simulator inventory unavailable")
	runner := &fakeRunner{hook: func(context.Context, Command, io.Writer, io.Writer) (bool, ProcessResult, error) {
		return true, ProcessResult{CleanupOK: true}, failure
	}}
	engine := engineFixture(t, runner)
	if err := engine.markReconciliation(); err != nil {
		t.Fatal(err)
	}
	if err := engine.saveManifest(manifest{JobID: "recorded", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DeviceUDID: ownedUDID, ProcessUncertain: true}); err != nil {
		t.Fatal(err)
	}
	if err := engine.reconcileRecords(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("reconcile failure lost: %v", err)
	}
	var saved manifest
	if err := readJSON(engine.root, "manifests/recorded.json", &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.ProcessUncertain || saved.DeviceUDID != ownedUDID {
		t.Fatalf("uncertainty erased: %+v", saved)
	}
	if err := engine.Recover(context.Background()); !errors.Is(err, ErrRecovery) {
		t.Fatalf("failed reconcile unquarantined: %v", err)
	}
}

func TestLegacyLoginInspectionAndUnavailableNativeAdmissionFailClosed(t *testing.T) {
	for _, tc := range []struct {
		out, diagnostic string
		err             error
		allowed         bool
	}{
		{"0\n", "", nil, true},
		{"1\n", "", nil, false},
		{"", "", nil, false},
		{"0\n", "not authorized", nil, false},
		{"0\n", "", context.DeadlineExceeded, false},
		{"", "", os.ErrNotExist, false},
	} {
		if err := inspectLoginItems(tc.out, tc.diagnostic, tc.err); (err == nil) != tc.allowed {
			t.Fatalf("login census %q: %v", tc.out, err)
		}
	}
	runner := &nativeRunner{scope: scopeFixture()}
	if err := runner.Admission(context.Background()); err == nil {
		t.Fatal("missing native persistence inspector admitted job")
	}
	runner.persistence = func(context.Context) error { return nil }
	if err := runner.Admission(context.Background()); err == nil {
		t.Fatal("missing native baseline admitted job")
	}
}
