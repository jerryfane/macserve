package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func quiescentFixture(t *testing.T, persistence string) (Options, GUIBaseline) {
	t.Helper()
	options, _ := attestationFixture(t)
	boot, err := bootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if persistence == "" {
		if persistence, err = PersistenceDigest(options.PersistencePath, options.JobUID); err != nil {
			t.Fatal(err)
		}
	}
	options.BaselinePath = filepath.Join(filepath.Dir(options.PersistencePath), "baseline.json")
	options.Root = privateRootFixture(t)
	baseline := GUIBaseline{JobUID: options.JobUID, Boot: boot, PersistenceSHA256: persistence, Processes: []ProcessIdentity{{PID: 100, Start: "10:0"}, {PID: 101, Start: "10:1"}}, Launchd: &LaunchdEnvironment{GUI: map[string]string{}, User: map[string]string{}}}
	if err := saveBaseline(options.BaselinePath, baseline); err != nil {
		t.Fatal(err)
	}
	return options, baseline
}

func quiescentScope(samples []processSample) *processScope {
	return &processScope{uid: testJobUID, agents: newFakeAgents(), interval: time.Millisecond, childWait: 5 * time.Millisecond, sample: func(context.Context) ([]processSample, error) {
		return samples, nil
	}}
}

func TestWorkerQuiescentPassesOnAuditedBaselineOnly(t *testing.T) {
	options, _ := quiescentFixture(t, "")
	report, err := workerQuiescent(context.Background(), options, quiescentScope([]processSample{sample(100, "10:0")}))
	if err != nil || !report.Quiescent || report.BaselineProcesses != 2 || len(report.BaselineExited) != 1 || report.BaselineExited[0].PID != 101 {
		t.Fatalf("quiet baseline refused: %+v %v", report, err)
	}
}

// ObserveGUIBaseline (the maintenance census) accepts an active job process;
// the carry gate must not.
func TestWorkerQuiescentFailsOnResidual(t *testing.T) {
	options, baseline := quiescentFixture(t, "")
	samples := []processSample{sample(100, "10:0"), sample(101, "10:1"), sample(200, "20:0")}
	// The census ObserveGUIBaseline applies: no settle sampling, residual kept.
	maintenance := processScope{uid: testJobUID, baseline: baseline, agents: newFakeAgents()}
	if _, err := maintenance.census(context.Background(), samples); err != nil {
		t.Fatalf("maintenance census fixture: %v", err)
	}
	report, err := workerQuiescent(context.Background(), options, quiescentScope(samples))
	if !errors.Is(err, ErrContamination) || report.Quiescent || report.Error == "" {
		t.Fatalf("residual job process passed: %+v %v", report, err)
	}
}

func TestWorkerQuiescentFailsOnUnverifiedRelaunch(t *testing.T) {
	options, _ := quiescentFixture(t, "")
	report, err := workerQuiescent(context.Background(), options, quiescentScope([]processSample{sample(100, "10:0"), sample(300, "30:0")}))
	if !errors.Is(err, errRelaunchUnverified) || report.Quiescent {
		t.Fatalf("unverified relaunch passed: %+v %v", report, err)
	}
}

func TestWorkerQuiescentFailsOnChangedPersistence(t *testing.T) {
	options, _ := quiescentFixture(t, "0000000000000000000000000000000000000000000000000000000000000000")
	report, err := workerQuiescent(context.Background(), options, quiescentScope([]processSample{sample(100, "10:0")}))
	if err == nil || report.Quiescent {
		t.Fatalf("changed reviewed persistence passed: %+v", report)
	}
}

func TestWorkerQuiescentFailsOnQuarantineOrInconclusive(t *testing.T) {
	for name, record := range map[string]string{quarantineRecord: `{"quarantined":true}`, admissionInconclusiveRecord: ""} {
		t.Run(name, func(t *testing.T) {
			options, _ := quiescentFixture(t, "")
			data := []byte(record)
			if record == "" {
				var err error
				if data, err = json.Marshal(AdmissionInconclusive{Reason: "unsettled", Since: time.Now().Add(-time.Minute), CheckedAt: time.Now()}); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(options.Root, name), data, 0600); err != nil {
				t.Fatal(err)
			}
			report, err := workerQuiescent(context.Background(), options, quiescentScope([]processSample{sample(100, "10:0")}))
			if err == nil || report.Quiescent {
				t.Fatalf("%s worker passed: %+v", name, report)
			}
		})
	}
}
