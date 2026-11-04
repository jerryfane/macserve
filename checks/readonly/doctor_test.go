package readonly

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestDoctorIsReadOnly proves `macserve doctor` without --live.
func TestDoctorIsReadOnly(t *testing.T) {
	report, err := testBuild(t).Check(Doctor, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range report.Problems {
		t.Error(p)
	}
	for key := range Doctor.Uses {
		if report.Uses[key] == 0 {
			t.Errorf("policy allows %s, which nothing references; remove it", key)
		}
	}
	for _, want := range []string{
		mainPkg + ".main", mainPkg + ".run", mainPkg + ".runDoctor", mainPkg + ".runDoctorWith",
		doctorFunc + "SystemProbe", doctorFunc + "runReadOnly", doctorFunc + "command", doctorFunc + "Run",
		doctorFunc + "readFile", doctorFunc + "portInUse", doctorFunc + "Write",
		module + "/internal/deploy.ParseEnvironment", module + "/internal/setup.SystemBoot",
	} {
		if !slices.Contains(report.Reached, want) {
			t.Errorf("walk did not reach %s", want)
		}
	}
	// Nothing of the live clause or of other commands is reached.
	for _, never := range []string{
		mainPkg + ".runDoctorLive", mainPkg + ".liveGitHub", module + "/internal/setup.CheckFDA",
		mainPkg + ".runSetup", mainPkg + ".runBuild", mainPkg + ".runSetupRoot",
		module + "/internal/onboarding.LocalRepo",
	} {
		if slices.Contains(report.Reached, never) {
			t.Errorf("walk reached %s, outside doctor's read-only clause", never)
		}
	}
}

// TestDoctorMutantsRefused: changes that would let read-only doctor write,
// run another command, dial again or reach the live clause are refused.
func TestDoctorMutantsRefused(t *testing.T) {
	b := testBuild(t)
	root := repoRoot(t)
	system := filepath.Join(root, "internal/doctor/system.go")
	cmd := filepath.Join(root, "cmd/macserve/onboarding_doctor.go")
	report := filepath.Join(root, "internal/doctor/report.go")
	for _, m := range []struct {
		name, file, old, new string
	}{
		{"write in readFile", system, "\tdata, err := os.ReadFile(path)\n", "\t_ = os.WriteFile(path, nil, 0o600)\n\tdata, err := os.ReadFile(path)\n"},
		{"remove in readFile", system, "\tdata, err := os.ReadFile(path)\n", "\t_ = os.Remove(path)\n\tdata, err := os.ReadFile(path)\n"},
		{"launchctl bootout allowed", system, `{"/bin/launchctl", "print-disabled", "system"},`, `{"/bin/launchctl", "print-disabled", "system"}, {"/bin/launchctl", "bootout", "system/org.macserve.worker"},`},
		{"second dial", system, "\tconn.Close()\n\treturn true\n", "\tconn.Close()\n\t_, _ = d.DialContext(ctx, \"tcp\", \"127.0.0.1:1\")\n\treturn true\n"},
		{"check clause runs live", cmd, "\treturn runDoctorWith(doctor.SystemProbe(), args, stdout, stderr)\n}", "\treturn runDoctorLive(args, stdout, stderr)\n}"},
		{"Mode never live", report, "\t\t\treturn ModeLive\n", "\t\t\treturn \"check\"\n"},
	} {
		data, err := os.ReadFile(m.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), m.old) {
			t.Fatalf("%s: anchor not found", m.name)
		}
		overlay := map[string][]byte{m.file: []byte(strings.Replace(string(data), m.old, m.new, 1))}
		r, err := b.Check(Doctor, overlay)
		if err != nil {
			t.Errorf("mutant %q does not type-check: %v", m.name, err)
			continue
		}
		if len(r.Problems) == 0 {
			t.Errorf("mutant %q survived", m.name)
		}
	}
}

// TestDoctorRefsGuardAllowlists: a module init that widens either command
// allowlist is refused under the Doctor policy itself.
func TestDoctorRefsGuardAllowlists(t *testing.T) {
	b := testBuild(t)
	root := repoRoot(t)
	// Each mutant appends an init to an existing file of the package.
	for _, m := range []struct{ name, file, code string }{
		{"plan allowlist appended", "internal/setup/plan/runner.go", "\nfunc init() { readOnlyCommands = append(readOnlyCommands, []string{\"/bin/launchctl\", \"bootout\", \"system/x\"}) }\n"},
		{"launchctl gui pattern replaced", "internal/doctor/system.go", "\nfunc init() { launchctlGUI = regexp.MustCompile(`.*`) }\n"},
	} {
		path := filepath.Join(root, m.file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		r, err := b.Check(Doctor, map[string][]byte{path: append(data, m.code...)})
		if err != nil {
			t.Errorf("%s: %v", m.name, err)
			continue
		}
		if len(r.Problems) == 0 {
			t.Errorf("mutant %q survived", m.name)
		}
	}
}
