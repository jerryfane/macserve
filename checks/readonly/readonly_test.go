package readonly

import (
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	listed    *Build
	buildErr  error
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		t.Fatal(err)
	}
	return root
}

// testBuild lists the release build once. The extra std packages give the
// mutants below export data for imports the tree itself does not use.
func testBuild(t *testing.T) *Build {
	t.Helper()
	buildOnce.Do(func() {
		listed, buildErr = List(repoRoot(t), "./cmd/macserve", "./internal/setup/plan", "io/ioutil", "net/http", "os/signal", "unsafe")
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return listed
}

func TestSetupPlanIsReadOnly(t *testing.T) {
	report, err := testBuild(t).Check(SetupPlan, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range report.Problems {
		t.Error(p)
	}
	for key := range SetupPlan.Uses {
		if report.Uses[key] == 0 {
			t.Errorf("policy allows %s, which nothing references; remove it", key)
		}
	}
	// The walk must reach the code it is meant to prove: main and the
	// dispatch, the command entry points, the runner, the system probe and
	// the deploy parser seam.
	for _, want := range []string{
		mainPkg + ".main", mainPkg + ".run", mainPkg + ".usage",
		mainPkg + ".onboardingCommand", mainPkg + ".runSetup", mainPkg + ".runSetupWith",
		planFunc + "SystemProbe", planFunc + "runReadOnly", planFunc + "command", planFunc + "portInUse",
		planFunc + "lstat", planFunc + "Preflight", planFunc + "RenderEnvironment", planFunc + "WritePlan",
		module + "/internal/deploy.ParseEnvironment", module + "/internal/maintenance.ValidateCoexistenceConfig",
	} {
		if !slices.Contains(report.Reached, want) {
			t.Errorf("walk did not reach %s; reached %q", want, report.Reached)
		}
	}
	// Nothing outside the "setup" clause of the dispatch is reached.
	for _, never := range []string{mainPkg + ".runDeployInstall", mainPkg + ".runQualify", mainPkg + ".runWait"} {
		if slices.Contains(report.Reached, never) {
			t.Errorf("walk reached %s, outside the setup dispatch", never)
		}
	}
}
