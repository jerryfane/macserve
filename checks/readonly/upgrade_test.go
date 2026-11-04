package readonly

import (
	"slices"
	"testing"
)

// TestUpgradePlanIsReadOnly proves `macserve upgrade --plan`.
func TestUpgradePlanIsReadOnly(t *testing.T) {
	report, err := testBuild(t).Check(Upgrade, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range report.Problems {
		t.Error(p)
	}
	for _, want := range []string{
		mainPkg + ".runUpgrade", mainPkg + ".runUpgradeWith", mainPkg + ".parseUpgradeFlags",
		upgradeFunc + "Plan", upgradeFunc + "Write", upgradeFunc + "SystemProbe",
		setupFunc + "ReleaseVersion", setupFunc + "CheckCarryProof", doctorFunc + "readFile",
	} {
		if !slices.Contains(report.Reached, want) {
			t.Errorf("walk did not reach %s", want)
		}
	}
	// Nothing of the apply clause, the helper or other commands is reached.
	for _, never := range []string{
		mainPkg + ".runUpgradeApply", mainPkg + ".startRootHelper", setupFunc + "RunRoot",
		mainPkg + ".runSetup", mainPkg + ".runDoctor", mainPkg + ".runBuild",
	} {
		if slices.Contains(report.Reached, never) {
			t.Errorf("walk reached %s", never)
		}
	}
}
