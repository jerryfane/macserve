package readonly

const (
	upgradePkg  = module + "/internal/setup/upgrade"
	upgradeFunc = upgradePkg + "."
	setupFunc   = module + "/internal/setup."
)

// Upgrade is the policy for `macserve upgrade --plan`: main and the
// dispatch, the "upgrade" entry of the command table, everything in
// internal/setup/upgrade (which reads the host through doctor's read-only
// probe), the pure release checks of internal/setup and the package
// initialisation of every module package in the binary. The apply clause
// (the upgrade helper under sudo) is the only code not walked.
var Upgrade = Policy{
	Package: upgradePkg,
	Roots: []string{
		mainPkg + ".main",
		mainPkg + ".run",
		mainPkg + ".onboardingCommand",
		mainPkg + ".runUpgrade",
		mainPkg + ".upgradeDispatch",
		mainPkg + ".runUpgradeWith",
		mainPkg + ".parseUpgradeFlags",
		"(" + mainPkg + ".upgradeFlags).options",
	},
	// upgradeDispatch is proven for the word "plan": runUpgrade passes
	// plan.Mode(args), which is "plan" whenever an argument names the plan
	// flag. runUpgrade and plan.Mode are pinned.
	Switch: map[string]string{mainPkg + ".run": "upgrade", mainPkg + ".upgradeDispatch": "plan"},
	Entry:  map[string]string{mainPkg + ".run": mainPkg + ".main", mainPkg + ".upgradeDispatch": mainPkg + ".runUpgrade"},
	Table: &Table{
		Var: mainPkg + ".onboardingCommands", Name: "name", Run: "run", Key: "upgrade", Root: mainPkg + ".runUpgrade",
		Fields: []string{"name", "summary", "help", "run"},
	},
	// qualification only for the CarryBinaries struct type: no function of
	// it is a seam, so plan code cannot call into it.
	Imports: []string{
		module + "/internal/deploy", module + "/internal/doctor", module + "/internal/qualification", module + "/internal/setup",
	},
	Seams: []string{
		module + "/internal/deploy.ParseEnvironment",
		module + "/internal/deploy.ParseInstalledBinaries",
		"(*" + module + "/internal/deploy.InstalledBinaries).ReleaseDigest",
		module + "/internal/doctor.SystemProbe",
		setupFunc + "ReleaseDigest",
		setupFunc + "ReleaseVersion",
		setupFunc + "CompareReleases",
		setupFunc + "CheckCarryProof",
		setupFunc + "ValidRelease",
		module + "/internal/setup/plan.Mode",
		mainPkg + ".usage",
	},
	Dispatch: map[string][]string{mainPkg + ".onboardingCommands": {mainPkg + ".onboardingCommand", mainPkg + ".writeOnboardingUsage"}},
	PureStd:  SetupPlan.PureStd,
	Uses: func() map[string]Use {
		uses := map[string]Use{}
		for name, use := range Doctor.Uses {
			uses[name] = use
		}
		for _, name := range []string{"flag.NewFlagSet", "flag.ErrHelp", "(*flag.FlagSet).SetOutput", "(*flag.FlagSet).BoolVar", "(*flag.FlagSet).StringVar", "(*flag.FlagSet).Parse", "(*flag.FlagSet).NArg"} {
			delete(uses, name)
		}
		// The only write: the plan to the CLI writer passed down from main.
		uses["(io.Writer).Write"] = Use{Caller: upgradeFunc + "Write", Max: 1, Args: []string{"b.Bytes()"}}
		// The running binary's path, then reads through doctor's readFile.
		uses["os.Executable"] = Use{Caller: upgradeFunc + "executable", Max: 1}
		uses["path/filepath.EvalSymlinks"] = Use{Caller: upgradeFunc + "executable", Max: 1, Args: []string{"self"}}
		// qualify carry's strict proof decoding (qualification.decode and
		// uniqueJSON), from bytes in memory.
		for _, name := range []string{"encoding/json.NewDecoder", "(*encoding/json.Decoder).UseNumber", "(*encoding/json.Decoder).Token", "(*encoding/json.Decoder).More", "(*encoding/json.Decoder).DisallowUnknownFields", "(*encoding/json.Decoder).Decode"} {
			uses[name] = Use{}
		}
		// The release's macserve-controller beside this binary, read through
		// doctor's readFile.
		uses["path/filepath.Join"] = Use{Caller: upgradeFunc + "Plan", Max: 1, Args: []string{"filepath.Dir(self)", "deploy.ControllerBinaryName"}}
		uses["path/filepath.Dir"] = Use{Caller: upgradeFunc + "Plan", Max: 1, Args: []string{"self"}}
		// The release version stamped into a binary already in memory.
		uses["debug/buildinfo.Read"] = Use{Caller: setupFunc + "ReleaseVersion", Max: 1, Args: []string{"bytes.NewReader(binary)"}}
		uses["flag.NewFlagSet"] = Use{Caller: mainPkg + ".parseUpgradeFlags", Max: 1}
		uses["flag.ErrHelp"] = Use{Caller: mainPkg + ".parseUpgradeFlags", Max: 1}
		uses["(*flag.FlagSet).SetOutput"] = Use{Caller: mainPkg + ".parseUpgradeFlags", Max: 1, Args: []string{"io.Discard"}}
		uses["(*flag.FlagSet).BoolVar"] = Use{Caller: mainPkg + ".parseUpgradeFlags"}
		uses["(*flag.FlagSet).StringVar"] = Use{Caller: mainPkg + ".parseUpgradeFlags"}
		uses["(*flag.FlagSet).Parse"] = Use{Caller: mainPkg + ".parseUpgradeFlags", Max: 1}
		uses["(*flag.FlagSet).NArg"] = Use{Caller: mainPkg + ".parseUpgradeFlags", Max: 1}
		return uses
	}(),
	SafeBox:     SetupPlan.SafeBox,
	Boxes:       Doctor.Boxes,
	Fields:      Doctor.Fields,
	UnsafeFiles: SetupPlan.UnsafeFiles,
	EmbedFiles:  SetupPlan.EmbedFiles,
	Refs:        Doctor.Refs,
	Pinned: func() map[string]string {
		pins := map[string]string{}
		for name, pin := range Doctor.Pinned {
			pins[name] = pin
		}
		delete(pins, mainPkg+".runDoctor")
		delete(pins, mainPkg+".doctorDispatch")
		pins[mainPkg+".runUpgrade"] = "98c0831ae1bea40a1b0ebc9daf17676a8f9d3a1d5911d27ec1813fe8915c66d5"
		pins[mainPkg+".upgradeDispatch"] = "a9e5067e245dc27cb3c2988102b851d2415b7deab8b7bf0bc906cd2244e51c7e"
		pins[planFunc+"Mode"] = SetupPlan.Pinned[planFunc+"Mode"]
		return pins
	}(),
}
