package readonly

const (
	doctorPkg  = module + "/internal/doctor"
	doctorFunc = doctorPkg + "."
)

// Doctor is the policy for `macserve doctor` without --live: main and the
// dispatch, the "doctor" entry of the command table, everything in
// internal/doctor and the package initialisation of every module package in
// the binary. The live clause (the transient launchd Full Disk Access job
// and the GitHub App calls, sudo only) is the only code not walked.
var Doctor = Policy{
	Package: doctorPkg,
	Roots: []string{
		mainPkg + ".main",
		mainPkg + ".run",
		mainPkg + ".onboardingCommand",
		mainPkg + ".runDoctor",
		mainPkg + ".doctorDispatch",
		mainPkg + ".runDoctorWith",
	},
	// doctorDispatch is proven for the word "check": runDoctor passes
	// doctor.Mode(args), which is "live" whenever an argument names the
	// live flag. runDoctor and doctor.Mode are pinned.
	Switch: map[string]string{mainPkg + ".run": "doctor", mainPkg + ".doctorDispatch": "check"},
	Entry:  map[string]string{mainPkg + ".run": mainPkg + ".main", mainPkg + ".doctorDispatch": mainPkg + ".runDoctor"},
	Table: &Table{
		Var: mainPkg + ".onboardingCommands", Name: "name", Run: "run", Key: "doctor", Root: mainPkg + ".runDoctor",
		Fields: []string{"name", "summary", "help", "run"},
	},
	Imports: []string{
		module + "/internal/deploy", module + "/internal/health", module + "/internal/hostguard",
		module + "/internal/model", module + "/internal/setup", module + "/internal/setup/plan",
	},
	Seams: []string{
		module + "/internal/deploy.ParseEnvironment",
		// installed-binaries.json: strict decode of bytes already read and
		// a digest lookup, no I/O.
		module + "/internal/deploy.ParseInstalledBinaries",
		"(*" + module + "/internal/deploy.InstalledBinaries).ReleaseDigest",
		module + "/internal/hostguard.ConsoleAdmissible",
		module + "/internal/setup.SystemBoot",
		// The recorded controller digest: a walk of the decoded ledger's
		// install input, releases and controller rebinds, no I/O.
		"(*" + module + "/internal/setup.Ledger).InstalledController",
		module + "/internal/setup/plan.AllowedCommand",
		mainPkg + ".usage",
	},
	Dispatch: map[string][]string{mainPkg + ".onboardingCommands": {mainPkg + ".onboardingCommand", mainPkg + ".writeOnboardingUsage"}},
	PureStd:  SetupPlan.PureStd,
	Uses: map[string]Use{
		"os.Args":   {Caller: mainPkg + ".main", Max: 1},
		"os.Stdout": {Caller: mainPkg + ".main", Max: 1},
		"os.Stderr": {Caller: mainPkg + ".main", Max: 1},
		"os.Exit":   {Caller: mainPkg + ".main", Max: 1},
		// The only write: the report to the CLI writer passed down from main.
		"(io.Writer).Write": {Caller: doctorFunc + "Write", Max: 1, Args: []string{"data"}},
		// The one command runner: one process, built from the checked argv.
		"os/exec.CommandContext": {Caller: doctorFunc + "command", Max: 1, Args: []string{"ctx", "argv[0]", "argv[1:]..."}},
		"(*os/exec.Cmd).Run":     {Caller: doctorFunc + "runReadOnly", Max: 1, Args: []string{}},
		"os.Geteuid":             {Caller: doctorFunc + "SystemProbe", Max: 1},
		// Reads: stat and read files, lstat, interfaces, the boot identity.
		"os.Stat":                         {Caller: doctorFunc + "readFile", Max: 1, Args: []string{"path"}},
		"os.ReadFile":                     {Caller: doctorFunc + "readFile", Max: 1, Args: []string{"path"}},
		"os.Lstat":                        {Caller: doctorFunc + "lstat", Max: 1, Args: []string{"path"}},
		"(io/fs.FileInfo).Mode":           {},
		"(io/fs.FileInfo).Sys":            {Caller: doctorFunc + "lstat", Max: 1},
		"(io/fs.FileInfo).Size":           {Caller: doctorFunc + "readFile", Max: 1},
		"net.InterfaceAddrs":              {Caller: doctorFunc + "interfaceAddrs", Max: 1},
		"golang.org/x/sys/unix.SysctlRaw": {Caller: module + "/internal/setup.SystemBoot", Max: 1, Args: []string{`"kern.boottime"`}},
		"golang.org/x/sys/unix.Sysctl":    {Caller: module + "/internal/setup.SystemBoot", Max: 1, Args: []string{`"kern.bootsessionuuid"`}},
		// One TCP connect to the API address; the connection may only be
		// closed.
		"(*net.Dialer).DialContext": {Caller: doctorFunc + "portInUse", Max: 1, Args: []string{"ctx", `"tcp"`, "ap.String()"}},
		"(net.Conn).Close":          {Caller: doctorFunc + "portInUse", Max: 1, Args: []string{}},
		"encoding/json.Unmarshal":   {},
		// ProgramArguments of a launchd plist already read into memory.
		"encoding/xml.NewDecoder":               {Caller: doctorFunc + "programArguments", Max: 1, Args: []string{"bytes.NewReader(data)"}},
		"(*encoding/xml.Decoder).Token":         {Caller: doctorFunc + "programArguments", Max: 1, Args: []string{}},
		"(*encoding/xml.Decoder).DecodeElement": {Caller: doctorFunc + "programArguments", Max: 2},
		// ParseInstalledBinaries: strict decode of installed-binaries.json
		// bytes already read, and its digest syntax check.
		"encoding/json.NewDecoder":                       {Caller: module + "/internal/deploy.ParseInstalledBinaries", Max: 1, Args: []string{"bytes.NewReader(data)"}},
		"(*encoding/json.Decoder).DisallowUnknownFields": {Caller: module + "/internal/deploy.ParseInstalledBinaries", Max: 1, Args: []string{}},
		"(*encoding/json.Decoder).Decode":                {Caller: module + "/internal/deploy.ParseInstalledBinaries", Max: 2},
		"encoding/hex.DecodeString":                      {Caller: module + "/internal/deploy.validDigest", Max: 1, Args: []string{"s"}},
		// Pure encoding into memory (doctor's report, model and ledger digests).
		"encoding/json.Marshal":       {},
		"encoding/json.MarshalIndent": {},
		"crypto/sha256.Sum256":        {},
		"encoding/hex.EncodeToString": {},
		"runtime/debug.ReadBuildInfo": {Caller: module + "/internal/worker.<init>", Max: 1},
		"runtime.Version":             {Caller: module + "/internal/worker.<init>", Max: 1},
		"path/filepath.IsAbs":         {},
		"path/filepath.Clean":         {},
		"path/filepath.Base":          {},
		"flag.NewFlagSet":             {Caller: mainPkg + ".runDoctorWith", Max: 1},
		"flag.ErrHelp":                {Caller: mainPkg + ".runDoctorWith", Max: 1},
		"(*flag.FlagSet).SetOutput":   {Caller: mainPkg + ".runDoctorWith", Max: 1, Args: []string{"io.Discard"}},
		"(*flag.FlagSet).BoolVar":     {Caller: mainPkg + ".runDoctorWith"},
		"(*flag.FlagSet).StringVar":   {Caller: mainPkg + ".runDoctorWith"},
		"(*flag.FlagSet).Parse":       {Caller: mainPkg + ".runDoctorWith", Max: 1},
		"(*flag.FlagSet).NArg":        {Caller: mainPkg + ".runDoctorWith", Max: 1},
	},
	SafeBox: SetupPlan.SafeBox,
	Boxes:   []Box{{Caller: mainPkg + ".main", From: "*os.File", To: "io.Writer"}},
	Fields: map[string]string{
		"os/exec.Cmd.Env":    doctorFunc + "command",
		"os/exec.Cmd.Dir":    doctorFunc + "command",
		"os/exec.Cmd.Stdout": doctorFunc + "command",
		"os/exec.Cmd.Stderr": doctorFunc + "command",
		"net.Dialer.Timeout": doctorFunc + "portInUse",
	},
	UnsafeFiles: SetupPlan.UnsafeFiles,
	EmbedFiles:  SetupPlan.EmbedFiles,
	Refs: map[string][]string{
		doctorFunc + "launchctlCommands": {doctorFunc + "AllowedCommand"},
		doctorFunc + "doctorEnv":         {doctorFunc + "command"},
		doctorFunc + "launchctlGUI":      {doctorFunc + "AllowedCommand"},
		planFunc + "readOnlyCommands":    {planFunc + "AllowedCommand"},
	},
	Pinned: map[string]string{
		mainPkg + ".main":                SetupPlan.Pinned[mainPkg+".main"],
		doctorFunc + "launchctlCommands": "1efea01e9436c631265c4dcb6c08d4738e73f8c270d57a47d3f486c347e7306e",
		doctorFunc + "launchctlGUI":      "a8f5ca9c4ff7da987f1dbabb562dd4064ad15d04a6e6ffc054617408e843b809",
		doctorFunc + "doctorEnv":         "15dfb777934bca3a9f605efa35133e873a2e4f632486d5221d700e7402529b7e",
		doctorFunc + "AllowedCommand":    "e2e28f6fd058c2eb3396098fb57eed517eae1fc3b1b828210681cbf411e03948",
		doctorFunc + "command":           "fbb70f09b0bf7cd50ce067c6b651b121ad4646e6a01a64370d6f21c83c190757",
		doctorFunc + "runReadOnly":       "9a01fa6fcca2a28efef67e96780826a64726d89e9ee477f68c1663f76186d420",
		doctorFunc + "readFile":          "626f19424d5ed5b56da12cedb1b75e698cd6142e510873a478cd0ec151e326ab",
		doctorFunc + "portInUse":         "3651950197abf1e1ebbef7fecb8be49d308ee8ca665d149d87de5070a432f9dc",
		doctorFunc + "lstat":             "cfe02ee0e3f487ced55e72b8fb96c08d5ea213120dc79f81caf562a654466044",
		doctorFunc + "Mode":              "19da2835e7d8d18cbe8785b1c6f522219bb722b09629004080d134feeee53cff",
		mainPkg + ".runDoctor":           "e6b70ea486e4ea292e66a5a4149eebad3989f77606451b5bd65eb29d50f9d4a3",
		mainPkg + ".doctorDispatch":      "026a9fa720d9101e68860647b58fc0744655e452fd07b1f7b28e70a51094bbef",
		"github.com/jerryfane/macserve/internal/setup/plan.AllowedCommand":   SetupPlan.Pinned[planFunc+"AllowedCommand"],
		"github.com/jerryfane/macserve/internal/setup/plan.readOnlyCommands": SetupPlan.Pinned[planFunc+"readOnlyCommands"],
	},
}
