package readonly

const (
	module   = "github.com/jerryfane/macserve"
	planPkg  = module + "/internal/setup/plan"
	mainPkg  = module + "/cmd/macserve"
	planFunc = planPkg + "."
)

// SetupPlan is the policy for `macserve setup --plan`: main and the
// dispatch for the word "setup", the onboarding entry points in
// cmd/macserve/onboarding.go, everything in internal/setup/plan, and the
// package initialisation of every module package in the binary.
var SetupPlan = Policy{
	Package: planPkg,
	Roots: []string{
		mainPkg + ".main",
		mainPkg + ".run",
		mainPkg + ".onboardingCommand",
		mainPkg + ".runSetup",
		mainPkg + ".runSetupWith",
	},
	Switch:  map[string]string{mainPkg + ".run": "setup"},
	Imports: []string{module + "/internal/deploy", module + "/internal/setup"},
	Seams: []string{
		module + "/internal/deploy.ParseEnvironment",
		mainPkg + ".usage",
	},
	// The command table. Its "setup" entry is runSetup, a root
	// (TestSetupDispatchesToRunSetup); the inactive entries have no run
	// function (TestInactiveShellsHaveNoRunFunction).
	Dispatch: map[string][]string{mainPkg + ".onboardingCommands": {mainPkg + ".onboardingCommand", mainPkg + ".writeOnboardingUsage"}},
	PureStd: []string{
		"bytes", "cmp", "context", "errors", "fmt", "io", "io/fs", "iter", "maps", "math", "net/netip",
		"regexp", "slices", "sort", "strconv", "strings", "time", "unicode", "unicode/utf8",
	},
	Uses: map[string]Use{
		// main: the process arguments and the CLI's stdout and stderr.
		"os.Args":   {Caller: mainPkg + ".main", Max: 1},
		"os.Stdout": {Caller: mainPkg + ".main", Max: 1},
		"os.Stderr": {Caller: mainPkg + ".main", Max: 1},
		"os.Exit":   {Caller: mainPkg + ".main", Max: 1},
		// The only writes: the plan to the CLI writer passed down from main.
		"(io.Writer).Write": {Caller: planFunc + "WritePlan", Max: 1, Args: []string{"b.Bytes()"}},
		// The one command runner: one process, built from the checked argv.
		"os/exec.CommandContext": {Caller: planFunc + "command", Max: 1, Args: []string{"ctx", "argv[0]", "argv[1:]..."}},
		"(*os/exec.Cmd).Run":     {Caller: planFunc + "runReadOnly", Max: 1, Args: []string{}},
		// Identity of the invoking process.
		"os.Getuid":  {Caller: ""},
		"os.Geteuid": {Caller: planFunc + "SystemProbe", Max: 1},
		"os.Getgid":  {Caller: planFunc + "SystemProbe", Max: 1},
		"os.Getegid": {Caller: planFunc + "SystemProbe", Max: 1},
		"os.Environ": {Caller: planFunc + "SystemProbe", Max: 1},
		// Reads: lstat, interfaces, accounts.
		"os.Lstat":                 {Caller: planFunc + "lstat", Max: 1, Args: []string{"path"}},
		"(io/fs.FileInfo).Mode":    {Caller: planFunc + "lstat", Max: 1},
		"(io/fs.FileInfo).Sys":     {Caller: planFunc + "lstat", Max: 1},
		"net.InterfaceAddrs":       {Caller: planFunc + "interfaceAddrs", Max: 1},
		"os/user.LookupId":         {Caller: planFunc + "invokingAccount", Max: 1},
		"(*os/user.User).GroupIds": {Caller: planFunc + "invokingAccount", Max: 1},
		"os/user.LookupGroup":      {Caller: planFunc + "adminGID", Max: 1, Args: []string{`"admin"`}},
		// One TCP connect to the candidate API port; the connection may
		// only be closed.
		"(*net.Dialer).DialContext": {Caller: planFunc + "portInUse", Max: 1, Args: []string{"ctx", `"tcp"`, "ap.String()"}},
		"(net.Conn).Close":          {Caller: planFunc + "portInUse", Max: 1, Args: []string{}},
		// Build information read by internal/worker at start-up.
		"runtime/debug.ReadBuildInfo": {Caller: module + "/internal/worker.<init>", Max: 1},
		"runtime.Version":             {Caller: module + "/internal/worker.<init>", Max: 1},
		"path/filepath.IsAbs":         {},
		"path/filepath.Clean":         {},
		"path/filepath.Base":          {},
		"reflect.DeepEqual":           {Caller: planFunc + "exactEnvironment", Max: 1},
		"flag.NewFlagSet":             {Caller: mainPkg + ".runSetupWith", Max: 1},
		"flag.ErrHelp":                {Caller: mainPkg + ".runSetupWith", Max: 1},
		"(*flag.FlagSet).SetOutput":   {Caller: mainPkg + ".runSetupWith", Max: 1, Args: []string{"io.Discard"}},
		"(*flag.FlagSet).BoolVar":     {Caller: mainPkg + ".runSetupWith"},
		"(*flag.FlagSet).StringVar":   {Caller: mainPkg + ".runSetupWith"},
		"(*flag.FlagSet).Parse":       {Caller: mainPkg + ".runSetupWith", Max: 1},
		"(*flag.FlagSet).NArg":        {Caller: mainPkg + ".runSetupWith", Max: 1},
	},
	SafeBox: []string{"*bytes.Buffer", "*bytes.Reader", "*strings.Builder", "*strings.Reader"},
	Boxes:   []Box{{Caller: mainPkg + ".main", From: "*os.File", To: "io.Writer"}},
	Fields: map[string]string{
		"os/exec.Cmd.Env":    planFunc + "command",
		"os/exec.Cmd.Dir":    planFunc + "command",
		"os/exec.Cmd.Stdout": planFunc + "command",
		"os/exec.Cmd.Stderr": planFunc + "command",
		"net.Dialer.Timeout": planFunc + "portInUse",
	},
	Refs: map[string][]string{
		planFunc + "readOnlyCommands": {planFunc + "AllowedCommand"},
		planFunc + "commandEnv":       {planFunc + "command"},
	},
	// The command allowlist and everything that runs or dials. A change
	// here is a change to what `setup --plan` may do and needs review.
	Pinned: map[string]string{
		planFunc + "readOnlyCommands":  "b3d4af8c1c840fbf1093c306e5443d68109943751351953423bb3edb22f35f5f",
		planFunc + "commandEnv":        "ca060e11532bf08953461902a0f3cefe849b90dc09ad9d043c11a3fdefeaacef",
		planFunc + "xcodebuildSuffix":  "eb025439af1f96f08c68725e789a9f9e7576cdc0fa19b96fb70e69f39cc0a6a9",
		planFunc + "AllowedCommand":    "5c1e14556a260c8e1ca9326cab1db44a1f607215fbb19268efc218c050bad361",
		planFunc + "validDeveloperDir": "a60b86902a8b25f2f63fbab0f1dbd759b2745aa4e5fb9fbfc7bc80280c4f02ef",
		planFunc + "command":           "ac58d62bbd8916b913a71ec08986f61a241e40edb8afebb050177bb8b162c0b1",
		planFunc + "runReadOnly":       "a2b323cebd33cacb4368df7790c9e18d82a737cc5a5524b76ec4fbe78e003b08",
		planFunc + "portInUse":         "280ef394e7c9b1098c4068019a427193f2d34cf7f7b3ec9c0fa46c06c3f0d9ee",
		planFunc + "lstat":             "251be9e0866e8e13a0b1042da3d141584d1f0153d35d63d50564faa7b5948642",
	},
}
