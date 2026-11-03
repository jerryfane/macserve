package readonly

const (
	module   = "github.com/jerryfane/macserve"
	planPkg  = module + "/internal/setup/plan"
	mainPkg  = module + "/cmd/macserve"
	planFunc = planPkg + "."
)

// SetupPlan is the policy for `macserve setup --plan`: everything in
// internal/setup/plan, plus the command entry points in
// cmd/macserve/onboarding.go that run before and around it.
var SetupPlan = Policy{
	Package: planPkg,
	Roots: []string{
		mainPkg + ".onboardingCommand",
		mainPkg + ".runSetup",
		mainPkg + ".runSetupWith",
	},
	Imports: []string{module + "/internal/deploy", module + "/internal/setup"},
	Seams:   []string{module + "/internal/deploy.ParseEnvironment"},
	// The command table; its "setup" entry is runSetup, a root
	// (TestSetupDispatchesToRunSetup in cmd/macserve).
	Dispatch: map[string]string{mainPkg + ".onboardingCommands": mainPkg + ".onboardingCommand"},
	PureStd: []string{
		"bytes", "cmp", "context", "errors", "fmt", "io", "io/fs", "iter", "maps", "math", "net/netip",
		"regexp", "slices", "sort", "strconv", "strings", "time", "unicode", "unicode/utf8",
	},
	Uses: map[string]Use{
		// The one command runner: one process built, one run.
		"os/exec.CommandContext": {Caller: planFunc + "command", Max: 1},
		"(*os/exec.Cmd).Run":     {Caller: planFunc + "runReadOnly", Max: 1},
		// Identity of the invoking process.
		"os.Getuid":  {Caller: ""},
		"os.Geteuid": {Caller: planFunc + "SystemProbe", Max: 1},
		"os.Getgid":  {Caller: planFunc + "SystemProbe", Max: 1},
		"os.Getegid": {Caller: planFunc + "SystemProbe", Max: 1},
		"os.Environ": {Caller: planFunc + "SystemProbe", Max: 1},
		// Reads: lstat, interfaces, accounts.
		"os.Lstat":                  {Caller: planFunc + "lstat", Max: 1},
		"net.InterfaceAddrs":        {Caller: planFunc + "interfaceAddrs", Max: 1},
		"os/user.LookupId":          {Caller: planFunc + "invokingAccount", Max: 1},
		"(*os/user.User).GroupIds":  {Caller: planFunc + "invokingAccount", Max: 1},
		"os/user.LookupGroup":       {Caller: planFunc + "adminGID", Max: 1},
		"(*net.Dialer).DialContext": {Caller: planFunc + "portInUse", Max: 1},
		"(net.Conn).Close":          {Caller: planFunc + "portInUse", Max: 1},
		"path/filepath.IsAbs":       {},
		"path/filepath.Clean":       {},
		"path/filepath.Base":        {},
		"reflect.DeepEqual":         {Caller: planFunc + "exactEnvironment", Max: 1},
		"flag.NewFlagSet":           {Caller: mainPkg + ".runSetupWith", Max: 1},
		"flag.ErrHelp":              {Caller: mainPkg + ".runSetupWith", Max: 1},
		"(*flag.FlagSet).SetOutput": {Caller: mainPkg + ".runSetupWith", Max: 1},
		"(*flag.FlagSet).BoolVar":   {Caller: mainPkg + ".runSetupWith"},
		"(*flag.FlagSet).StringVar": {Caller: mainPkg + ".runSetupWith"},
		"(*flag.FlagSet).Parse":     {Caller: mainPkg + ".runSetupWith", Max: 1},
		"(*flag.FlagSet).NArg":      {Caller: mainPkg + ".runSetupWith", Max: 1},
	},
}
