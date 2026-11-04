package readonly

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type edit struct{ file, old, new string }

type mutant struct {
	name  string
	edits []edit
}

const (
	system     = "internal/setup/plan/system.go"
	runner     = "internal/setup/plan/runner.go"
	env        = "internal/setup/plan/env.go"
	pre        = "internal/setup/plan/preflight.go"
	newFile    = "internal/setup/plan/zz_new.go"
	command    = "cmd/macserve/onboarding.go"
	lstatFn    = "func lstat(path string) (FileInfo, error) {"
	adminFn    = "func adminGID() (uint32, error) {"
	probeDoc   = "// SystemProbe reads the running host."
	runCall    = "	if err := cmd.Run(); err != nil {"
	cmdDir     = "	cmd.Dir = \"/\""
	parse      = "	parsed, err := deploy.ParseEnvironment(data)"
	embedGo    = "assets/embed.go"
	embedLine  = "//go:embed create-users.sh"
	planCall   = "	result := plan.Preflight(context.Background(), probe, choices)"
	writeOut   = "	_, err := w.Write(b.Bytes())"
	osImport   = "\t\"os\"\n"
	ioImport   = "\t\"io\"\n"
	fsImport   = "\t\"io/fs\"\n"
	ledger     = "internal/setup/ledger.go"
	deployEnv  = "internal/deploy/environment.go"
	maint      = "internal/maintenance/maintenance.go"
	mainGo     = "cmd/macserve/main.go"
	dialCall   = "\tconn, err := d.DialContext(ctx, \"tcp\", ap.String())"
	connClose  = "\tif err == nil {\n\t\tconn.Close()"
	elevated   = "\tif probe.Elevated() {"
	setupFn    = "func runSetup("
	stepDoc    = "// Step is one ordered setup step."
	parseFn    = "func ParseEnvironment("
	sw0        = "\tswitch args[0] {"
	lnCommands = "//go:linkname planCommands github.com/jerryfane/macserve/internal/setup/plan.readOnlyCommands\nvar planCommands [][]string\n\n"
	unknownCmd = "\t\tfmt.Fprintf(stderr, \"macserve: unknown command %q\\n\", args[0])\n"
	setupEntry = "\t{\"setup\", \"First-time setup of this Mac (--plan: read-only preflight)\", setupHelp, runSetup},"
	tableType  = "\trun                 func(args []string, stdout, stderr io.Writer) int\n}{"
)

// imp adds an import to system.go.
func imp(spec string) edit { return edit{system, osImport, osImport + "\t" + spec + "\n"} }

// at inserts code after the line anchor in file.
func at(file, anchor, code string) edit { return edit{file, anchor, anchor + "\n" + code} }

// tableHook adds a func field to the command table, sets it for "setup"
// to hook (other entries nil) and calls it in onboardingCommand.
func tableHook(hook, decl string) []edit {
	edits := []edit{cmdOS, {command, tableType, "\trun                 func(args []string, stdout, stderr io.Writer) int\n\tpre                 func()\n}{"}}
	edits = append(edits, edit{command, setupEntry, strings.Replace(setupEntry, "runSetup}", "runSetup, "+hook+"}", 1)})
	for _, name := range []string{"connectGitHubHelp, runConnectGitHub}", "doctorHelp, nil}", "buildHelp, nil}", "upgradeHelp, nil}", "setupRootHelp, runSetupRoot}", "fdaCheckHelp, runFDACheck}"} {
		edits = append(edits, edit{command, name, strings.TrimSuffix(name, "}") + ", nil}"})
	}
	edits = append(edits, edit{command, "\t\thelp, run := c.help, c.run", "\t\thelp, run := c.help, c.run\n\t\tif c.pre != nil {\n\t\t\tc.pre()\n\t\t}"})
	if decl != "" {
		edits = append(edits, edit{command, setupFn, decl + setupFn})
	}
	return edits
}

// cmdOS adds the os import to onboarding.go.
var cmdOS = edit{command, ioImport, ioImport + osImport}

// mutants change setup --plan code in ways that could write, run or reach
// something. Each compiles, and each must be refused by the checker.
var mutants = []mutant{
	{"aliased os write", []edit{imp(`xos "os"`), at(system, lstatFn, "\t_ = xos.WriteFile(path, nil, 0o600)")}},
	{"dot-imported write", []edit{{newFile, "", "package plan\n\nimport . \"io/ioutil\"\n\nfunc helper() { _ = WriteFile(\"/tmp/x\", nil, 0o600) }\n"}}},
	{"ioutil write", []edit{imp(`"io/ioutil"`), at(system, lstatFn, "\t_ = ioutil.WriteFile(path, nil, 0o600)")}},
	{"os.File write", []edit{at(system, lstatFn, "\tif f, err := os.Create(path); err == nil {\n\t\tf.Write(nil)\n\t}")}},
	{"os.Stdout write", []edit{{pre, writeOut, "\t_, err := os.Stdout.Write(b.Bytes())"}, {pre, fsImport, fsImport + osImport}}},
	{"method value", []edit{at(system, lstatFn, "\tremove := os.Remove\n\t_ = remove(path)")}},
	{"package var initializer", []edit{{system, probeDoc, "var _ = os.Mkdir(\"/tmp/x\", 0o700)\n\n" + probeDoc}}},
	{"init func", []edit{{system, probeDoc, "func init() { os.Setenv(\"X\", \"1\") }\n\n" + probeDoc}}},
	{"second exec in runReadOnly", []edit{{runner, runCall, "\texec.CommandContext(ctx, \"/usr/bin/touch\", \"/tmp/x\").Run()\n" + runCall}}},
	{"second exec in command", []edit{at(runner, cmdDir, "\t_ = exec.CommandContext(ctx, \"/usr/bin/touch\", \"/tmp/x\")")}},
	{"second run", []edit{{runner, runCall, "\t_ = cmd.Run()\n" + runCall}}},
	{"cmd.Start", []edit{{runner, runCall, "\tif err := cmd.Start(); err != nil {"}}},
	{"cmd.Output", []edit{{runner, runCall, "\tif _, err := cmd.Output(); err != nil {"}}},
	{"run outside runReadOnly", []edit{at(system, adminFn, "\tcmd, _, _ := command(context.Background(), []string{\"/usr/bin/csrutil\", \"status\"})\n\t_ = cmd.Run()")}},
	{"exec.LookPath", []edit{at(runner, cmdDir, "\tcmd.Path, _ = exec.LookPath(filepath.Base(argv[0]))")}},
	{"exec.Command", []edit{{runner, "exec.CommandContext(ctx, argv[0], argv[1:]...)", "exec.Command(argv[0], argv[1:]...)"}}},
	{"cross-package read helper", []edit{{env, parse, "\t_, _ = deploy.LoadEnvironment(\"/tmp/x\")\n" + parse}}},
	{"deploy.Install", []edit{{env, parse, "\t_ = deploy.Install(deploy.Options{}, nil, nil)\n" + parse}}},
	{"ledger call", []edit{{pre, writeOut, "\t_, _ = setup.NewLedger(\"jdoe\", 501, time.Time{}).Encode()\n" + writeOut}, {pre, fsImport, fsImport + "\t\"time\"\n"}}},
	{"new file in package", []edit{{newFile, "", "package plan\n\nimport \"os\"\n\nfunc helper() { _ = os.WriteFile(\"/tmp/x\", nil, 0o600) }\n"}}},
	{"new file init", []edit{{newFile, "", "package plan\n\nimport \"os\"\n\nfunc init() { _ = os.Chmod(\"/Users\", 0o777) }\n"}}},
	{"new file method", []edit{{newFile, "", "package plan\n\nimport \"os\"\n\nfunc (Plan) String() string { os.Exit(3); return \"\" }\n"}}},
	{"dial anywhere", []edit{at(system, adminFn, "\t_, _ = net.Dial(\"tcp\", \"example.com:80\")")}},
	{"second dial", []edit{{system, "\tconn, err := d.DialContext(ctx, \"tcp\", ap.String())", "\t_, _ = d.DialContext(ctx, \"tcp\", \"1.2.3.4:80\")\n\tconn, err := d.DialContext(ctx, \"tcp\", ap.String())"}}},
	{"dial outside portInUse", []edit{at(system, adminFn, "\t_, _ = (&net.Dialer{}).DialContext(context.Background(), \"tcp\", \"1.2.3.4:80\")")}},
	{"http", []edit{imp(`"net/http"`), at(system, adminFn, "\t_, _ = http.Get(\"http://example.com\")")}},
	{"unsafe", []edit{imp(`_ "unsafe"`)}},
	{"linkname", []edit{imp(`_ "unsafe"`), {system, probeDoc, "//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n\n" + probeDoc}}},
	{"signal", []edit{imp(`"os/signal"`), at(system, adminFn, "\tsignal.Ignore()")}},
	{"setenv", []edit{at(system, adminFn, "\tos.Setenv(\"PATH\", \"/tmp\")")}},
	{"identity read outside SystemProbe", []edit{at(system, adminFn, "\t_ = os.Environ()")}},
	{"reflect call", []edit{{env, "\tif !reflect.DeepEqual(parsed, want) {", "\treflect.ValueOf(func() {}).Call(nil)\n\tif !reflect.DeepEqual(parsed, want) {"}}},
	{"apply reached outside its clause", []edit{{command, "\treturn runSetupWith(plan.SystemProbe(), args, stdout, stderr)\n}", "\t_ = runSetupApply(args, stdout, stderr)\n\treturn runSetupWith(plan.SystemProbe(), args, stdout, stderr)\n}"}}},
	{"apply clause as the default", []edit{{command, "\tcase plan.ModeApply:\n", "\tdefault:\n"}}},
	{"Mode always plan with apply in its clause", []edit{{command, "\tcase plan.ModeApply:\n", "\tcase \"plan\":\n"}}},
	{"Mode widened to apply", []edit{{"internal/setup/plan/mode.go", "\t\t\treturn \"plan\"\n", "\t\t\treturn ModeApply\n"}}},
	{"runSetup passes apply", []edit{{command, "setupDispatch([]string{plan.Mode(args)}", "setupDispatch([]string{plan.ModeApply}"}}},
	{"setupDispatch called from the plan", []edit{{command, planCall, "	if len(args) > 5 {\n\t\treturn setupDispatch([]string{plan.ModeApply}, args, stdout, stderr)\n\t}\n" + planCall}}},
	{"words rewritten before the setup dispatch", []edit{{command, "\tswitch words[0] {", "\twords[0] = plan.ModeApply\n\tswitch words[0] {"}}},
	{"os write in runSetup", []edit{{command, planCall, "\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n" + planCall}, cmdOS}},
	{"os write in dispatch", []edit{{command, "\t\thelp, run := c.help, c.run", "\t\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\t\thelp, run := c.help, c.run"}, cmdOS}},
	{"cmd helper from runSetup", []edit{{command, planCall, "\trunDeployInstall(nil, stdout, stderr)\n" + planCall}}},
	{"func var in cmd", []edit{{command, "\treturn runSetupWith(plan.SystemProbe(), args, stdout, stderr)", "\treturn runSetupWith(probeFunc(), args, stdout, stderr)\n}\n\nvar probeFunc = func() plan.Probe {\n\t_ = os.Remove(\"/tmp/x\")\n\treturn plan.SystemProbe()"}, cmdOS}},
	{"probe field replaced in runSetup", []edit{{command, "\tif probe.Elevated() {", "\tprobe.Run = func(context.Context, []string) (string, error) { return \"\", os.Remove(\"/tmp/x\") }\n\tif probe.Elevated() {"}, cmdOS}},

	// Deimos's survivors at 488f000 (PR #68 re-review).
	{"A08 dial another address", []edit{{system, dialCall, "\tconn, err := d.DialContext(ctx, \"tcp\", \"203.0.113.1:80\")"}}},
	{"C04 dial port+1", []edit{{system, dialCall, "\tconn, err := d.DialContext(ctx, \"tcp\", netip.AddrPortFrom(ap.Addr(), ap.Port()+1).String())"}}},
	{"A10 PATH lookup", []edit{{runner, "exec.CommandContext(ctx, argv[0], argv[1:]...)", "exec.CommandContext(ctx, filepath.Base(argv[0]), argv[1:]...)"}}},
	{"B01 fmt.Fprint to the dialled conn", []edit{{system, connClose, "\tif err == nil {\n\t\tfmt.Fprint(conn, \"GET / HTTP/1.0\\r\\n\\r\\n\")\n\t\tconn.Close()"}}},
	{"B02 io.WriteString to the dialled conn", []edit{{system, fsImport, "\t\"io\"\n" + fsImport}, {system, connClose, "\tif err == nil {\n\t\t_, _ = io.WriteString(conn, fmt.Sprint(ap))\n\t\tconn.Close()"}}},
	{"C03 io.Copy to the dialled conn", []edit{{system, fsImport, "\t\"io\"\n" + fsImport + "\t\"strings\"\n"}, {system, connClose, "\tif err == nil {\n\t\t_, _ = io.Copy(conn, strings.NewReader(\"POST /v1/shutdown HTTP/1.0\\r\\n\\r\\n\"))\n\t\tconn.Close()"}}},
	{"conn boxed as io.Writer", []edit{{system, connClose, "\tif err == nil {\n\t\tvar w interface{ Write([]byte) (int, error) } = conn\n\t\t_, _ = w.Write(nil)\n\t\tconn.Close()"}}},
	{"conn asserted to io.Writer", []edit{{system, fsImport, "\t\"io\"\n" + fsImport}, {system, connClose, "\tif err == nil {\n\t\t_, _ = conn.(io.Writer).Write(nil)\n\t\tconn.Close()"}}},
	{"conn.Write", []edit{{system, connClose, "\tif err == nil {\n\t\t_, _ = conn.Write(nil)\n\t\tconn.Close()"}}},
	{"B04 stdout closed via io.Closer", []edit{{command, elevated, "\tif c, ok := stdout.(io.Closer); ok {\n\t\t_ = c.Close()\n\t}\n" + elevated}}},
	{"B27 stderr closed via io.Closer", []edit{{command, elevated, "\tif c, ok := stderr.(io.Closer); ok {\n\t\t_ = c.Close()\n\t}\n" + elevated}}},
	{"B28 stdout WriteAt", []edit{{command, elevated, "\tif w, ok := stdout.(io.WriterAt); ok {\n\t\t_, _ = w.WriteAt([]byte(\"x\"), 0)\n\t}\n" + elevated}}},
	{"stdout type switch", []edit{{command, elevated, "\tswitch w := stdout.(type) {\n\tcase io.Closer:\n\t\t_ = w.Close()\n\t}\n" + elevated}}},
	{"B08 init in onboarding.go", []edit{cmdOS, {command, setupFn, "func init() {\n\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n}\n\n" + setupFn}}},
	{"B08' aliased init in onboarding.go", []edit{{command, ioImport, ioImport + "\txos \"os\"\n"}, {command, setupFn, "func init() {\n\t_ = xos.WriteFile(\"/tmp/x\", nil, 0o600)\n}\n\n" + setupFn}}},
	{"B09 var initializer in onboarding.go", []edit{cmdOS, {command, setupFn, "var _ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\n" + setupFn}}},
	{"var initializer calling a literal", []edit{cmdOS, {command, setupFn, "var _ = func() error { return os.Remove(\"/tmp/x\") }()\n\n" + setupFn}}},
	{"B10 init in internal/setup", []edit{{ledger, ioImport, ioImport + osImport}, {ledger, stepDoc, "func init() {\n\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n}\n\n" + stepDoc}}},
	{"B11 init in internal/deploy", []edit{{deployEnv, parseFn, "func init() {\n\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n}\n\n" + parseFn}}},
	{"B25 var initializer in internal/deploy", []edit{{deployEnv, parseFn, "var _ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\n" + parseFn}}},
	{"B24 init in internal/maintenance", []edit{{maint, "type Config struct {", "func init() {\n\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n}\n\ntype Config struct {"}}},
	{"init in an unrelated package", []edit{{"internal/store/zz_init.go", "", "package store\n\nimport \"os\"\n\nfunc init() { _ = os.Remove(\"/tmp/x\") }\n"}}},
	{"B19 build-constrained file", []edit{{"internal/setup/plan/zz_cgo.go", "", "//go:build darwin && cgo\n\npackage plan\n\nimport \"os\"\n\nfunc init() { _ = os.WriteFile(\"/tmp/x\", nil, 0o600) }\n"}}},
	{"B21 write in main.run before dispatch", []edit{{mainGo, "\tswitch args[0] {", "\tif args[0] == \"setup\" {\n\t\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\t}\n\tswitch args[0] {"}}},
	{"setup case added to the dispatch", []edit{{mainGo, "\tcase \"wait\":", "\tcase \"setup\":\n\t\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\t\treturn 0\n\tcase \"wait\":"}}},
	{"write in main", []edit{{mainGo, "\tos.Exit(run(", "\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\tos.Exit(run("}}},
	{"C01 cmd.Path/Args rewritten", []edit{at(runner, cmdDir, "\tif strings.Contains(argv[0], \"Xcode-beta\") {\n\t\tcmd.Path, cmd.Args = \"/usr/bin/touch\", []string{\"touch\", \"/tmp/x\"}\n\t}")}},
	{"cmd.Args element rewritten", []edit{at(runner, cmdDir, "\tcmd.Args[0] = \"/usr/bin/touch\"")}},
	{"C06 cmd.Stdin set", []edit{at(runner, cmdDir, "\tif strings.Contains(argv[0], \"Xcode-beta\") {\n\t\tcmd.Stdin = strings.NewReader(\"y\\n\")\n\t}")}},
	{"cmd field address taken", []edit{at(runner, cmdDir, "\tp := &cmd.Path\n\t*p = \"/usr/bin/touch\"")}},
	{"C02 AllowedCommand widened", []edit{{runner, "\treturn false\n}\n\n// validDeveloperDir", "\treturn len(argv) == 3 && argv[0] == \"/usr/bin/defaults\"\n}\n\n// validDeveloperDir"}, {pre, "\t\tdetail := \"FileVault state unknown\"\n", "\t\tdetail := \"FileVault state unknown\"\n\t\t_, _ = run(\"/usr/bin/defaults\", \"delete\", \"com.apple.dock\")\n"}}},
	{"allowlist appended at runtime", []edit{{pre, "\tvar plan Plan\n", "\tvar plan Plan\n\treadOnlyCommands = append(readOnlyCommands, []string{\"/usr/bin/touch\", \"/tmp/x\"})\n"}}},
	{"allowlist literal widened", []edit{{runner, "\t{\"/usr/bin/csrutil\", \"status\"},\n", "\t{\"/usr/bin/csrutil\", \"status\"},\n\t{\"/usr/bin/defaults\", \"delete\", \"com.apple.dock\"},\n"}}},

	// Deimos's survivors at b84a802 (PR #68 round 3).
	{"N01 constant switch on len(args)", []edit{{mainGo, sw0, "\tswitch len(args) {\n\tcase 2:\n\t\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\t}\n" + sw0}}},
	{"N01b switch on len(args[0])", []edit{{mainGo, sw0, "\tswitch len(args[0]) {\n\tcase len(\"setup\"):\n\t\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\t}\n" + sw0}}},
	{"N01d switch on args[0][:3]", []edit{{mainGo, sw0, "\tswitch args[0][:3] {\n\tcase \"set\":\n\t\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\t}\n" + sw0}}},
	{"N02 table hook field (func literal)", tableHook("func() { _ = os.WriteFile(\"/tmp/x\", nil, 0o600) }", "")},
	{"N03 table hook field (named func)", tableHook("setupHook", "func setupHook() { _ = os.WriteFile(\"/tmp/x\", nil, 0o600) }\n\n")},
	// Variants: changing which clause runs, and the table itself.
	{"args reversed before dispatch", []edit{{mainGo, sw0, "\tslices.Reverse(args)\n" + sw0}, {mainGo, "\t\"os\"\n", "\t\"os\"\n\t\"slices\"\n"}}},
	{"args[0] rewritten before dispatch", []edit{{mainGo, sw0, "\targs[0] = \"deploy-install\"\n" + sw0}}},
	{"args reassigned before dispatch", []edit{{mainGo, sw0, "\targs = []string{\"deploy-install\"}\n" + sw0}}},
	{"non-constant dispatch case", []edit{{mainGo, "\tcase \"wait\":", "\tcase strings.ToLower(\"SETUP\"):\n\t\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\t\treturn 0\n\tcase \"wait\":"}, {mainGo, "\t\"os\"\n", "\t\"os\"\n\t\"strings\"\n"}}},
	{"dispatch switch removed", []edit{{mainGo, sw0, "\tswitch x := args[0]; x {"}}},
	{"setup entry runs another function", []edit{{command, setupEntry, strings.Replace(setupEntry, "runSetup}", "runEvil}", 1) + "\n"}, {command, setupFn, "func runEvil(args []string, stdout, stderr io.Writer) int {\n\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\treturn 0\n}\n\n" + setupFn}, cmdOS}},
	{"second setup entry", []edit{{command, setupEntry, setupEntry + "\n" + setupEntry}}},
	{"table written in init", []edit{{command, setupFn, "func init() {\n\tonboardingCommands[0].help = \"x\"\n}\n\n" + setupFn}}},
	{"table written in dispatch", []edit{{command, "\t\thelp, run := c.help, c.run", "\t\tonboardingCommands[0].run = nil\n\t\thelp, run := c.help, c.run"}}},

	// Deimos's survivors at d8fe620 (PR #68 round 4): re-entering the dispatch.
	{"R01 re-enter run with another word", []edit{{mainGo, unknownCmd, "\t\tif len(args) > 1 {\n\t\t\treturn run([]string{\"worker-reset\"}, stdout, stderr)\n\t\t}\n" + unknownCmd}}},
	{"R02 re-enter run into a new case", []edit{{mainGo, unknownCmd, "\t\tif len(args) > 1 {\n\t\t\treturn run([]string{\"zz\"}, stdout, stderr)\n\t\t}\n" + unknownCmd}, {mainGo, "\tcase \"wait\":", "\tcase \"zz\":\n\t\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\t\treturn 0\n\tcase \"wait\":"}}},
	{"R03 goto back with args rewritten", []edit{{mainGo, sw0, "again:\n" + sw0}, {mainGo, unknownCmd, "\t\tif len(args) > 1 {\n\t\t\targs[0] = \"worker-reset\"\n\t\t\tgoto again\n\t\t}\n" + unknownCmd}}},
	{"R04 goto back without a write", []edit{{mainGo, sw0, "\tn := 0\nagain:\n" + sw0}, {mainGo, unknownCmd, "\t\tif n == 0 && len(args) > 1 {\n\t\t\tn++\n\t\t\tgoto again\n\t\t}\n" + unknownCmd}}},
	{"R05 args element written", []edit{{mainGo, unknownCmd, "\t\targs[0] = \"worker-reset\"\n" + unknownCmd}}},
	{"R06 args aliased and written", []edit{{mainGo, unknownCmd, "\t\ta := args\n\t\ta[0] = \"worker-reset\"\n" + unknownCmd}}},
	{"R07 args passed whole", []edit{{mainGo, unknownCmd, "\t\tslices.Reverse(args)\n" + unknownCmd}, {mainGo, "\t\"os\"\n", "\t\"os\"\n\t\"slices\"\n"}}},
	{"R08 args written in a range", []edit{{mainGo, unknownCmd, "\t\tfor i := range args {\n\t\t\targs[i] = \"x\"\n\t\t}\n" + unknownCmd}}},
	{"R09 run as a method value", []edit{{mainGo, unknownCmd, "\t\tif f := run; len(args) > 1 {\n\t\t\treturn f([]string{\"worker-reset\"}, stdout, stderr)\n\t\t}\n" + unknownCmd}}},
	{"R10 run through a variable set in init", []edit{{mainGo, "func run(", "var reenter func([]string, io.Writer, io.Writer) int\n\nfunc init() { reenter = run }\n\nfunc run("}, {mainGo, unknownCmd, "\t\tif len(args) > 1 {\n\t\t\treturn reenter([]string{\"worker-reset\"}, stdout, stderr)\n\t\t}\n" + unknownCmd}}},
	{"R11 run re-entered from the setup command", []edit{{mainGo, "func run(", "var reenter func([]string, io.Writer, io.Writer) int\n\nfunc init() { reenter = run }\n\nfunc run("}, {command, planCall, "\tif len(args) > 3 {\n\t\treturn reenter([]string{\"worker-reset\"}, stdout, stderr)\n\t}\n" + planCall}}},
	{"R12 labelled break in walked code", []edit{{command, planCall, "out:\n\tfor {\n\t\tbreak out\n\t}\n" + planCall}}},
	{"R13 main rewrites the command word", []edit{{mainGo, "\tos.Exit(run(os.Args[1:], os.Stdout, os.Stderr))", "\ta := os.Args[1:]\n\tif len(a) > 0 && a[0] == \"setup\" {\n\t\ta[0] = \"worker-reset\"\n\t}\n\tos.Exit(run(a, os.Stdout, os.Stderr))"}}},

	// Deimos's survivor at cdc8ff2 (PR #68 round 5): linkname from outside
	// the plan package.
	{"L01 cmd linknames the allowlist and runs touch", []edit{{command, ioImport, ioImport + "\t_ \"unsafe\"\n"}, {command, setupFn, lnCommands + setupFn}, {command, elevated, "\tif len(args) > 4 {\n\t\tplanCommands = append(planCommands, []string{\"/usr/bin/touch\", \"/tmp/x\"})\n\t\t_, _ = probe.Run(context.Background(), []string{\"/usr/bin/touch\", \"/tmp/x\"})\n\t}\n" + elevated}}},
	{"L01b cmd linknames the allowlist only", []edit{{command, ioImport, ioImport + "\t_ \"unsafe\"\n"}, {command, setupFn, lnCommands + setupFn}, {command, elevated, "\tif len(args) > 4 {\n\t\tplanCommands = append(planCommands, []string{\"/usr/bin/touch\", \"/tmp/x\"})\n\t}\n" + elevated}}},
	{"L02 cmd linknames commandEnv", []edit{{command, ioImport, ioImport + "\t_ \"unsafe\"\n"}, {command, setupFn, "//go:linkname planEnv github.com/jerryfane/macserve/internal/setup/plan.commandEnv\nvar planEnv []string\n\n" + setupFn}, {command, elevated, "\tif len(args) > 4 {\n\t\tplanEnv = append(planEnv, \"DYLD_INSERT_LIBRARIES=/tmp/x.dylib\")\n\t}\n" + elevated}}},
	{"L03 internal/setup linknames the allowlist", []edit{{ledger, ioImport, ioImport + "\t_ \"unsafe\"\n"}, {ledger, stepDoc, strings.Replace(lnCommands, "planCommands", "planCommands2", 2) + stepDoc}}},
	{"L04 the deploy seam widens a linknamed allowlist", []edit{{deployEnv, "\t\"strings\"\n", "\t\"strings\"\n\t_ \"unsafe\"\n"}, {deployEnv, parseFn, lnCommands + parseFn}, {deployEnv, "\tvar e Environment\n", "\tvar e Environment\n\tplanCommands = append(planCommands, []string{\"/usr/bin/touch\", \"/tmp/x\"})\n"}}},
	{"L04b unsafe.Add rewrites args[0] from runSetup", []edit{{command, ioImport, ioImport + "\t\"unsafe\"\n"}, {command, "\treturn runSetupWith(plan.SystemProbe(), args, stdout, stderr)", "\tif len(args) > 0 {\n\t\tp := (*string)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(args)), -int(unsafe.Sizeof(\"\"))))\n\t\t*p = \"zq\"\n\t}\n\treturn runSetupWith(plan.SystemProbe(), args, stdout, stderr)"}}},
	{"L05 linkname in a new file of an unrelated package", []edit{{"internal/store/zz_link.go", "", "package store\n\nimport _ \"unsafe\"\n\n" + lnCommands}}},
	{"L06 unsafe in an unlisted file", []edit{{"internal/store/zz_unsafe.go", "", "package store\n\nimport \"unsafe\"\n\nvar _ = unsafe.Sizeof(0)\n"}}},
	{"L07 other directive in cmd", []edit{{command, setupFn, "//go:noinline\n" + setupFn}}},
	{"L08 cgo_import_dynamic in a linked package", []edit{{"internal/store/zz_dyn.go", "", "package store\n\n//go:cgo_import_dynamic libc_unlink unlink \"/usr/lib/libSystem.B.dylib\"\n"}}},
	{"L09 export directive", []edit{{command, setupFn, "//export runSetupExported\n" + setupFn}}},
	{"L10 assembly file in the plan package", []edit{{"internal/setup/plan/zz_amd.s", "", "#include \"textflag.h\"\n"}}},
	{"L11 listed unsafe file's package imports plan", []edit{{"internal/qualification/host_darwin.go", "\t\"unsafe\"\n", "\t\"unsafe\"\n\n\t_ \"github.com/jerryfane/macserve/internal/setup/plan\"\n"}}},

	// Deimos's round 6 at 25eaf12.
	{"P2-2 //line spoofs a listed unsafe file", []edit{{"cmd/macserve/zz_spoof.go", "", "//line /root/macserve-o1/internal/worker/login_darwin.go:1\npackage main\n\nimport \"unsafe\"\n\nvar _ = unsafe.Sizeof(0)\n"}}},
	{"//line spoofs a relative listed path", []edit{{"cmd/macserve/zz_spoof.go", "", "//line internal/worker/login_darwin.go:1\npackage main\n\nimport \"unsafe\"\n\nvar _ = unsafe.Sizeof(0)\n"}}},
	{"block /*line*/ directive", []edit{{command, setupFn, "/*line onboarding.go:1*/\n" + setupFn}}},
	{"argv clone removed", []edit{{runner, "\targv = slices.Clone(argv)\n", ""}}},
	{"goroutine in walked code", []edit{{command, elevated, "\tgo func() {}()\n" + elevated}}},

	{"E01 go:embed outside the listed files", []edit{{"assets/zz_embed.go", "", "package assets\n\nimport _ \"embed\"\n\n//go:embed qualify.sh\nvar extra []byte\n"}}},
	{"E02 listed embed file also linknames", []edit{{embedGo, embedLine, "//go:linkname extra runtime.x\n" + embedLine}}},
	{"E03 embed pattern leaves the package", []edit{{embedGo, embedLine, "//go:embed ../go.mod\n" + embedLine}}},
	{"E04 embed glob", []edit{{embedGo, embedLine, "//go:embed launchd/*\n" + embedLine}}},
	{"E06 go:embed in another package", []edit{{"internal/setup/zz_embed.go", "", "package setup\n\nimport _ \"embed\"\n\n//go:embed ledger.go\nvar extra []byte\n"}}},
	{"E05 listed embed file's package imports plan", []edit{{embedGo, "import \"embed\"\n", "import (\n\t\"embed\"\n\n\t_ \"github.com/jerryfane/macserve/internal/setup/plan\"\n)\n"}}},
}

// pinOnly are mutants of pinned code that only the pins catch: the
// general rules cannot know which argv a widened allowlist admits.
var pinOnly = map[string]bool{"C02 AllowedCommand widened": true, "allowlist literal widened": true, "R13 main rewrites the command word": true, "argv clone removed": true, "Mode widened to apply": true, "runSetup passes apply": true}

func TestMutantsRefused(t *testing.T) {
	b := testBuild(t)
	root := repoRoot(t)
	unpinned := SetupPlan
	unpinned.Pinned = nil
	refused := 0
	for _, m := range mutants {
		overlay := map[string][]byte{}
		for _, e := range m.edits {
			path := filepath.Join(root, e.file)
			data, ok := overlay[path]
			if !ok && e.old != "" {
				var err error
				if data, err = os.ReadFile(path); err != nil {
					t.Fatal(err)
				}
			}
			switch {
			case e.old == "":
				data = []byte(e.new)
			case !strings.Contains(string(data), e.old):
				t.Fatalf("%s: %q not found in %s", m.name, e.old, e.file)
			default:
				data = []byte(strings.Replace(string(data), e.old, e.new, 1))
			}
			overlay[path] = data
		}
		report, err := b.Check(SetupPlan, overlay)
		if err != nil {
			// The mutant must compile to count as refused by the policy.
			t.Errorf("mutant %q does not type-check: %v", m.name, err)
			continue
		}
		if len(report.Problems) == 0 {
			t.Errorf("mutant %q survived", m.name)
			continue
		}
		refused++
		general, err := b.Check(unpinned, overlay)
		if err != nil {
			t.Fatal(err)
		}
		if len(general.Problems) == 0 && !pinOnly[m.name] {
			t.Errorf("mutant %q is refused only by a pin: %s", m.name, report.Problems[0])
		}
		t.Logf("mutant %q refused: %s", m.name, report.Problems[0])
	}
	t.Logf("%d of %d mutants refused", refused, len(mutants))

	// Test files are not linked into the binary, so a linkname there is not
	// refused.
	test := map[string][]byte{filepath.Join(root, "cmd/macserve/zz_link_test.go"): []byte("package main\n\nimport _ \"unsafe\"\n\n" + lnCommands)}
	if report, err := b.Check(SetupPlan, test); err != nil || len(report.Problems) != 0 {
		t.Errorf("linkname in a test file: %v %v", err, report.Problems)
	}
}
