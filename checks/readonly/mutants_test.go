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
	system   = "internal/setup/plan/system.go"
	runner   = "internal/setup/plan/runner.go"
	env      = "internal/setup/plan/env.go"
	pre      = "internal/setup/plan/preflight.go"
	newFile  = "internal/setup/plan/zz_new.go"
	command  = "cmd/macserve/onboarding.go"
	lstatFn  = "func lstat(path string) (FileInfo, error) {"
	adminFn  = "func adminGID() (uint32, error) {"
	probeDoc = "// SystemProbe reads the running host."
	runCall  = "	if err := cmd.Run(); err != nil {"
	cmdDir   = "	cmd.Dir = \"/\""
	parse    = "	parsed, err := deploy.ParseEnvironment(check)"
	planCall = "	result := plan.Preflight(context.Background(), probe, choices)"
	writeOut = "	_, err := w.Write(b.Bytes())"
	osImport = "\t\"os\"\n"
	ioImport = "\t\"io\"\n"
	fsImport = "\t\"io/fs\"\n"
)

// imp adds an import to system.go.
func imp(spec string) edit { return edit{system, osImport, osImport + "\t" + spec + "\n"} }

// at inserts code after the line anchor in file.
func at(file, anchor, code string) edit { return edit{file, anchor, anchor + "\n" + code} }

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
	{"os write in runSetup", []edit{{command, planCall, "\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n" + planCall}, cmdOS}},
	{"os write in dispatch", []edit{{command, "\t\thelp, run := c.help, c.run", "\t\t_ = os.WriteFile(\"/tmp/x\", nil, 0o600)\n\t\thelp, run := c.help, c.run"}, cmdOS}},
	{"cmd helper from runSetup", []edit{{command, planCall, "\trunDeployInstall(nil, stdout, stderr)\n" + planCall}}},
	{"func var in cmd", []edit{{command, "\treturn runSetupWith(plan.SystemProbe(), args, stdout, stderr)", "\treturn runSetupWith(probeFunc(), args, stdout, stderr)\n}\n\nvar probeFunc = func() plan.Probe {\n\t_ = os.Remove(\"/tmp/x\")\n\treturn plan.SystemProbe()"}, cmdOS}},
	{"probe field replaced in runSetup", []edit{{command, "\tif probe.Elevated() {", "\tprobe.Run = func(context.Context, []string) (string, error) { return \"\", os.Remove(\"/tmp/x\") }\n\tif probe.Elevated() {"}, cmdOS}},
}

func TestMutantsRefused(t *testing.T) {
	b := testBuild(t)
	root := repoRoot(t)
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
		problems := report.Problems
		switch {
		case err != nil:
			// The mutant must compile to count as refused by the policy.
			t.Errorf("mutant %q does not type-check: %v", m.name, err)
		case len(problems) == 0:
			t.Errorf("mutant %q survived", m.name)
		default:
			t.Logf("mutant %q refused: %s", m.name, problems[0])
		}
	}
}
