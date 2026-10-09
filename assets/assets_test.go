package assets_test

import (
	"bytes"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"text/template"
)

func render(t *testing.T, path string) []byte {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New(path).Option("missingkey=error").Parse(string(source))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = tmpl.Execute(&out, map[string]any{
		"ControllerUser": "servicecontrol", "ControllerGroup": "servicecontrol",
		"JobUID": 1502,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

type plistNode struct {
	XMLName  xml.Name
	Text     string      `xml:",chardata"`
	Children []plistNode `xml:",any"`
}

func dictionary(t *testing.T, node plistNode) map[string]plistNode {
	t.Helper()
	if node.XMLName.Local != "dict" || len(node.Children)%2 != 0 {
		t.Fatal("invalid plist dictionary")
	}
	out := map[string]plistNode{}
	for i := 0; i < len(node.Children); i += 2 {
		key := node.Children[i]
		if key.XMLName.Local != "key" {
			t.Fatal("missing plist key")
		}
		if _, duplicate := out[key.Text]; duplicate {
			t.Fatalf("duplicate plist key %q", key.Text)
		}
		out[key.Text] = node.Children[i+1]
	}
	return out
}

func TestLaunchDaemonsRemainDisabledAndSeparated(t *testing.T) {
	for _, role := range []string{"controller", "worker", "maintenance"} {
		t.Run(role, func(t *testing.T) {
			data := render(t, "launchd/org.macserve."+role+".plist.tmpl")
			var root plistNode
			if err := xml.Unmarshal(data, &root); err != nil {
				t.Fatal(err)
			}
			if root.XMLName.Local != "plist" || len(root.Children) != 1 {
				t.Fatal("invalid plist root")
			}
			fields := dictionary(t, root.Children[0])
			if fields["Disabled"].XMLName.Local != "true" || fields["RunAtLoad"].XMLName.Local != "false" {
				t.Fatal("daemon must remain disabled")
			}
			user, group, work := "root", "wheel", "/Library/macserve/var/broker"
			if role == "controller" {
				user, group, work = "servicecontrol", "servicecontrol", "/Library/macserve/var/controller"
			}
			for key, want := range map[string]string{"Label": "org.macserve." + role, "UserName": user, "GroupName": group, "WorkingDirectory": work, "ProcessType": "Background"} {
				if fields[key].XMLName.Local != "string" || fields[key].Text != want {
					t.Fatalf("%s = %+v, want %s", key, fields[key], want)
				}
			}
			args := fields["ProgramArguments"]
			want := []string{"/Library/macserve/bin/macserve", role, "--config", "/Library/macserve/config/" + role + ".json"}
			if args.XMLName.Local != "array" || len(args.Children) != len(want) {
				t.Fatal("invalid daemon arguments")
			}
			for i, arg := range args.Children {
				if arg.XMLName.Local != "string" || arg.Text != want[i] {
					t.Fatalf("argument %d = %+v", i, arg)
				}
			}
			for key, want := range map[string]int{"Umask": 63, "Nice": 10, "ThrottleInterval": 60} {
				n, err := strconv.Atoi(fields[key].Text)
				if err != nil || fields[key].XMLName.Local != "integer" || n != want {
					t.Fatalf("unsafe %s: %+v", key, fields[key])
				}
			}
			env := dictionary(t, fields["EnvironmentVariables"])
			if env["PATH"].Text != "/usr/bin:/bin:/usr/sbin:/sbin" || env["GOMAXPROCS"].Text != "2" {
				t.Fatal("unsafe execution environment")
			}
			for key, suffix := range map[string]string{"StandardOutPath": "out", "StandardErrorPath": "err"} {
				expected := work + "/log/" + role + "." + suffix + ".log"
				if fields[key].Text != expected {
					t.Fatalf("log outside protected role directory: %s", fields[key].Text)
				}
			}
		})
	}
}

func scriptArgs() []string {
	return []string{"--controller-user", "servicecontrol", "--controller-uid", "1501", "--controller-gid", "1601", "--job-user", "servicejob", "--job-uid", "1502", "--job-gid", "1602", "--owner-user", "serviceowner", "--owner-uid", "1503"}
}
func runScript(t *testing.T, args []string) (string, error) {
	t.Helper()
	script, err := filepath.Abs("create-users.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", append([]string{script}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=/nonexistent", "HOME=" + cmd.Dir}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestAccountInputRefusals(t *testing.T) {
	cases := []struct {
		name  string
		index int
		value string
	}{
		{"shared-uid", 9, "1501"}, {"shared-gid", 11, "1601"}, {"owner-uid", 15, "1502"}, {"privileged-gid", 11, "20"},
		{"controller-job-name", 7, "servicecontrol"}, {"controller-owner-name", 13, "servicecontrol"}, {"job-owner-name", 13, "servicejob"},
		{"controller-owner-uid", 15, "1501"},
		{"privileged-name", 7, "admin"}, {"injected-name", 1, "evil/../root"}, {"leading-zero", 9, "01502"}, {"non-numeric", 9, "1502;id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := scriptArgs()
			args[tc.index] = tc.value
			output, err := runScript(t, args)
			if err == nil {
				t.Fatalf("unsafe identity accepted: %s", output)
			}
		})
	}
	for _, args := range [][]string{nil, append(scriptArgs(), "--job-user", "another"), append(scriptArgs(), "--password", "not-a-secret")} {
		output, err := runScript(t, args)
		if err == nil {
			t.Fatalf("invalid flags accepted: %s", output)
		}
	}
}

func TestCreatedAccountAuthentication(t *testing.T) {
	script, err := filepath.Abs("create-users.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"default", nil, "macserve build"},
		{"explicit", []string{"--job-real-name", "Studio Build User"}, "Studio Build User"},
		{"literal", []string{"--job-real-name", "$(not-executed) * 'quoted'"}, "$(not-executed) * 'quoted'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Source the real parser and creation functions, but intercept the
			// absolute directory command before executing any creation function.
			program := `source "$1"; shift
function /usr/bin/dscl() { printf '%s\t' "$@"; printf '\n'; }
main "$@" >/dev/null
create_accounts`
			args := append([]string{"-c", program, "account-test", script}, scriptArgs()...)
			args = append(args, tc.args...)
			cmd := exec.Command("/bin/bash", args...)
			cmd.Dir = t.TempDir()
			cmd.Env = []string{"PATH=/nonexistent", "HOME=" + cmd.Dir}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("account fixture: %v: %s", err, out)
			}
			attributes := map[string]string{}
			for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
				fields := strings.Split(strings.TrimSuffix(line, "\t"), "\t")
				if len(fields) != 3 && len(fields) != 5 {
					t.Fatalf("directory argument boundary lost: %q", fields)
				}
				if fields[0] != "." || fields[1] != "-create" {
					t.Fatalf("unexpected directory operation: %q", fields)
				}
				if len(fields) == 5 {
					key := fields[2] + "/" + fields[3]
					if _, duplicate := attributes[key]; duplicate {
						t.Fatalf("attribute written twice: %s", key)
					}
					attributes[key] = fields[4]
				}
			}
			for key, want := range map[string]string{
				"/Users/servicejob/RealName":                tc.want,
				"/Users/servicejob/AuthenticationAuthority": ";ShadowHash;",
				"/Users/servicejob/UserShell":               "/bin/zsh",
				"/Users/servicecontrol/Password":            "*",
				"/Users/servicecontrol/IsHidden":            "1",
				"/Users/servicecontrol/UserShell":           "/usr/bin/false",
				"/Groups/servicejob/Password":               "*",
				"/Groups/servicecontrol/Password":           "*",
			} {
				if got := attributes[key]; got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			for _, key := range []string{"/Users/servicejob/Password", "/Users/servicejob/IsHidden", "/Users/servicecontrol/AuthenticationAuthority"} {
				if value, present := attributes[key]; present {
					t.Errorf("unexpected attribute %s = %q", key, value)
				}
			}
		})
	}
	for _, args := range [][]string{
		{"--job-real-name", ""},
		{"--job-real-name", "Bad\nName"},
		{"--job-real-name", "First", "--job-real-name", "Second"},
		{"--job-real-name"},
	} {
		if out, err := runScript(t, append(scriptArgs(), args...)); err == nil {
			t.Fatalf("invalid real name options accepted: %q: %s", args, out)
		}
	}
}

func TestApplyRefusesUnsupportedHostOrPrivilege(t *testing.T) {
	if runtime.GOOS == "darwin" && os.Geteuid() == 0 {
		t.Skip("never execute valid apply on a root Darwin host")
	}
	out, err := runScript(t, append(scriptArgs(), "--apply"))
	if err == nil {
		t.Fatalf("apply accepted unsupported host or privilege: %s", out)
	}
}

func TestCreatedAccountSupplementaryGroups(t *testing.T) {
	script, err := filepath.Abs("create-users.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []struct {
		name, primary, other string
	}{
		{"servicecontrol", "1601", "1602"},
		{"servicejob", "1602", "1601"},
	} {
		for _, tc := range []struct {
			name, extra string
			refuse      bool
		}{
			{"dedicated-only", "", false},
			{"unprivileged-extra", "1700", false},
			{"root", "0", true},
			{"staff", "20", true},
			{"admin", "80", true},
			{"other-primary", role.other, true},
		} {
			t.Run(role.name+"/"+tc.name, func(t *testing.T) {
				cmd := exec.Command("/bin/bash", "-c", `source "$1"; validate_account_groups "$2" "$3" "$4"`, "membership-test", script, role.name, role.other, role.primary+" "+tc.extra)
				cmd.Dir = t.TempDir()
				cmd.Env = []string{"PATH=/nonexistent", "HOME=" + cmd.Dir}
				out, err := cmd.CombinedOutput()
				if tc.refuse && err == nil {
					t.Fatalf("unsafe membership was not refused: output=%q", out)
				} else if !tc.refuse && err != nil {
					t.Fatalf("safe membership rejected: err=%v output=%q", err, out)
				}
			})
		}
	}
}

func TestInstallerEarlyRefusals(t *testing.T) {
	script, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "binary")
	if err := os.WriteFile(binary, []byte("must not execute"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"help-followed-by-option", []string{"--help", "--env", "unused"}},
		{"help-after-option", []string{"--env", "unused", "--help"}},
		{"missing-env", []string{"--binary", binary, "--sha256", digest}},
		{"missing-binary", []string{"--env", "unused", "--sha256", digest}},
		{"missing-digest", []string{"--env", "unused", "--binary", binary}},
		{"absent-file", []string{"--env", "unused", "--binary", filepath.Join(dir, "absent"), "--sha256", digest}},
		{"directory", []string{"--env", "unused", "--binary", dir, "--sha256", digest}},
		{"symlink", []string{"--env", "unused", "--binary", link, "--sha256", digest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("/bin/bash", append([]string{script}, tc.args...)...)
			cmd.Dir = dir
			cmd.Env = []string{"PATH=/nonexistent", "HOME=" + dir}
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("invalid installer input was not refused: err=%v output=%q", err, out)
			}
		})
	}
}

func TestQualificationWrapperRejectsRawCommandsBeforeBinary(t *testing.T) {
	script, err := filepath.Abs("qualify.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "macserve-fixture")
	marker := filepath.Join(dir, "executed")
	if err := os.WriteFile(binary, []byte("#!/bin/bash\nprintf executed > \"$MARKER\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"pfctl", "-f", "/policy"},
		{"/sbin/pfctl", "-a", "org.example/peer", "-f", "/policy"},
		{"-a", "org.example/service", "-f", "/policy"},
		{"sh", "-c", "pfctl -F all"},
		{"exec", "/sbin/pfctl", "-d"},
		{"begin;pfctl", "-d"},
		{"unknown"},
	} {
		cmd := exec.Command("/bin/bash", append([]string{script, "--binary", binary}, args...)...)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=/nonexistent", "HOME=" + dir, "MARKER=" + marker}
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "raw commands are refused") {
			t.Fatalf("raw qualification command was not refused: args=%q err=%v output=%q", args, err, out)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("raw command executed supplied binary: %v", err)
		}
	}
}
