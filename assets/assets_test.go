package assets_test

import (
	"bytes"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
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
			if role == "controller" {
				want = []string{"/Library/macserve/bin/macserve-controller", "--config", "/Library/macserve/config/controller.json"}
			}
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

// The fixture models directory records in its temporary working directory.
// Absolute shell functions intercept every host-account command used by the
// creation/postcheck entrypoints; no account or protected filesystem is touched.
const accountDirectoryFixture = `
source "$1"; shift
scenario=$1 expected_real_name=$2; shift 2
put_record() { printf '%s\n' "$3" > "${1//\//_}.$2"; }
get_record() { local value; IFS= read -r value < "${1//\//_}.$2" || return 1; printf '%s\n' "$value"; }
function /usr/bin/dscl() {
    [ "$1" = . ] || return 91
    case "$2" in
        -create)
            # Only sysadminctl may create/write job user authentication.
            [ "$3" != /Users/servicejob ] || return 92
            case "$#" in
                3) put_record "$3" exists yes ;;
                5) put_record "$3" "$4" "$5" ;;
                *) return 93 ;;
            esac ;;
        -read)
            [ "$scenario" != record-read-error ] || return 94
            local value
            value=$(get_record "$3" "$4") || return 95
            printf '%s: %s\n' "$4" "$value" ;;
        -list)
            [ "$3 $4" = '/Users IsHidden' ] || return 96
            [ "$scenario" != hidden-read-error ] || return 97
            printf '%s\n' 'servicecontrol 1' 'servicejob_neighbor 1'
            [ "$scenario" != hidden-missing ] || return 0
            local hidden=''
            if [ -f _Users_servicejob.IsHidden ]; then hidden=$(get_record /Users/servicejob IsHidden); fi
            printf 'servicejob %s\n' "$hidden" ;;
        *) return 98 ;;
    esac
}
function /usr/sbin/sysadminctl() {
    [ "$#" -eq 14 ] || return 81
    [ "$1 $2 $3" = '-addUser servicejob -fullName' ] || return 82
    [ "$4" = "$expected_real_name" ] || return 83
    [ "$5 $6 $7 $8 $9 ${10} ${11} ${12} ${13} ${14}" = '-UID 1502 -GID 1602 -shell /bin/zsh -home /Users/servicejob -password -' ] || return 84
    [ "$(get_record /Groups/servicejob PrimaryGroupID)" = 1602 ] || return 85
    [ "$scenario" != no-create ] || return 0
    put_record /Users/servicejob exists yes
    put_record /Users/servicejob UniqueID "$6"
    put_record /Users/servicejob PrimaryGroupID "$8"
    put_record /Users/servicejob UserShell "${10}"
    put_record /Users/servicejob NFSHomeDirectory "${12}"
    put_record /Users/servicejob RealName "$4"
    put_record /Users/servicejob AuthenticationAuthority ';ShadowHash;'
    case "$scenario" in
        wrong-uid) put_record /Users/servicejob UniqueID 1999 ;;
        wrong-gid) put_record /Users/servicejob PrimaryGroupID 1999 ;;
        wrong-home) put_record /Users/servicejob NFSHomeDirectory /Users/unrelated ;;
        hidden) put_record /Users/servicejob IsHidden 1 ;;
        hidden-zero) put_record /Users/servicejob IsHidden 0 ;;
    esac
    local groups=1602
    case "$scenario" in
        staff|staff-stuck|staff-command-error|staff-read-error) groups='1602 20' ;;
        admin) groups='1602 20 80' ;;
        wheel) groups='1602 0' ;;
        controller-group) groups='1602 1601' ;;
    esac
    put_record /Users/servicejob groups "$groups"
}
function /usr/bin/id() {
    case "$1" in
        -u) get_record "/Users/$2" UniqueID ;;
        -g) get_record "/Users/$2" PrimaryGroupID ;;
        -G)
            if [ "$2" = servicecontrol ]; then
                get_record /Users/servicecontrol PrimaryGroupID
            else
                if [ "$scenario" = staff-read-error ] && [ -f staff-cleanup ]; then return 71; fi
                get_record /Users/servicejob groups
            fi ;;
        *) return 72 ;;
    esac
}
function /usr/sbin/dseditgroup() {
    [ "$#" -eq 7 ] && [ "$*" = '-o edit -d servicejob -t user staff' ] || return 61
    printf attempted > staff-cleanup
    [ "$scenario" != staff-command-error ] || return 62
    [ "$scenario" != staff-stuck ] || return 0
    put_record /Users/servicejob groups 1602
}
main "$@" >/dev/null
create_accounts
# Controller remains nonlogin and password-disabled; its dedicated group remains.
[ "$(get_record /Users/servicecontrol Password)" = '*' ]
[ "$(get_record /Users/servicecontrol IsHidden)" = 1 ]
[ "$(get_record /Users/servicecontrol UserShell)" = /usr/bin/false ]
[ "$(get_record /Groups/servicecontrol PrimaryGroupID)" = 1601 ]
[ "$(get_record /Groups/servicecontrol Password)" = '*' ]
[ "$(get_record /Groups/servicejob Password)" = '*' ]
[ ! -f _Users_servicecontrol.AuthenticationAuthority ]
validate_created_accounts
printf verified > ready-for-provisioning
`

func TestCreatedAccountAuthentication(t *testing.T) {
	script, err := filepath.Abs("create-users.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, scenario, realName string
		refuse, cleanup          bool
	}{
		{"default", "normal", "", false, false},
		{"explicit", "normal", "Studio Build User", false, false},
		{"literal", "normal", "$(not-executed) * 'quoted'", false, false},
		{"staff-removed", "staff", "", false, true},
		{"staff-remains", "staff-stuck", "", true, true},
		{"staff-command-error", "staff-command-error", "", true, true},
		{"staff-reread-error", "staff-read-error", "", true, true},
		{"admin-not-removed", "admin", "", true, false},
		{"wheel", "wheel", "", true, false},
		{"shared-controller-group", "controller-group", "", true, false},
		{"hidden", "hidden", "", true, false},
		{"hidden-zero", "hidden-zero", "", true, false},
		{"visibility-read-error", "hidden-read-error", "", true, false},
		{"visibility-missing-user", "hidden-missing", "", true, false},
		{"record-read-error", "record-read-error", "", true, false},
		{"successful-exit-without-user", "no-create", "", true, false},
		{"incorrect-uid", "wrong-uid", "", true, false},
		{"incorrect-gid", "wrong-gid", "", true, false},
		{"unrelated-home", "wrong-home", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantName := tc.realName
			if wantName == "" {
				wantName = "macserve build"
			}
			args := append([]string{"-c", accountDirectoryFixture, "account-test", script, tc.scenario, wantName}, scriptArgs()...)
			if tc.realName != "" {
				args = append(args, "--job-real-name", tc.realName)
			}
			cmd := exec.Command("/bin/bash", args...)
			cmd.Dir = t.TempDir()
			cmd.Env = []string{"PATH=/nonexistent", "HOME=" + cmd.Dir}
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.refuse {
				t.Fatalf("refuse=%v, err=%v: %s", tc.refuse, err, out)
			}
			_, readyErr := os.Stat(filepath.Join(cmd.Dir, "ready-for-provisioning"))
			if (readyErr == nil) == tc.refuse {
				t.Fatalf("provisioning gate did not match refusal: %v", readyErr)
			}
			_, cleanupErr := os.Stat(filepath.Join(cmd.Dir, "staff-cleanup"))
			if (cleanupErr == nil) != tc.cleanup {
				t.Fatalf("staff cleanup attempted=%v, want %v", cleanupErr == nil, tc.cleanup)
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

func TestApplyRequiresInteractiveInput(t *testing.T) {
	script, err := filepath.Abs("create-users.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Trap the first host query as well as refusing Darwin, so a regression
	// cannot mutate real accounts even when this test is run as root.
	program := `source "$1"; shift
function /usr/bin/uname() { printf queried > host-inspected; printf 'Linux\n'; }
main "$@"`
	args := append([]string{"-c", program, "terminal-test", script}, scriptArgs()...)
	cmd := exec.Command("/bin/bash", append(args, "--apply")...)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=/nonexistent", "HOME=" + cmd.Dir}
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("apply accepted noninteractive input: %s", out)
	}
	if _, err := os.Stat(filepath.Join(cmd.Dir, "host-inspected")); !os.IsNotExist(err) {
		t.Fatalf("noninteractive apply reached host inspection: %v", err)
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
		if err == nil {
			t.Fatalf("raw qualification command was not refused: args=%q err=%v output=%q", args, err, out)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("raw command executed supplied binary: %v", err)
		}
	}
}

func TestSignerLaunchDaemon(t *testing.T) {
	data := render(t, "launchd/org.macserve.signer.plist.tmpl")
	var root plistNode
	if err := xml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	if root.XMLName.Local != "plist" || len(root.Children) != 1 {
		t.Fatal("invalid plist root")
	}
	fields := dictionary(t, root.Children[0])
	if fields["Disabled"].XMLName.Local != "true" || fields["RunAtLoad"].XMLName.Local != "false" {
		t.Fatal("signer must remain disabled")
	}
	keepAlive := dictionary(t, fields["KeepAlive"])
	if len(keepAlive) != 1 || keepAlive["SuccessfulExit"].XMLName.Local != "false" {
		t.Fatal("signer restarts only after a failed exit")
	}
	state := "/Library/macserve/var/signer"
	for key, want := range map[string]string{
		"Label": "org.macserve.signer", "UserName": "_macserve_sign", "GroupName": "_macserve_sign",
		"WorkingDirectory": state, "ProcessType": "Background",
		"StandardOutPath": state + "/log/signer.out.log", "StandardErrorPath": state + "/log/signer.err.log",
	} {
		if fields[key].XMLName.Local != "string" || fields[key].Text != want {
			t.Fatalf("%s = %+v, want %s", key, fields[key], want)
		}
	}
	args := fields["ProgramArguments"]
	want := []string{"/Library/macserve/bin/macserve", "signer", "--config", "/Library/macserve/config/signer.json"}
	if args.XMLName.Local != "array" || len(args.Children) != len(want) {
		t.Fatal("invalid signer arguments")
	}
	for i, arg := range args.Children {
		if arg.XMLName.Local != "string" || arg.Text != want[i] {
			t.Fatalf("argument %d = %+v", i, arg)
		}
	}
	if n, err := strconv.Atoi(fields["Umask"].Text); err != nil || fields["Umask"].XMLName.Local != "integer" || n != 63 {
		t.Fatalf("unsafe Umask: %+v", fields["Umask"])
	}
	env := dictionary(t, fields["EnvironmentVariables"])
	if len(env) != 2 || env["PATH"].Text != "/usr/bin:/bin:/usr/sbin:/sbin" || env["HOME"].Text != state {
		t.Fatal("unsafe signer environment")
	}
}

func signerArgs() []string {
	return append(scriptArgs(), "--signer-uid", "401", "--signer-gid", "401", "--signrpc-gid", "402")
}

func TestSignerPlanAndInputRefusals(t *testing.T) {
	for _, args := range [][]string{signerArgs(), append(signerArgs(), "--signer-only")} {
		output, err := runScript(t, args)
		if err != nil {
			t.Fatalf("signer plan refused: %v: %s", err, output)
		}
		for _, want := range []string{"_macserve_sign uid=401", "_macserve_signrpc gid=402", "members servicecontrol and _macserve_sign only", "var/signer-run", "var/signer-inbox"} {
			if !strings.Contains(output, want) {
				t.Fatalf("plan lacks %q: %s", want, output)
			}
		}
	}
	if output, err := runScript(t, scriptArgs()); err != nil || strings.Contains(output, "_macserve_sign") {
		t.Fatalf("plan without signer IDs mentions the signer: %v: %s", err, output)
	}
	base := scriptArgs()
	for name, args := range map[string][]string{
		"partial":           append(base, "--signer-uid", "401", "--signer-gid", "401"),
		"only-without-ids":  append(base, "--signer-only"),
		"duplicate-only":    append(signerArgs(), "--signer-only", "--signer-only"),
		"shared-groups":     append(base, "--signer-uid", "401", "--signer-gid", "402", "--signrpc-gid", "402"),
		"below-range":       append(base, "--signer-uid", "199", "--signer-gid", "401", "--signrpc-gid", "402"),
		"service-range":     append(base, "--signer-uid", "501", "--signer-gid", "401", "--signrpc-gid", "402"),
		"leading-zero":      append(base, "--signer-uid", "0401", "--signer-gid", "401", "--signrpc-gid", "402"),
		"injected":          append(base, "--signer-uid", "401;id", "--signer-gid", "401", "--signrpc-gid", "402"),
		"duplicate-rpc-gid": append(signerArgs(), "--signrpc-gid", "403"),
	} {
		if output, err := runScript(t, args); err == nil {
			t.Fatalf("%s: unsafe signer input accepted: %s", name, output)
		}
	}
}

// The fixture models directory records like accountDirectoryFixture; the
// controller and job accounts already exist, as in --signer-only.
const signerDirectoryFixture = `
source "$1"; shift
scenario=$1; shift
put_record() { printf '%s\n' "$3" > "${1//\//_}.$2"; }
get_record() { local value; IFS= read -r value < "${1//\//_}.$2" || return 1; printf '%s\n' "$value"; }
function /usr/bin/dscl() {
    [ "$1" = . ] || return 91
    case "$2" in
        -create)
            case "$#" in
                3) put_record "$3" exists yes ;;
                5)
                    if [ "$scenario" = wrong-shell ] && [ "$4" = UserShell ]; then put_record "$3" "$4" /bin/zsh; else put_record "$3" "$4" "$5"; fi ;;
                *) return 93 ;;
            esac ;;
        -read)
            local value
            value=$(get_record "$3" "$4") || return 95
            printf '%s: %s\n' "$4" "$value" ;;
        -list)
            [ "$3 $4" = '/Groups GroupMembership' ] || return 96
            local members=''
            members=$(get_record /Groups/_macserve_signrpc members) || members=''
            [ "$scenario" != extra-member ] || members="$members intruder"
            printf '%s\n' 'staff root servicejob_neighbor' "_macserve_signrpc $members"
            [ "$scenario" != signer-group-member ] || printf '%s\n' '_macserve_sign servicejob' ;;
        *) return 98 ;;
    esac
}
function /usr/sbin/dseditgroup() {
    [ "$#" -eq 7 ] && [ "$1 $2 $3 $5 $6" = '-o edit -a -t user' ] || return 61
    [ "$scenario" != add-error ] || return 62
    local current=''
    current=$(get_record "/Groups/$7" members) || current=''
    put_record "/Groups/$7" members "${current:+$current }$4"
}
function /usr/bin/id() {
    local gids members
    case "$1" in
        -u) get_record "/Users/$2" UniqueID ;;
        -g) get_record "/Users/$2" PrimaryGroupID ;;
        -G)
            gids=$(get_record "/Users/$2" PrimaryGroupID) || return 71
            members=$(get_record /Groups/_macserve_signrpc members) || members=''
            case " $members " in *" $2 "*) gids="$gids 402" ;; esac
            case "$scenario:$2" in
                job-in-rpc:servicejob) gids="$gids 402" ;;
                job-in-signer:servicejob) gids="$gids 401" ;;
                signer-staff:_macserve_sign) gids="$gids 20" ;;
                signer-job-group:_macserve_sign) gids="$gids 1602" ;;
                controller-in-signer:servicecontrol) gids="$gids 401" ;;
            esac
            printf '%s\n' "$gids" ;;
        *) return 72 ;;
    esac
}
main "$@" >/dev/null
put_record /Users/servicecontrol PrimaryGroupID 1601
put_record /Users/servicejob PrimaryGroupID 1602
create_signer
# Hidden, password-disabled, nonlogin, with its own primary group.
[ "$(get_record /Users/_macserve_sign Password)" = '*' ]
[ "$(get_record /Users/_macserve_sign IsHidden)" = 1 ]
[ "$(get_record /Users/_macserve_sign UniqueID)" = 401 ]
[ "$(get_record /Groups/_macserve_sign PrimaryGroupID)" = 401 ]
[ "$(get_record /Groups/_macserve_signrpc PrimaryGroupID)" = 402 ]
[ "$(get_record /Groups/_macserve_signrpc Password)" = '*' ]
validate_signer_accounts
printf verified > signer-ready
`

func TestCreatedSignerAccounts(t *testing.T) {
	script, err := filepath.Abs("create-users.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		scenario string
		refuse   bool
	}{
		{"normal", false},
		{"wrong-shell", true},
		{"job-in-rpc", true},
		{"job-in-signer", true},
		{"signer-staff", true},
		{"signer-job-group", true},
		{"controller-in-signer", true},
		{"extra-member", true},
		{"signer-group-member", true},
		{"add-error", true},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			args := append([]string{"-c", signerDirectoryFixture, "signer-test", script, tc.scenario}, append(signerArgs(), "--signer-only")...)
			cmd := exec.Command("/bin/bash", args...)
			cmd.Dir = t.TempDir()
			cmd.Env = []string{"PATH=/nonexistent", "HOME=" + cmd.Dir}
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.refuse {
				t.Fatalf("refuse=%v, err=%v: %s", tc.refuse, err, out)
			}
			if _, readyErr := os.Stat(filepath.Join(cmd.Dir, "signer-ready")); (readyErr == nil) == tc.refuse {
				t.Fatalf("provisioning gate did not match refusal: %v", readyErr)
			}
		})
	}
}

func TestSignerOnlyApplyNeedsNoTerminalButRefusesOffDarwin(t *testing.T) {
	script, err := filepath.Abs("create-users.sh")
	if err != nil {
		t.Fatal(err)
	}
	program := `source "$1"; shift
function /usr/bin/uname() { printf queried > host-inspected; printf 'Linux\n'; }
main "$@"`
	args := append([]string{"-c", program, "signer-only-test", script}, append(signerArgs(), "--signer-only", "--apply")...)
	cmd := exec.Command("/bin/bash", args...)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=/nonexistent", "HOME=" + cmd.Dir}
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "requires Darwin") {
		t.Fatalf("signer-only apply off Darwin: err=%v output=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(cmd.Dir, "host-inspected")); err != nil {
		t.Fatalf("signer-only apply should reach the Darwin gate without a terminal: %v", err)
	}
}
