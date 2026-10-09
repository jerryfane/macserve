package assets_test

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		"JobUID": 1502, "ProtectedPorts": "12345, 12346",
		"HostAddresses": "192.0.2.10, 2001:db8::10",
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

// This deliberately small parser evaluates the shipped PF subset, not the host
// firewall. Native parsing and real effective-UID probes remain deployment gates.
type pfRule struct {
	destination, label string
	protected          bool
}
type pfPolicy struct {
	uid       int
	ports     map[int]bool
	addresses map[string][]netip.Prefix
	rules     []pfRule
}

var rulePattern = regexp.MustCompile(`^block drop out log quick proto \{ tcp udp \} from any to (any|\$[a-z_]+)( port \$protected_ports)? user \$job_uid label "([a-z-]+)"$`)
var addressPattern = regexp.MustCompile(`^([a-z_]+_addresses) = "\{ (.+) \}"$`)

func parsePF(data []byte) (pfPolicy, error) {
	p := pfPolicy{ports: map[int]bool{}, addresses: map[string][]netip.Prefix{}}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "job_uid = "):
			value, err := strconv.Unquote(strings.TrimPrefix(line, "job_uid = "))
			if err != nil {
				return p, err
			}
			p.uid, err = strconv.Atoi(value)
			if err != nil || p.uid < 501 {
				return p, fmt.Errorf("invalid UID")
			}
		case strings.HasPrefix(line, "protected_ports = "):
			value, err := strconv.Unquote(strings.TrimPrefix(line, "protected_ports = "))
			if err != nil {
				return p, err
			}
			if !strings.HasPrefix(value, "{ ") || !strings.HasSuffix(value, " }") {
				return p, fmt.Errorf("invalid port set")
			}
			for _, port := range strings.Split(value[2:len(value)-2], ",") {
				n, err := strconv.Atoi(strings.TrimSpace(port))
				if err != nil || n < 1 || n > 65535 {
					return p, fmt.Errorf("invalid port")
				}
				p.ports[n] = true
			}
		case addressPattern.MatchString(line):
			match := addressPattern.FindStringSubmatch(line)
			for _, item := range strings.Split(match[2], ",") {
				item = strings.TrimSpace(item)
				prefix, err := netip.ParsePrefix(item)
				if err != nil {
					address, e := netip.ParseAddr(item)
					if e != nil {
						return p, e
					}
					prefix = netip.PrefixFrom(address, address.BitLen())
				}
				p.addresses[match[1]] = append(p.addresses[match[1]], prefix)
			}
		case rulePattern.MatchString(line):
			match := rulePattern.FindStringSubmatch(line)
			p.rules = append(p.rules, pfRule{destination: match[1], protected: match[2] != "", label: match[3]})
		default:
			return p, fmt.Errorf("unsupported PF syntax: %s", line)
		}
	}
	if p.uid == 0 || len(p.ports) == 0 {
		return p, fmt.Errorf("missing identity/ports")
	}
	return p, nil
}

func (p pfPolicy) decision(uid int, protocol, address string, port int) string {
	if uid != p.uid || (protocol != "tcp" && protocol != "udp") {
		return "outside-anchor"
	}
	ip := netip.MustParseAddr(address)
	for _, rule := range p.rules {
		if rule.protected && !p.ports[port] {
			continue
		}
		matches := rule.destination == "any"
		for _, prefix := range p.addresses[strings.TrimPrefix(rule.destination, "$")] {
			matches = matches || prefix.Contains(ip)
		}
		if matches {
			return rule.label
		}
	}
	return "unmatched"
}

func TestPFRenderedDenyPrecedenceAndOwnerIsolation(t *testing.T) {
	policy, err := parsePF(render(t, "pf/org.macserve.conf.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"tcp", "udp"} {
		for _, address := range []string{"127.0.0.1", "::1", "10.20.30.40", "100.64.1.2", "169.254.2.3", "fc00::1", "fe80::1", "192.0.2.10", "2001:db8::10", "203.0.113.90"} {
			for _, port := range []int{12345, 12346} {
				if got := policy.decision(1502, protocol, address, port); got != "macserve-protected" {
					t.Fatalf("protected %s %s:%d = %s", protocol, address, port, got)
				}
			}
			if got := policy.decision(1501, protocol, address, 12345); got != "outside-anchor" {
				t.Fatalf("owner affected: %s", got)
			}
		}
		for address, want := range map[string]string{
			"10.20.30.40": "macserve-private", "172.16.1.2": "macserve-private", "192.168.1.2": "macserve-private", "100.64.1.2": "macserve-private", "fc00::1": "macserve-private", "fe80::1": "macserve-private",
			"192.0.2.10": "macserve-host", "2001:db8::10": "macserve-host",
			"127.0.0.1": "macserve-private", "127.255.255.254": "macserve-private", "::1": "macserve-private", "169.254.255.254": "macserve-private", "febf:ffff::1": "macserve-private", "203.0.113.90": "macserve-default-deny",
		} {
			if got := policy.decision(1502, protocol, address, 443); got != want {
				t.Fatalf("%s %s = %s, want %s", protocol, address, got, want)
			}
		}
	}
}

func TestPFMandatoryRangesCannotReachLaterException(t *testing.T) {
	policy, err := parsePF(render(t, "pf/org.macserve.conf.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	// Model an owner-reviewed quick pass immediately before the final catchall.
	// No host-address entry includes these destinations.
	policy.rules = append(policy.rules[:len(policy.rules)-1], pfRule{destination: "any", label: "reviewed-pass"})
	for _, protocol := range []string{"tcp", "udp"} {
		for _, address := range []string{"127.0.0.1", "127.255.255.255", "169.254.0.1", "169.254.255.255", "::1", "fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
			for _, port := range []int{1, 443, 65535} {
				if got := policy.decision(1502, protocol, address, port); got != "macserve-private" {
					t.Fatalf("mandatory boundary %s %s:%d reached %s", protocol, address, port, got)
				}
				if got := policy.decision(1501, protocol, address, port); got != "outside-anchor" {
					t.Fatalf("mandatory boundary affected non-job UID: %s", got)
				}
			}
		}
		if got := policy.decision(1502, protocol, "203.0.113.90", 443); got != "reviewed-pass" {
			t.Fatalf("public destination did not reach reviewed exception: %s", got)
		}
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
				cmd := exec.Command("/bin/bash", "-c", `source "$1"; validate_account_groups "$2" "$3" "$4"; printf 'membership accepted\n'`, "membership-test", script, role.name, role.other, role.primary+" "+tc.extra)
				cmd.Dir = t.TempDir()
				cmd.Env = []string{"PATH=/nonexistent", "HOME=" + cmd.Dir}
				out, err := cmd.CombinedOutput()
				if tc.refuse {
					want := "REFUSED: privileged/shared supplementary group for " + role.name + "; keep services disabled and reconcile manually\n"
					if err == nil || string(out) != want {
						t.Fatalf("unsafe membership was not refused: err=%v output=%q", err, out)
					}
				} else if err != nil || string(out) != "membership accepted\n" {
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
		want string
	}{
		{"help-followed-by-option", []string{"--help", "--env", "unused"}, "REFUSED: help must be used alone"},
		{"help-after-option", []string{"--env", "unused", "--help"}, "REFUSED: help must be used alone"},
		{"missing-env", []string{"--binary", binary, "--sha256", digest}, "Usage:"},
		{"missing-binary", []string{"--env", "unused", "--sha256", digest}, "Usage:"},
		{"missing-digest", []string{"--env", "unused", "--binary", binary}, "Usage:"},
		{"absent-file", []string{"--env", "unused", "--binary", filepath.Join(dir, "absent"), "--sha256", digest}, "REFUSED: binary must be a nonsymlink regular file"},
		{"directory", []string{"--env", "unused", "--binary", dir, "--sha256", digest}, "REFUSED: binary must be a nonsymlink regular file"},
		{"symlink", []string{"--env", "unused", "--binary", link, "--sha256", digest}, "REFUSED: binary must be a nonsymlink regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("/bin/bash", append([]string{script}, tc.args...)...)
			cmd.Dir = dir
			cmd.Env = []string{"PATH=/nonexistent", "HOME=" + dir}
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.HasPrefix(string(out), tc.want) {
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
