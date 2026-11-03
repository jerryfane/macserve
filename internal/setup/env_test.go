package setup

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/deploy"
)

var testOwner = Account{Name: "jdoe", UID: 501, Home: "/Users/jdoe", GIDs: []uint32{20, 80}}

func testFacts() EnvironmentFacts {
	return EnvironmentFacts{
		Owner:         testOwner,
		TailnetIP:     netip.MustParseAddr("100.101.102.103"),
		HostAddresses: []string{"100.101.102.103", "192.168.1.20"},
		Port:          8443,
		DeveloperDir:  "/Applications/Xcode.app/Contents/Developer",
	}
}

func TestGeneratedEnvParsesWithDeployParser(t *testing.T) {
	c := DefaultChoices()
	c.Repository = "jdoe/myapp:987654321"
	ids := IDs{ControllerUID: 6201, ControllerGID: 6201, JobUID: 6202, JobGID: 6202}
	data, env, err := RenderEnvironment(testFacts(), c, ids)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := deploy.ParseEnvironment(data)
	if err != nil {
		t.Fatalf("deploy parser rejects generated deploy.env: %v\n%s", err, data)
	}
	if parsed.ControllerUser != "macservectl" || parsed.JobUser != "macservejob" || parsed.OwnerUser != "jdoe" ||
		parsed.ControllerUID != 6201 || parsed.ControllerGID != 6201 || parsed.JobUID != 6202 || parsed.JobGID != 6202 || parsed.OwnerUID != 501 ||
		parsed.TailnetIP != "100.101.102.103" || parsed.Port != 8443 || len(parsed.ProtectedPorts) != 1 || parsed.ProtectedPorts[0] != 8443 ||
		parsed.JobRealName != "macserve build" || parsed.Repositories["jdoe/myapp"] != 987654321 || len(parsed.Repositories) != 1 {
		t.Fatalf("unexpected parse %+v", parsed)
	}
	if env.JobUID != parsed.JobUID || env.Repositories["jdoe/myapp"] != 987654321 {
		t.Fatalf("returned environment differs from parse: %+v", env)
	}

	c.Repository = ""
	data, env, err = RenderEnvironment(testFacts(), c, ids)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("REPOSITORIES")) || env.Repositories != nil || strings.Contains(string(data), pendingRepository) {
		t.Fatalf("stand-in repository leaked:\n%s", data)
	}
	if _, err := deploy.ParseEnvironment(data); err == nil || !strings.Contains(err.Error(), "REPOSITORIES") {
		t.Fatalf("environment without the GitHub step must still need REPOSITORIES: %v", err)
	}
}

func TestRenderEnvironmentRejectsWhatDeployRejects(t *testing.T) {
	ids := IDs{ControllerUID: 6201, ControllerGID: 6201, JobUID: 6202, JobGID: 6202}
	for name, mutate := range map[string]func(*EnvironmentFacts, *Choices){
		"repository":   func(_ *EnvironmentFacts, c *Choices) { c.Repository = "jdoe/myapp" },
		"real name":    func(_ *EnvironmentFacts, c *Choices) { c.JobRealName = "build\x01" },
		"shell value":  func(_ *EnvironmentFacts, c *Choices) { c.JobRealName = "$(id)" },
		"account":      func(_ *EnvironmentFacts, c *Choices) { c.JobUser = "staff" },
		"developer":    func(f *EnvironmentFacts, _ *Choices) { f.DeveloperDir = "/Applications/../Xcode.app" },
		"host address": func(f *EnvironmentFacts, _ *Choices) { f.HostAddresses = []string{"192.168.1.20"} },
	} {
		f, c := testFacts(), DefaultChoices()
		mutate(&f, &c)
		if _, _, err := RenderEnvironment(f, c, ids); err == nil {
			t.Errorf("%s: invalid environment accepted", name)
		}
	}
}

func TestPicksFreeIDsAndRefusesDirectoryConflicts(t *testing.T) {
	base := Directory{
		Users:             []DirectoryRecord{{"root", 0}, {"jdoe", 501}},
		Groups:            []DirectoryRecord{{"wheel", 0}, {"staff", 20}, {"admin", 80}},
		UserPrimaryGroups: []DirectoryRecord{{"root", 0}, {"jdoe", 20}},
	}
	ids, err := PickIDs(base, DefaultChoices(), testOwner)
	if err != nil || ids != (IDs{6201, 6201, 6202, 6202}) {
		t.Fatalf("defaults: %+v %v", ids, err)
	}

	d := base
	d.Groups = append(d.Groups, DirectoryRecord{"other", 6201})
	d.UserPrimaryGroups = append(d.UserPrimaryGroups, DirectoryRecord{"someone", 6203})
	d.Users = append(d.Users, DirectoryRecord{"someone", 6204})
	owner := testOwner
	owner.GIDs = append(owner.GIDs, 6205)
	ids, err = PickIDs(d, DefaultChoices(), owner)
	if err != nil || ids != (IDs{6202, 6202, 6206, 6206}) {
		t.Fatalf("taken IDs not skipped: %+v %v", ids, err)
	}

	for name, d := range map[string]Directory{
		"existing user":  {Users: []DirectoryRecord{{"macservejob", 7001}}},
		"existing group": {Groups: []DirectoryRecord{{"macservectl", 7002}}},
	} {
		if _, err := PickIDs(d, DefaultChoices(), testOwner); err == nil {
			t.Errorf("%s: conflict accepted", name)
		}
	}
	c := DefaultChoices()
	c.JobUser = "jdoe"
	if _, err := PickIDs(base, c, testOwner); err == nil {
		t.Error("job account named like the owner accepted")
	}

	full := base
	for id := int64(firstID); id < lastID; id++ {
		full.Users = append(full.Users, DirectoryRecord{"u" + string(rune('a'+id%26)), id})
	}
	if _, err := PickIDs(full, DefaultChoices(), testOwner); err == nil {
		t.Error("exhausted range accepted")
	}
}

func TestParseDirectoryListFailsClosed(t *testing.T) {
	records, err := ParseDirectoryList("root 0\n\njdoe   501\n_www -2\n")
	if err != nil || len(records) != 3 || records[1] != (DirectoryRecord{"jdoe", 501}) || records[2].ID != -2 {
		t.Fatalf("%+v %v", records, err)
	}
	for _, bad := range []string{"two words 5\n", "name\n", "name x\n", "name 1.5\n"} {
		if _, err := ParseDirectoryList(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRefusesNonTailnetAddress(t *testing.T) {
	addrs := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, a := range s {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	for name, list := range map[string][]netip.Addr{
		"no tailnet":       addrs("127.0.0.1", "192.168.1.20", "fe80::1%en0", "10.0.0.2"),
		"two IPv4 tailnet": addrs("100.64.0.1", "100.101.102.103"),
		"two IPv6 tailnet": addrs("fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2"),
		"outside range":    addrs("100.128.0.1", "fd7a:115c:a1e1::1"),
	} {
		if _, _, err := SelectAddresses(list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tailnet, hosts, err := SelectAddresses(addrs("fe80::1%en0", "192.168.1.20", "::1", "fd7a:115c:a1e0::1234", "100.101.102.103", "192.168.1.20", "224.0.0.1", "::ffff:10.0.0.2"))
	if err != nil || tailnet.String() != "100.101.102.103" || strings.Join(hosts, ",") != "100.101.102.103,10.0.0.2,192.168.1.20,fd7a:115c:a1e0::1234" {
		t.Fatalf("got %v %v %v", tailnet, hosts, err)
	}
	tailnet, hosts, err = SelectAddresses(addrs("fd7a:115c:a1e0::1234", "192.168.1.20"))
	if err != nil || tailnet.String() != "fd7a:115c:a1e0::1234" || strings.Join(hosts, ",") != "fd7a:115c:a1e0::1234,192.168.1.20" {
		t.Fatalf("IPv6 only: %v %v %v", tailnet, hosts, err)
	}
	f := testFacts()
	f.TailnetIP = netip.MustParseAddr("192.168.1.20")
	f.HostAddresses = []string{"192.168.1.20"}
	if _, _, err := RenderEnvironment(f, DefaultChoices(), IDs{6201, 6201, 6202, 6202}); err == nil || !strings.Contains(err.Error(), "TAILNET_IP") {
		t.Fatalf("non-tailnet TAILNET_IP accepted by the generator: %v", err)
	}
}
