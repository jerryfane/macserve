package plan

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/deploy"
)

var (
	testOwner = Account{Name: "jdoe", UID: 501, Home: "/Users/jdoe", GIDs: []uint32{20, 80}}
	testIDs   = IDs{ControllerUID: 6201, ControllerGID: 6201, JobUID: 6202, JobGID: 6202}
)

func testFacts() EnvironmentFacts {
	return EnvironmentFacts{
		Owner:         testOwner,
		TailnetIP:     netip.MustParseAddr("100.101.102.103"),
		HostAddresses: []string{"100.101.102.103", "192.168.1.20"},
		Port:          8443,
		DeveloperDir:  "/Applications/Xcode.app/Contents/Developer",
	}
}

// injectionChoices are inputs that try to add deploy.env lines or keys, or
// smuggle characters the deploy parser would accept or reinterpret.
func injectionChoices() map[string]func(*Choices) {
	return map[string]func(*Choices){
		"real name newline key": func(c *Choices) { c.JobRealName = "macserve build\nCOEXISTING_SERVICES=com.example.agent" },
		"real name newline anchor": func(c *Choices) {
			c.JobRealName = "macserve build\nCOEXISTING_ANCHORS=com.apple/250.ApplicationFirewall"
		},
		"real name carriage":      func(c *Choices) { c.JobRealName = "macserve build\rCOEXISTING_SERVICES=x" },
		"real name comment line":  func(c *Choices) { c.JobRealName = "macserve build\n# comment" },
		"real name equals":        func(c *Choices) { c.JobRealName = "a=b" },
		"real name C1 control":    func(c *Choices) { c.JobRealName = "macserve\u0085build" },
		"real name nul":           func(c *Choices) { c.JobRealName = "macserve\x00build" },
		"real name escape":        func(c *Choices) { c.JobRealName = "macserve \x1b[2J" },
		"real name non-ASCII":     func(c *Choices) { c.JobRealName = "macserve bùild" },
		"real name quote":         func(c *Choices) { c.JobRealName = "macserve 'build'" },
		"real name trailing":      func(c *Choices) { c.JobRealName = "macserve build " },
		"real name empty":         func(c *Choices) { c.JobRealName = "" },
		"real name too long":      func(c *Choices) { c.JobRealName = strings.Repeat("a", 65) },
		"repository newline key":  func(c *Choices) { c.Repository = "jdoe/myapp:1\nCOEXISTING_SERVICES=com.example.agent" },
		"repository second pin":   func(c *Choices) { c.Repository = "jdoe/myapp:1,jdoe/other:2" },
		"repository carriage":     func(c *Choices) { c.Repository = "jdoe/myapp:1\r" },
		"repository uppercase":    func(c *Choices) { c.Repository = "JDoe/MyApp:1" },
		"repository no id":        func(c *Choices) { c.Repository = "jdoe/myapp" },
		"repository zero id":      func(c *Choices) { c.Repository = "jdoe/myapp:0" },
		"repository leading zero": func(c *Choices) { c.Repository = "jdoe/myapp:01" },
		"repository huge id":      func(c *Choices) { c.Repository = "jdoe/myapp:9007199254740992" },
		"repository dotdot":       func(c *Choices) { c.Repository = "jdoe/a..b:1" },
		"repository dot git":      func(c *Choices) { c.Repository = "jdoe/myapp.git:1" },
		"repository equals":       func(c *Choices) { c.Repository = "jdoe/myapp:1=2" },
		"job user newline":        func(c *Choices) { c.JobUser = "macservejob\nCOEXISTING_SERVICES=x" },
		"job user reserved shape": func(c *Choices) { c.JobUser = "Macservejob" },
		"same account names":      func(c *Choices) { c.ControllerUser = c.JobUser },
	}
}

func TestGeneratedEnvParsesWithDeployParser(t *testing.T) {
	c := DefaultChoices()
	c.Repository = "jdoe/myapp:987654321"
	data, err := RenderEnvironment(testFacts(), c, testIDs)
	if err != nil {
		t.Fatal(err)
	}
	want := "CONTROLLER_USER=macservectl\nCONTROLLER_UID=6201\nCONTROLLER_GID=6201\nJOB_USER=macservejob\nJOB_REAL_NAME=macserve build\nJOB_UID=6202\nJOB_GID=6202\n" +
		"OWNER_USER=jdoe\nOWNER_UID=501\nTAILNET_IP=100.101.102.103\nPORT=8443\nPROTECTED_PORTS=8443\nHOST_ADDRESSES=100.101.102.103,192.168.1.20\n" +
		"DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer\nREPOSITORIES=jdoe/myapp:987654321\n"
	if string(data) != want {
		t.Fatalf("deploy.env:\n%s\nwant:\n%s", data, want)
	}
	parsed, err := deploy.ParseEnvironment(data)
	if err != nil {
		t.Fatalf("deploy parser rejects generated deploy.env: %v", err)
	}
	if parsed.Repositories["jdoe/myapp"] != 987654321 || len(parsed.Repositories) != 1 || parsed.CoexistingAnchors != nil || parsed.CoexistingServices != nil {
		t.Fatalf("unexpected parse %+v", parsed)
	}

	c.Repository = ""
	data, err = RenderEnvironment(testFacts(), c, testIDs)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != strings.TrimSuffix(want, "REPOSITORIES=jdoe/myapp:987654321\n") || strings.Contains(string(data), pendingRepositoryName) {
		t.Fatalf("stand-in repository leaked or output changed:\n%s", data)
	}
	if _, err := deploy.ParseEnvironment(data); err == nil || !strings.Contains(err.Error(), "REPOSITORIES") {
		t.Fatalf("environment without the GitHub step must still need REPOSITORIES: %v", err)
	}
}

func TestRenderEnvironmentRefusesInjection(t *testing.T) {
	for name, mutate := range injectionChoices() {
		c := DefaultChoices()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: Validate accepted", name)
		}
		if data, err := RenderEnvironment(testFacts(), c, testIDs); err == nil {
			t.Errorf("%s: rendered\n%s", name, data)
		}
	}
	// Detected facts are checked line by line too, not only user choices.
	for name, mutate := range map[string]func(*EnvironmentFacts){
		"host address line": func(f *EnvironmentFacts) { f.HostAddresses = []string{"100.101.102.103\nCOEXISTING_SERVICES=x"} },
		"developer dir line": func(f *EnvironmentFacts) {
			f.DeveloperDir = "/Applications/Xcode.app/Contents/Developer\nCOEXISTING_SERVICES=x"
		},
		"owner line":    func(f *EnvironmentFacts) { f.Owner.Name = "jdoe\nCOEXISTING_SERVICES=x" },
		"owner equals":  func(f *EnvironmentFacts) { f.Owner.Name = "jdoe=x" },
		"developer dir": func(f *EnvironmentFacts) { f.DeveloperDir = "/Applications/../Xcode.app" },
		"host address":  func(f *EnvironmentFacts) { f.HostAddresses = []string{"192.168.1.20"} },
		"duplicate host": func(f *EnvironmentFacts) {
			f.HostAddresses = []string{"100.101.102.103", "100.101.102.103"}
		},
	} {
		f := testFacts()
		mutate(&f)
		if data, err := RenderEnvironment(f, DefaultChoices(), testIDs); err == nil {
			t.Errorf("%s: rendered\n%s", name, data)
		}
	}
}

func TestChoicesGrammarAccepts(t *testing.T) {
	for _, c := range []Choices{
		DefaultChoices(),
		{ControllerUser: "ctl", JobUser: "job_1", JobRealName: "Build-2.0 x_y", Repository: "my-org/my.app_2:9007199254740991"},
		{ControllerUser: "ctl", JobUser: "job", JobRealName: "b"},
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
		if _, err := RenderEnvironment(testFacts(), c, testIDs); err != nil {
			t.Errorf("%+v: %v", c, err)
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
	owner = testOwner
	owner.UID = 6201
	if ids, err = PickIDs(base, DefaultChoices(), owner); err != nil || ids.ControllerUID != 6202 {
		t.Fatalf("owner UID not skipped: %+v %v", ids, err)
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
	full.Users = full.Users[:len(full.Users)-1]
	if _, err := PickIDs(full, DefaultChoices(), testOwner); err != nil {
		t.Errorf("two free IDs at the end of the range refused: %v", err)
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
	tailnet, hosts, err := SelectAddresses(addrs("fe80::1%en0", "192.168.1.20", "::1", "fd7a:115c:a1e0::1234", "100.101.102.103", "192.168.1.20", "224.0.0.1", "::ffff:10.0.0.2", "::", "ff02::1"))
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
	if _, err := RenderEnvironment(f, DefaultChoices(), testIDs); err == nil || !strings.Contains(err.Error(), "TAILNET_IP") {
		t.Fatalf("non-tailnet TAILNET_IP accepted by the generator: %v", err)
	}
}
