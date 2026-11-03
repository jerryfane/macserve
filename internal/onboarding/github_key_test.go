package onboarding

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// installRoot builds <tmp>/macserve with var/controller/secrets owned by
// the test user, standing in for root and the controller.
func installRoot(t *testing.T) KeyTarget {
	t.Helper()
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tmp, "macserve")
	for _, dir := range []struct {
		path string
		mode os.FileMode
	}{{root, 0o755}, {filepath.Join(root, "var"), 0o755}, {filepath.Join(root, "config"), 0o755}, {filepath.Join(root, "var", "controller"), 0o700}, {filepath.Join(root, "var", "controller", "secrets"), 0o700}} {
		if err := os.Mkdir(dir.path, dir.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir.path, dir.mode); err != nil {
			t.Fatal(err)
		}
	}
	return KeyTarget{Root: root, RootUID: uint32(os.Getuid()), ControllerUID: uint32(os.Getuid()), ControllerGID: uint32(os.Getgid())}
}

func TestAppKeyInstalledControllerOwned0600(t *testing.T) {
	target := installRoot(t)
	_, pemBytes := appKey(t)
	if err := InstallAppKey(target, pemBytes); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(target.Path())
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, nlink, _ := owner(info)
	if info.Mode() != 0o600 || uid != target.ControllerUID || gid != target.ControllerGID || nlink != 1 {
		t.Fatalf("mode %v uid %d gid %d links %d", info.Mode(), uid, gid, nlink)
	}
	if data, _ := os.ReadFile(target.Path()); !bytes.Equal(data, pemBytes) {
		t.Fatal("key bytes differ")
	}
}

func TestAppKeyWriteRefusesOverwriteSymlinkAndWrongOwner(t *testing.T) {
	_, pemBytes := appKey(t)
	t.Run("existing key", func(t *testing.T) {
		target := installRoot(t)
		if err := os.WriteFile(target.Path(), []byte("old key"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := InstallAppKey(target, pemBytes); !errors.Is(err, ErrKeyExists) {
			t.Fatal(err)
		}
		if data, _ := os.ReadFile(target.Path()); string(data) != "old key" {
			t.Fatal("existing key changed")
		}
		if exists, err := target.KeyInstalled(); !exists || err != nil {
			t.Fatal(exists, err)
		}
	})
	t.Run("symlink at key path", func(t *testing.T) {
		target := installRoot(t)
		decoy := filepath.Join(target.Root, "decoy")
		if err := os.Symlink(decoy, target.Path()); err != nil {
			t.Fatal(err)
		}
		if err := InstallAppKey(target, pemBytes); !errors.Is(err, ErrKeyExists) {
			t.Fatal(err)
		}
		if _, err := os.Lstat(decoy); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("wrote through the symlink")
		}
	})
	t.Run("symlinked secrets directory", func(t *testing.T) {
		target := installRoot(t)
		elsewhere := filepath.Join(target.Root, "elsewhere")
		if err := os.Mkdir(elsewhere, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(target.Dir()); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, target.Dir()); err != nil {
			t.Fatal(err)
		}
		if err := InstallAppKey(target, pemBytes); err == nil || !strings.Contains(err.Error(), "not a real directory") {
			t.Fatal(err)
		}
	})
	t.Run("symlinked ancestor", func(t *testing.T) {
		target := installRoot(t)
		link := target.Root + "-link"
		if err := os.Symlink(target.Root, link); err != nil {
			t.Fatal(err)
		}
		target.Root = link
		if err := InstallAppKey(target, pemBytes); err == nil {
			t.Fatal("accepted a symlinked install root")
		}
	})
	t.Run("wrong controller owner", func(t *testing.T) {
		target := installRoot(t)
		target.ControllerUID++
		if err := InstallAppKey(target, pemBytes); err == nil || !strings.Contains(err.Error(), "controller-owned 0700") {
			t.Fatal(err)
		}
	})
	t.Run("group-readable secrets", func(t *testing.T) {
		target := installRoot(t)
		if err := os.Chmod(target.Dir(), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := InstallAppKey(target, pemBytes); err == nil {
			t.Fatal("accepted a 0750 secrets directory")
		}
	})
	t.Run("writable ancestor", func(t *testing.T) {
		target := installRoot(t)
		if err := os.Chmod(filepath.Join(target.Root, "var"), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := InstallAppKey(target, pemBytes); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatal(err)
		}
	})
	t.Run("untrusted root owner", func(t *testing.T) {
		target := installRoot(t)
		target.RootUID++
		if err := InstallAppKey(target, pemBytes); err == nil {
			t.Fatal("accepted an install root of another owner")
		}
	})
	t.Run("not a key", func(t *testing.T) {
		target := installRoot(t)
		if err := InstallAppKey(target, []byte("not a key")); err == nil {
			t.Fatal("installed a non-key")
		}
		if exists, _ := target.KeyInstalled(); exists {
			t.Fatal("left a file")
		}
	})
}

// controllerFixture writes a deploy-install style controller.json pinning
// jdoe/myapp and returns its file.
func controllerFixture(t *testing.T, target KeyTarget) ConfigFile {
	t.Helper()
	config := filepath.Join(target.Root, "config")
	c := controller.Config{
		Root: target.Root + "/var/controller", Socket: target.Root + "/var/controller/run/worker.sock", JobUID: 611,
		ProfilesFile: config + "/profiles.json", Listen: "100.64.0.10:9443", AllowedNetworks: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		TLSCertificate: config + "/tls-cert.pem", TLSKey: target.Dir() + "/tls-key.pem", HealthFile: target.Root + "/health/current.json",
		PauseFile: config + "/owner.pause", OwnerUID: 501,
		Receipt: controller.ReceiptConfig{KeyID: "k1", PrivateKeyFile: target.Dir() + "/receipt-key.pem", ServiceID: "svc", HostID: "host", Repositories: map[string]int64{"jdoe/myapp": 4242}},
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(config, "controller.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	return ConfigFile{Path: path, RootUID: target.RootUID}
}

func enrollment(target KeyTarget) Enrollment {
	return Enrollment{AppID: 77, InstallationID: 555, Repository: "jdoe/myapp", RepositoryID: 4242, AuthorIDs: []int64{1001}, BaseBranches: []string{"main"}, Profiles: []string{"myapp-build-v1"}, KeyFile: target.Path()}
}

func TestWriteGitHubProducesLoadableConfig(t *testing.T) {
	target := installRoot(t)
	file := controllerFixture(t, target)
	_, pemBytes := appKey(t)
	if err := file.WriteGitHub(enrollment(target), func() error { return InstallAppKey(target, pemBytes) }); err != nil {
		t.Fatal(err)
	}
	c, err := controller.LoadConfig(file.Path)
	if err != nil {
		t.Fatal(err)
	}
	g := c.GitHub
	if g == nil || g.AppID != 77 || g.InstallationID != 555 || g.PrivateKeyFile != target.Path() || g.PollSeconds != 45 || len(g.Policies) != 1 {
		t.Fatalf("%+v", g)
	}
	p := g.Policies[0]
	if p.RepositoryID != 4242 || p.Repository != "jdoe/myapp" || p.PolicyRevision != 1 || len(p.AuthorIDs) != 1 || p.AuthorIDs[0] != 1001 || p.BaseBranches[0] != "main" || p.Profiles[0] != "myapp-build-v1" {
		t.Fatalf("%+v", p)
	}
	if c.Receipt.Repositories["jdoe/myapp"] != 4242 || c.OwnerUID != 501 {
		t.Fatalf("other fields changed: %+v", c)
	}
	info, _ := os.Lstat(file.Path)
	if info.Mode() != 0o644 {
		t.Fatal(info.Mode())
	}
	if err := file.WriteGitHub(enrollment(target), func() error { return nil }); !errors.Is(err, ErrGitHubConfigured) {
		t.Fatal(err)
	}
	if _, err := file.Check(); !errors.Is(err, ErrGitHubConfigured) {
		t.Fatal(err)
	}
}

func TestWriteGitHubRefusesUnpinnedRepositoryAndKeepsFileOnKeyFailure(t *testing.T) {
	target := installRoot(t)
	file := controllerFixture(t, target)
	before, _ := os.ReadFile(file.Path)
	e := enrollment(target)
	e.RepositoryID = 4243
	called := false
	if err := file.WriteGitHub(e, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("wrote a policy whose ID differs from the receipt pin")
	}
	if err := file.WriteGitHub(enrollment(target), func() error { return ErrKeyExists }); !errors.Is(err, ErrKeyExists) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(file.Path)
	entries, _ := os.ReadDir(filepath.Dir(file.Path))
	if !bytes.Equal(before, after) || len(entries) != 1 {
		t.Fatalf("controller.json changed or temp left: %v", entries)
	}
}

func TestCheckPolicyProfilesTemporaryUntilO7(t *testing.T) {
	p := model.Profile{
		ID: "myapp-build-v1", Version: 1, Repo: "jdoe/myapp", Kind: model.Build,
		Xcode: model.Xcode{Version: "26.0", Build: "17A100"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", WorkDir: ".",
		Run: model.Command{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "build", "-derivedDataPath", "${DERIVED_DATA}"}},
	}
	other := p
	other.ID, other.Repo = "other-build-v1", "jdoe/other"
	tmpl := model.Template{ID: "jdoe-build-v1", Version: 1, Kind: model.Build, Owners: []string{"jdoe"}, Xcode: p.Xcode, DeveloperDir: p.DeveloperDir}
	registry, err := profiles.New([]model.Profile{p, other}, []model.Template{tmpl})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPolicyProfiles(registry, "jdoe/myapp", []string{"myapp-build-v1"}); err != nil {
		t.Fatal(err)
	}
	for name, ids := range map[string][]string{
		"none": nil, "repeated": {"myapp-build-v1", "myapp-build-v1"}, "unknown": {"nope"},
		"other repository": {"other-build-v1"}, "template": {"jdoe-build-v1"},
	} {
		if err := CheckPolicyProfiles(registry, "jdoe/myapp", ids); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := CheckPolicyProfiles(registry, "jdoe/myapp", []string{"jdoe-build-v1"}); !strings.Contains(err.Error(), "O7") {
		t.Errorf("template refusal does not name O7: %v", err)
	}
}

const fixtureEnv = `CONTROLLER_USER=buildcontroller
CONTROLLER_UID=610
CONTROLLER_GID=610
JOB_USER=buildjob
JOB_UID=611
JOB_GID=611
OWNER_USER=jdoe
OWNER_UID=501
TAILNET_IP=100.64.0.10
PORT=9443
PROTECTED_PORTS=22,9443
HOST_ADDRESSES=127.0.0.1,::1,100.64.0.10
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
REPOSITORIES=jdoe/myapp:4242
`

func hostFixture(t *testing.T) (Host, KeyTarget) {
	t.Helper()
	target := installRoot(t)
	controllerFixture(t, target)
	config := filepath.Join(target.Root, "config")
	if err := os.WriteFile(filepath.Join(config, "deploy.env"), []byte(fixtureEnv), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config, "profiles.json"), []byte(`{"profiles":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return Host{Root: target.Root, RootUID: target.RootUID, EUID: int(target.RootUID), SudoUID: "501", ConsoleUID: func() (uint32, error) { return 501, nil }}, target
}

func TestPrepareAcceptsFreshDeployInstall(t *testing.T) {
	h, target := hostFixture(t)
	p, err := Prepare(h)
	if err != nil {
		t.Fatal(err)
	}
	if p.OwnerUID != 501 || p.Key.ControllerUID != 610 || p.Key.Path() != target.Path() {
		t.Fatalf("%+v", p)
	}
	if repo, id, err := p.Repository(""); err != nil || repo != "jdoe/myapp" || id != 4242 {
		t.Fatal(repo, id, err)
	}
	if _, _, err := p.Repository("jdoe/other"); err == nil {
		t.Fatal("accepted an unpinned repository")
	}
}

func TestPrepareRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Host, KeyTarget)
		want   string
	}{
		"not root":          {func(h *Host, _ KeyTarget) { h.EUID = int(h.RootUID) + 1 }, "sudo"},
		"root without sudo": {func(h *Host, _ KeyTarget) { h.SudoUID = "" }, "SUDO_UID"},
		"sudo from root":    {func(h *Host, _ KeyTarget) { h.SudoUID = "0" }, "SUDO_UID"},
		"noncanonical uid":  {func(h *Host, _ KeyTarget) { h.SudoUID = "0501" }, "SUDO_UID"},
		"not console user":  {func(h *Host, _ KeyTarget) { h.ConsoleUID = func() (uint32, error) { return 502, nil } }, "screen"},
		"not deploy.env user": {func(h *Host, _ KeyTarget) {
			h.SudoUID = "502"
			h.ConsoleUID = func() (uint32, error) { return 502, nil }
		}, "OWNER_UID"},
		"no deploy-install": {func(h *Host, k KeyTarget) {
			_ = os.Remove(filepath.Join(k.Root, "config", "deploy.env"))
		}, "deploy-install"},
		"approved": {func(h *Host, k KeyTarget) {
			_ = os.WriteFile(filepath.Join(k.Root, "config", "activation-anchor.json"), []byte("{}"), 0o644)
		}, "requalification"},
		"existing key": {func(h *Host, k KeyTarget) {
			_ = os.WriteFile(k.Path(), []byte("old"), 0o600)
		}, "already installed"},
	} {
		t.Run(name, func(t *testing.T) {
			h, target := hostFixture(t)
			tc.mutate(&h, target)
			if _, err := Prepare(h); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
