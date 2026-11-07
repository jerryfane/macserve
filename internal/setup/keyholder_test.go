package setup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/assets"
	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/keyholder"
	"github.com/jerryfane/macserve/internal/onboarding"
	"github.com/jerryfane/macserve/internal/workerclient"
)

// oldEnv is testEnv as deploy-install wrote it before the keyholder.
func oldEnv(owner Owner) string {
	return strings.Replace(testEnv(owner), "KEYHOLDER_UID=499\nKEYHOLDER_GID=499\nKEYRPC_GID=498\n", "", 1)
}

// migrationHost is an upgradeHost whose installation is from before the
// keyholder: deploy.env without KEYHOLDER_*, the receipt and App keys and
// two receipt manifests (one hard-linked pair) controller-owned in
// var/controller, controller.json naming them without a keyholder section,
// worker.json without the lease fields and no keyholder plist. dscl lists
// 499 as taken; create-users.sh --keyholder-only creates the keyholder's
// directories; Chown records instead of changing owners.
type migrationHost struct {
	*upgradeHost
	chowns     []string
	createRuns int
	appKey     []byte
	receiptKey []byte
	// precopied names a file an interrupted run had already copied.
	precopied string
}

func newMigrationHost(t *testing.T) *migrationHost {
	t.Helper()
	m := &migrationHost{upgradeHost: newUpgradeHost(t), appKey: []byte("-----BEGIN RSA PRIVATE KEY-----\napp\n-----END RSA PRIVATE KEY-----\n"), receiptKey: []byte("-----BEGIN PRIVATE KEY-----\nreceipt\n-----END PRIVATE KEY-----\n")}
	h, root := m.h, m.h.Root
	env := oldEnv(h.Owner)
	writeRoot(t, h.configPath("deploy.env"), []byte(env), 0o644)
	l := m.ledger()
	l.record(StepInstall).Inputs["deploy.env"] = digestHex([]byte(env))
	if err := h.Store.Save(l, LedgerInstalled); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.daemonPlist(deploy.KeyholderLabel)); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "var/keyholder")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"var/controller/secrets", "var/controller/receipts", "var/broker"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secrets := filepath.Join(root, "var/controller/secrets")
	writeRoot(t, filepath.Join(secrets, "tls-key.pem"), []byte("tls"), 0o600)
	writeRoot(t, filepath.Join(secrets, "receipt-key.pem"), m.receiptKey, 0o600)
	writeRoot(t, filepath.Join(secrets, "github-app.pem"), m.appKey, 0o600)
	receipts := filepath.Join(root, "var/controller/receipts")
	writeRoot(t, filepath.Join(receipts, "job1.json"), []byte(`{"receipt":1}`), 0o600)
	if err := os.Link(filepath.Join(receipts, "job1.json"), filepath.Join(receipts, "sha-1.json")); err != nil {
		t.Fatal(err)
	}
	writeRoot(t, filepath.Join(receipts, ".pending.tmp"), []byte("partial"), 0o600)
	c := m.controllerConfig()
	c.Keyholder = nil
	c.Receipt.PrivateKeyFile = filepath.Join(secrets, "receipt-key.pem")
	c.GitHub = onboarding.Enrollment{AppID: 77, InstallationID: 555, Repository: "jdoe/myapp", RepositoryID: 4242, AuthorIDs: []int64{1001}, BaseBranches: []string{"main"}, Profiles: []string{"myapp-build-v1"}}.Section(filepath.Join(secrets, "github-app.pem"))
	writeJSON(t, h.configPath("controller.json"), c)
	writeJSON(t, h.configPath("worker.json"), oldWorker(root))
	if _, err := controllerconfig.LoadConfig(h.configPath("controller.json")); err != nil {
		t.Fatalf("pre-keyholder controller.json fixture: %v", err)
	}
	plist, err := fs.ReadFile(assets.Deploy, "launchd/org.macserve.keyholder.plist.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	h.Assets["launchd/org.macserve.keyholder.plist.tmpl"] = plist
	h.Assets["create-users.sh"] = []byte("#!/bin/bash\n# release create-users.sh\n")
	h.Chown = func(f *os.File, uid, gid uint32) error {
		m.chowns = append(m.chowns, filepath.Base(f.Name())+":"+itoa(uid)+":"+itoa(gid))
		return nil
	}
	output := h.Output
	h.Output = func(ctx context.Context, c Cmd) ([]byte, int, error) {
		if c.Argv[0] == "/usr/bin/dscl" {
			m.outputs = append(m.outputs, c.Argv)
			return []byte("root 0\n_taken 499\n"), 0, nil
		}
		return output(ctx, c)
	}
	exec := h.Exec
	h.Exec = func(ctx context.Context, c Cmd) error {
		if len(c.Argv) > 1 && strings.HasSuffix(c.Argv[1], "create-users.sh") {
			m.createRuns++
			m.execs = append(m.execs, c.Argv)
			if data, err := os.ReadFile(c.Argv[1]); err != nil || !bytes.Equal(data, h.Assets["create-users.sh"]) {
				t.Errorf("create-users.sh staged %q %v", data, err)
			}
			for _, dir := range []string{"var/keyholder/secrets", "var/keyholder/receipts", "var/keyholder/release", "var/keyholder/log", "var/keyholder-run"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
					return err
				}
			}
			return nil
		}
		return exec(ctx, c)
	}
	return m
}

func oldWorker(root string) workerclient.Config {
	return workerclient.Config{Socket: root + "/var/controller/run/worker.sock", ControllerUID: 6201, Root: root + "/var/broker", ExportRoot: root + "/var/exports", WorkspaceRoot: root + "/var/workspaces", JobUID: 6202, JobGID: 6202, OwnerUID: 501, HelperPath: root + "/bin/macserve", BaselinePath: root + "/var/broker/gui-baseline.json", PersistencePath: root + "/var/broker/reviewed-persistence.json", PollSeconds: 2, HeartbeatSeconds: 5, RequestTimeoutSeconds: 10}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeRoot(t, path, append(data, '\n'), 0o644)
}

func readJSON[T any](t *testing.T, path string) T {
	t.Helper()
	var v T
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(data, &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

// wantMigrated checks the installation has the keyholder layout.
func (m *migrationHost) wantMigrated() {
	t, h, root := m.t, m.h, m.h.Root
	t.Helper()
	env, err := deploy.LoadEnvironment(h.configPath("deploy.env"))
	if err != nil {
		t.Fatal(err)
	}
	if env.KeyholderUID != 498 || env.KeyholderGID != 498 || env.KeyRPCGID != 497 {
		t.Fatalf("keyholder IDs %d/%d/%d (499 is taken)", env.KeyholderUID, env.KeyholderGID, env.KeyRPCGID)
	}
	data, _ := os.ReadFile(h.configPath("deploy.env"))
	if !strings.HasPrefix(string(data), oldEnv(h.Owner)) {
		t.Fatal("deploy.env lost its reviewed lines")
	}
	if got := m.ledger().record(StepInstall).Inputs["deploy.env"]; got != digestHex(data) {
		t.Fatal("the install record does not name the migrated deploy.env")
	}
	for name, want := range map[string][]byte{"secrets/receipt-key.pem": m.receiptKey, "secrets/github-app.pem": m.appKey, "receipts/job1.json": []byte(`{"receipt":1}`), "receipts/sha-1.json": []byte(`{"receipt":1}`)} {
		path := filepath.Join(root, "var/keyholder", name)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		_, _, nlink, _ := statOwner(info)
		if got, _ := os.ReadFile(path); !bytes.Equal(got, want) || info.Mode() != 0o600 || nlink != 1 {
			t.Fatalf("%s: %q mode %v links %d", name, got, info.Mode(), nlink)
		}
	}
	for _, name := range []string{"secrets/receipt-key.pem", "secrets/github-app.pem", "receipts/job1.json", "receipts/sha-1.json"} {
		if _, err := os.Lstat(filepath.Join(root, "var/controller", name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("controller copy of %s survived: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "var/controller/receipts/.pending.tmp")); err != nil {
		t.Fatal("a pending controller write was moved")
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "var/controller/secrets")); len(entries) != 1 || entries[0].Name() != "tls-key.pem" {
		t.Fatalf("controller secrets %v", entries)
	}
	for _, name := range []string{"receipt-key.pem", "github-app.pem", "job1.json", "sha-1.json"} {
		if name != m.precopied && !slices.Contains(m.chowns, "."+name+".migrating:498:498") {
			t.Fatalf("%s not given to the keyholder: %q", name, m.chowns)
		}
	}
	c, err := controllerconfig.LoadConfig(h.configPath("controller.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := m.controllerConfig()
	if c.Receipt.PrivateKeyFile != root+"/var/keyholder/secrets/receipt-key.pem" || c.GitHub.PrivateKeyFile != root+"/var/keyholder/secrets/github-app.pem" {
		t.Fatalf("controller key paths %s %s", c.Receipt.PrivateKeyFile, c.GitHub.PrivateKeyFile)
	}
	if c.Keyholder == nil || *c.Keyholder != (controllerconfig.KeyholderConfig{Socket: root + "/var/keyholder-run/keyholder.sock", UID: 498}) {
		t.Fatalf("keyholder section %+v", c.Keyholder)
	}
	if c.TLSKey != want.TLSKey || c.Listen != want.Listen || c.GitHub.AppID != 77 || c.Receipt.HostID != "host" {
		t.Fatal("controller.json changed beyond the keys and the keyholder")
	}
	sealPEM, err := h.Store.readPrivate(filepath.Join(root, "var/broker/seal-key.pem"), 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(sealPEM)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sealPub := base64.StdEncoding.EncodeToString(parsed.(ed25519.PrivateKey).Public().(ed25519.PublicKey))
	w, err := workerclient.LoadConfig(h.configPath("worker.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.LeaseAuthority(); err != nil || w.SealKeyFile != root+"/var/broker/seal-key.pem" || w.SealKeyID != "macserve-worker-host" || w.ProfilesFile != h.configPath("profiles.json") || w.QualificationFile != h.configPath("qualification.json") {
		t.Fatalf("worker.json %+v %v", w, err)
	}
	w.ProfilesFile, w.QualificationFile, w.SealKeyFile, w.SealKeyID = "", "", "", ""
	if w != oldWorker(root) {
		t.Fatal("worker.json changed beyond the lease fields")
	}
	k, err := keyholder.LoadConfig(h.configPath("keyholder.json"))
	if err != nil {
		t.Fatal(err)
	}
	if k.KeyholderUID != 498 || k.RPCGID != 497 || k.ControllerUID != 6201 || k.StateDir != root+"/var/keyholder" || k.ReleaseScopeFile != h.configPath("release-scope.json") || len(k.SealKeys) != 1 || k.SealKeys["macserve-worker-host"] != sealPub {
		t.Fatalf("keyholder.json %+v", k)
	}
	plist, err := os.ReadFile(h.daemonPlist(deploy.KeyholderLabel))
	if err != nil || !bytes.Equal(plist, h.Assets["launchd/org.macserve.keyholder.plist.tmpl"]) {
		t.Fatalf("keyholder plist: %v", err)
	}
	if err := h.checkDisabledPlist(deploy.KeyholderLabel); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeMigratesToKeyholder(t *testing.T) {
	m := newMigrationHost(t)
	r := m.upgrade(Request{})
	if r.Error != "" || !r.Done || !slices.Equal(r.Items, []string{EffectRequalify}) {
		t.Fatalf("upgrade %+v", r)
	}
	m.wantRequalified("")
	m.wantMigrated()
	if m.createRuns != 1 {
		t.Fatalf("create-users.sh ran %d times", m.createRuns)
	}
	argv := m.execs[len(m.execs)-1]
	if !slices.Equal(argv[len(argv)-8:], []string{"--keyholder-uid", "498", "--keyholder-gid", "498", "--keyrpc-gid", "497", "--keyholder-only", "--apply"}) || !slices.Contains(argv, "--controller-uid") {
		t.Fatalf("create-users.sh %q", argv)
	}
	if _, err := os.Lstat(m.h.Store.staged("create-users.sh")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("staged create-users.sh left behind")
	}
	// A completed migration is never repeated: the next release upgrades
	// without dscl or create-users.sh.
	e, _, err := m.h.installedEnv(m.ledger())
	if err != nil {
		t.Fatal(err)
	}
	if done, err := m.h.keyholderMigrated(e); !done || err != nil {
		t.Fatalf("migration not recorded as done: %v", err)
	}
}

// A release with a carry proof cannot carry an installation the migration
// changes: it requalifies (with the job-session guard).
func TestUpgradeKeyholderMigrationRefusesCarry(t *testing.T) {
	m := newMigrationHost(t)
	r := m.upgrade(m.carryRequest(true))
	if r.Error != "" || !r.Done || !slices.Equal(r.Items, []string{EffectRequalify}) {
		t.Fatalf("upgrade %+v", r)
	}
	m.wantRequalified("keyholder migration")
	m.wantMigrated()
	if len(m.carried) != 0 {
		t.Fatalf("carry verbs ran: %q", m.carried)
	}
}

// The migration resumes after an interruption at any step: here after the
// IDs, the account and the receipt key's copy, with the controller's
// receipt key still in place and a temporary App key copy left behind.
func TestUpgradeKeyholderMigrationResumes(t *testing.T) {
	m := newMigrationHost(t)
	fail := errors.New("power lost")
	h := m.h
	exec := h.Exec
	h.Exec = func(ctx context.Context, c Cmd) error {
		if err := exec(ctx, c); err != nil {
			return err
		}
		if strings.HasSuffix(c.Argv[1], "create-users.sh") && m.createRuns == 1 {
			// The interrupted run had copied the receipt key and created the
			// seal key; then it stopped.
			writeRoot(t, filepath.Join(h.Root, "var/keyholder/secrets/receipt-key.pem"), m.receiptKey, 0o600)
			m.precopied = "receipt-key.pem"
			writeRoot(t, filepath.Join(h.Root, "var/keyholder/secrets/.github-app.pem.migrating"), []byte("partial"), 0o600)
			return fail
		}
		return nil
	}
	if r := m.upgrade(Request{}); !strings.Contains(r.Error, "power lost") || !strings.Contains(r.Error, "run macserve upgrade again") {
		t.Fatalf("interrupted upgrade %+v", r)
	}
	if rel := m.ledger().PendingRelease(); rel == nil || rel.KeyholderEnvSHA256 == "" {
		t.Fatalf("pending release %+v", rel)
	}
	r := m.upgrade(Request{})
	if r.Error != "" || !r.Done {
		t.Fatalf("resumed upgrade %+v", r)
	}
	m.wantRequalified("")
	m.wantMigrated()
	if m.createRuns != 2 {
		t.Fatalf("create-users.sh ran %d times, want the resume to re-verify", m.createRuns)
	}
	if _, err := os.Lstat(filepath.Join(h.Root, "var/keyholder/secrets/.github-app.pem.migrating")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("interrupted temporary copy left behind")
	}
}

func TestUpgradeKeyholderMigrationRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		prepare func(m *migrationHost)
		want    string
	}{
		"different keyholder copy": {func(m *migrationHost) {
			exec := m.h.Exec
			m.h.Exec = func(ctx context.Context, c Cmd) error {
				err := exec(ctx, c)
				if strings.HasSuffix(c.Argv[1], "create-users.sh") {
					writeRoot(m.t, filepath.Join(m.h.Root, "var/keyholder/secrets/receipt-key.pem"), []byte("other"), 0o600)
				}
				return err
			}
		}, "different receipt-key.pem"},
		"missing receipt key": {func(m *migrationHost) {
			os.Remove(filepath.Join(m.h.Root, "var/controller/secrets/receipt-key.pem"))
		}, "neither"},
		"linked key": {func(m *migrationHost) {
			os.Link(filepath.Join(m.h.Root, "var/controller/secrets/receipt-key.pem"), filepath.Join(m.h.Root, "var/controller/secrets/copy"))
		}, "private regular file"},
		"readable key": {func(m *migrationHost) {
			os.Chmod(filepath.Join(m.h.Root, "var/controller/secrets/github-app.pem"), 0o640)
		}, "private regular file"},
		"symlinked key": {func(m *migrationHost) {
			path := filepath.Join(m.h.Root, "var/controller/secrets/receipt-key.pem")
			os.Rename(path, path+".real")
			os.Symlink(path+".real", path)
		}, "private regular file"},
		"foreign key path": {func(m *migrationHost) {
			c := readJSON[controllerconfig.Config](m.t, m.h.configPath("controller.json"))
			c.Receipt.PrivateKeyFile = m.h.Root + "/elsewhere/receipt-key.pem"
			writeJSON(m.t, m.h.configPath("controller.json"), c)
		}, "not the deployed receipt-key.pem"},
		"no free IDs": {func(m *migrationHost) {
			output := m.h.Output
			m.h.Output = func(ctx context.Context, c Cmd) ([]byte, int, error) {
				if c.Argv[0] != "/usr/bin/dscl" {
					return output(ctx, c)
				}
				var b strings.Builder
				for id := 200; id <= 499; id++ {
					b.WriteString("u" + itoa(uint32(id)) + " " + itoa(uint32(id)) + "\n")
				}
				return []byte(b.String()), 0, nil
			}
		}, "no two free system IDs"},
		"ambiguous directory": {func(m *migrationHost) {
			output := m.h.Output
			m.h.Output = func(ctx context.Context, c Cmd) ([]byte, int, error) {
				if c.Argv[0] == "/usr/bin/dscl" {
					return []byte("a b c\n"), 0, nil
				}
				return output(ctx, c)
			}
		}, "ambiguous"},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMigrationHost(t)
			tc.prepare(m)
			if r := m.upgrade(Request{}); !strings.Contains(r.Error, tc.want) {
				t.Fatalf("got %+v, want %q", r, tc.want)
			}
			if _, err := os.Lstat(m.h.daemonPlist(deploy.KeyholderLabel)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("a refused migration installed the keyholder plist")
			}
		})
	}
}

func TestMigratedControllerConfig(t *testing.T) {
	root := "/Library/macserve"
	e := deploy.Environment{KeyholderUID: 498}
	old := controllerconfig.Config{Root: root + "/var/controller", TLSKey: root + "/var/controller/secrets/tls-key.pem", OwnerUID: 501,
		Receipt: controllerconfig.ReceiptConfig{KeyID: "k1", PrivateKeyFile: root + "/var/controller/secrets/receipt-key.pem", HostID: "h"},
		GitHub:  &controllerconfig.GitHubConfig{AppID: 7, PrivateKeyFile: root + "/var/controller/secrets/github-app.pem"}}
	data, _ := json.Marshal(old)
	next, err := migratedControllerConfig(data, root, e)
	if err != nil {
		t.Fatal(err)
	}
	var c controllerconfig.Config
	if err := decodeStrictJSON(next, &c); err != nil {
		t.Fatal(err)
	}
	if c.Receipt.PrivateKeyFile != deploy.KeyholderReceiptKey || c.GitHub.PrivateKeyFile != deploy.KeyholderAppKey || *c.Keyholder != *deploy.KeyholderSection(deploy.Environment{KeyholderUID: 498}) {
		t.Fatalf("%+v", c)
	}
	c.Receipt.PrivateKeyFile, c.GitHub.PrivateKeyFile, c.Keyholder = old.Receipt.PrivateKeyFile, old.GitHub.PrivateKeyFile, nil
	again, _ := json.Marshal(c)
	if !bytes.Equal(again, data) {
		t.Fatalf("other fields changed:\n%s\n%s", again, data)
	}
	if same, err := migratedControllerConfig(next, root, e); err != nil || !bytes.Equal(same, next) {
		t.Fatalf("migrated file rewritten: %v", err)
	}
	if _, err := migratedControllerConfig(next, root, deploy.Environment{KeyholderUID: 497}); err == nil {
		t.Fatal("accepted another keyholder section")
	}
	noApp := old
	noApp.GitHub = nil
	data, _ = json.Marshal(noApp)
	if next, err = migratedControllerConfig(data, root, e); err != nil || bytes.Contains(next, []byte("github")) {
		t.Fatalf("without github: %s %v", next, err)
	}
}

func TestMigratedWorkerConfig(t *testing.T) {
	data, _ := json.Marshal(oldWorker("/Library/macserve"))
	next, err := migratedWorkerConfig(data, "/p", "/q", "/s", "id")
	if err != nil {
		t.Fatal(err)
	}
	var w workerclient.Config
	if err := decodeStrictJSON(next, &w); err != nil || w.ProfilesFile != "/p" || w.QualificationFile != "/q" || w.SealKeyFile != "/s" || w.SealKeyID != "id" {
		t.Fatalf("%+v %v", w, err)
	}
	if same, err := migratedWorkerConfig(next, "/p", "/q", "/s", "id"); err != nil || !bytes.Equal(same, next) {
		t.Fatalf("migrated worker.json rewritten: %v", err)
	}
	if _, err := migratedWorkerConfig(next, "/p", "/q", "/s", "other"); err == nil {
		t.Fatal("accepted another seal key ID")
	}
}

func TestKeyholderEnv(t *testing.T) {
	old := oldEnv(Owner{UID: 501, Name: "jdoe"})
	next, e, err := keyholderEnv([]byte(strings.TrimSuffix(old, "\n")), 498, 498, 497)
	if err != nil || string(next) != old+"KEYHOLDER_UID=498\nKEYHOLDER_GID=498\nKEYRPC_GID=497\n" || e.KeyholderUID != 498 {
		t.Fatalf("%q %v", next, err)
	}
	if _, _, err := keyholderEnv([]byte(old), 6201, 6201, 497); err == nil {
		t.Fatal("accepted a service ID for the keyholder")
	}
	if _, _, err := keyholderEnv(next, 496, 496, 495); err == nil {
		t.Fatal("added a second keyholder")
	}
}
