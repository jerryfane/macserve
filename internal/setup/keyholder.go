package setup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/keyholder"
	"github.com/jerryfane/macserve/internal/workerclient"
)

// The keyholder migration (macserve upgrade, full requalification path).
// An installation from before the keyholder has the receipt key and the
// GitHub App key controller-owned in var/controller/secrets, no keyholder
// account and no KEYHOLDER_* IDs in deploy.env. After the binaries are
// replaced and before the release is finished, requalify brings it to the
// layout deploy-install now creates, in this order, each step idempotent so
// an interrupted upgrade resumes where it stopped:
//
//	ids        pick free system IDs (dscl), record the new deploy.env in
//	           the release, write it, then record it as the install's
//	accounts   create-users.sh --keyholder-only (creates, or re-verifies
//	           and re-applies the directories when the account exists)
//	seal key   var/broker/seal-key.pem, root 0600, if absent
//	move       receipt-key.pem, github-app.pem and the full receipt
//	           manifests into the keyholder's state, keyholder-owned 0600;
//	           each copy is created exclusively, synced and read back
//	           before the controller's copy is removed
//	configs    keyholder.json, the worker.json lease fields, controller.json
//	           (key paths and the keyholder section; every other field
//	           keeps its decoded value)
//	plist      the disabled org.macserve.keyholder.plist, last: its
//	           presence marks a finished migration
//
// Nothing here starts a service; qualification starts again afterwards.

// keyholderMigrated reports whether the installation has the keyholder:
// its IDs in deploy.env and its plist (the migration's last step).
func (h *Helper) keyholderMigrated(e deploy.Environment) (bool, error) {
	if !e.Keyholder() {
		return false, nil
	}
	_, err := os.Lstat(h.daemonPlist(deploy.KeyholderLabel))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// installPath maps a deploy layout path to this helper's Root (equal
// outside tests).
func (h *Helper) installPath(path string) string {
	return filepath.Join(h.Root, strings.TrimPrefix(path, deploy.Prefix))
}

// ChownFile sets the owner and group of f and verifies them on the
// descriptor. It is the production Helper.Chown.
func ChownFile(f *os.File, uid, gid uint32) error {
	if err := f.Chown(int(uid), int(gid)); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	u, g, _, ok := statOwner(info)
	if !ok || u != uid || g != gid {
		return fmt.Errorf("%s is not owned by %d:%d after chown", f.Name(), uid, gid)
	}
	return nil
}

// migrateKeyholder runs the migration unless it is done.
func (h *Helper) migrateKeyholder(ctx context.Context, l *Ledger, loc LedgerLocation, e deploy.Environment) error {
	if done, err := h.keyholderMigrated(e); err != nil || done {
		return err
	}
	e, err := h.keyholderEnvironment(ctx, l, loc, e)
	if err != nil {
		return fmt.Errorf("keyholder IDs: %w", err)
	}
	if err := h.createKeyholder(ctx, e); err != nil {
		return fmt.Errorf("keyholder account: %w", err)
	}
	sealPublic, err := h.sealKey()
	if err != nil {
		return fmt.Errorf("worker seal key: %w", err)
	}
	controllerData, err := h.readConfig("controller.json", 1<<20)
	if err != nil {
		return err
	}
	var c controllerconfig.Config
	if err := decodeStrictJSON(controllerData, &c); err != nil {
		return fmt.Errorf("controller.json: %w", err)
	}
	// Refuse a controller.json the migration cannot rewrite before any key
	// moves.
	if _, err := migratedControllerConfig(controllerData, h.Root, e); err != nil {
		return fmt.Errorf("controller.json: %w", err)
	}
	if err := h.moveKeyholderFiles(e, c.GitHub != nil); err != nil {
		return fmt.Errorf("move the keys to the keyholder: %w", err)
	}
	sealID := deploy.SealKeyID(c.Receipt.HostID)
	k := deploy.KeyholderConfig(e, sealID, sealPublic)
	k.StateDir, k.Socket = h.installPath(k.StateDir), h.installPath(k.Socket)
	k.ControllerConfig, k.ReleaseScopeFile = h.installPath(k.ControllerConfig), h.installPath(k.ReleaseScopeFile)
	if err := k.Validate(); err != nil {
		return err
	}
	keyholderJSON, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	if err := h.writeOnce(h.configPath("keyholder.json"), append(keyholderJSON, '\n')); err != nil {
		return err
	}
	if err := h.migrateConfig("worker.json", func(data []byte) ([]byte, error) {
		return migratedWorkerConfig(data, h.installPath(deploy.ProfilesPath), h.installPath(deploy.QualificationPath), h.installPath(deploy.SealKeyPath), sealID)
	}, func(path string) error {
		_, err := workerclient.LoadConfig(path)
		return err
	}); err != nil {
		return err
	}
	if err := h.migrateConfig("controller.json", func(data []byte) ([]byte, error) {
		return migratedControllerConfig(data, h.Root, e)
	}, func(path string) error {
		_, err := controllerconfig.LoadConfig(path)
		return err
	}); err != nil {
		return err
	}
	plist, err := deploy.RenderKeyholderPlist(h.Assets)
	if err != nil {
		return err
	}
	if err := h.writeOnce(h.daemonPlist(deploy.KeyholderLabel), plist); err != nil {
		return err
	}
	h.audit(VerbUpgrade, "keyholder migrated", nil)
	return nil
}

// keyholderEnvironment adds the keyholder's IDs to deploy.env when it has
// none. The new deploy.env is recorded in the release before it is
// written, and recorded as the install step's afterwards, so an
// interrupted run resumes with either file.
func (h *Helper) keyholderEnvironment(ctx context.Context, l *Ledger, loc LedgerLocation, e deploy.Environment) (deploy.Environment, error) {
	data, err := h.readConfig("deploy.env", deploy.MaxEnvironment)
	if err != nil {
		return e, err
	}
	rel := l.PendingRelease()
	if rel == nil {
		return e, errors.New("the keyholder migration runs only inside an upgrade")
	}
	if !e.Keyholder() {
		taken, err := h.directoryIDs(ctx)
		if err != nil {
			return e, err
		}
		for id := range e.TakenIDs() {
			taken[id] = true
		}
		uid, gid, rpc, err := deploy.PickKeyholderIDs(taken)
		if err != nil {
			return e, err
		}
		next, parsed, err := keyholderEnv(data, uid, gid, rpc)
		if err != nil {
			return e, err
		}
		rel.KeyholderEnvSHA256 = digestHex(next)
		if err := h.Store.Save(l, loc); err != nil {
			return e, err
		}
		if err := h.Store.checkAncestors(filepath.Dir(h.configPath("deploy.env"))); err != nil {
			return e, err
		}
		if err := h.Store.writeFile(h.configPath("deploy.env"), next, 0o644); err != nil {
			return e, err
		}
		h.audit(VerbUpgrade, fmt.Sprintf("config/deploy.env: keyholder uid/gid %d, RPC gid %d", uid, rpc), nil)
		data, e = next, parsed
	}
	if d := digestHex(data); l.record(StepInstall).Inputs["deploy.env"] != d {
		l.record(StepInstall).Inputs["deploy.env"] = d
		if err := h.Store.Save(l, loc); err != nil {
			return e, err
		}
	}
	return e, nil
}

// keyholderEnv appends the keyholder's IDs to deploy.env data and parses
// the result, which must name exactly those IDs and nothing else new.
func keyholderEnv(data []byte, uid, gid, rpc uint32) ([]byte, deploy.Environment, error) {
	next := bytes.Clone(data)
	if len(next) > 0 && next[len(next)-1] != '\n' {
		next = append(next, '\n')
	}
	next = append(next, deploy.KeyholderEnvironmentLines(uid, gid, rpc)...)
	parsed, err := deploy.ParseEnvironment(next)
	if err != nil {
		return nil, parsed, fmt.Errorf("deploy.env with the keyholder: %w", err)
	}
	if parsed.KeyholderUID != uid || parsed.KeyholderGID != gid || parsed.KeyRPCGID != rpc {
		return nil, parsed, errors.New("deploy.env does not read back the keyholder IDs")
	}
	return next, parsed, nil
}

// directoryIDs is every user ID, group ID and user primary group of the
// search and local directory nodes, as create-users.sh lists them.
func (h *Helper) directoryIDs(ctx context.Context) (map[int64]bool, error) {
	taken := map[int64]bool{}
	for _, q := range [][2]string{{"/Users", "UniqueID"}, {"/Groups", "PrimaryGroupID"}, {"/Users", "PrimaryGroupID"}} {
		for _, node := range []string{"/Search", "."} {
			argv := []string{"/usr/bin/dscl", node, "-list", q[0], q[1]}
			out, status, err := h.Output(ctx, Cmd{Argv: argv, Env: []string{FixedPath}, Timeout: 30 * time.Second})
			if err == nil && status != 0 {
				err = fmt.Errorf("exit status %d", status)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
			}
			records, err := deploy.ParseDirectoryList(string(out))
			if err != nil {
				return nil, err
			}
			for _, r := range records {
				taken[r.ID] = true
			}
		}
	}
	return taken, nil
}

// createKeyholder runs the release's create-users.sh --keyholder-only.
func (h *Helper) createKeyholder(ctx context.Context, e deploy.Environment) error {
	script, ok := h.Assets["create-users.sh"]
	if !ok {
		return errors.New("the release has no create-users.sh")
	}
	if err := h.Store.EnsureStaging(); err != nil {
		return err
	}
	path := h.Store.staged("create-users.sh")
	if err := h.Store.writePrivate(path, script); err != nil {
		return err
	}
	defer h.Store.removeStaged("create-users.sh")
	argv := append(append([]string{"/bin/bash", path}, deploy.CreateUsersArgs(e)...), deploy.KeyholderArgs(e)...)
	argv = append(argv, "--keyholder-only", "--apply")
	return h.Exec(ctx, Cmd{Argv: argv, Env: []string{FixedPath}, Timeout: 2 * time.Minute})
}

// sealKey returns the worker seal key's base64 public key, creating the
// key (root 0600 Ed25519 PKCS#8 PEM, atomically) when it is absent.
func (h *Helper) sealKey() (string, error) {
	path := h.installPath(deploy.SealKeyPath)
	data, err := h.Store.readPrivate(path, 64<<10)
	if errors.Is(err, fs.ErrNotExist) {
		_, key, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return "", gerr
		}
		der, merr := x509.MarshalPKCS8PrivateKey(key)
		if merr != nil {
			return "", merr
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := h.Store.checkAncestors(filepath.Dir(path)); err != nil {
			return "", err
		}
		if err := h.Store.writePrivate(path, data); err != nil {
			return "", err
		}
		h.audit(VerbUpgrade, "var/broker/seal-key.pem created", nil)
	} else if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("%s is not a PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return "", fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), nil
}

// Bounds of the files the migration moves.
const (
	maxKeyBytes     = 64 << 10
	maxReceiptBytes = 64 << 20
)

// moveKeyholderFiles moves the receipt key, the App key (when
// controller.json has a github section) and the full receipt manifests
// from the controller's directories into the keyholder's. The keyholder
// directories are the ones create-users.sh just created and verified.
func (h *Helper) moveKeyholderFiles(e deploy.Environment, github bool) error {
	secrets, err := h.openPrivateDir(h.installPath(deploy.KeyholderSecretsDir))
	if err != nil {
		return err
	}
	defer secrets.Close()
	controllerSecrets, err := h.openPrivateDir(filepath.Join(h.Root, "var/controller/secrets"))
	if err != nil {
		return err
	}
	defer controllerSecrets.Close()
	m := fileMove{chown: h.Chown, uid: e.KeyholderUID, gid: e.KeyholderGID}
	for _, name := range []string{keyholder.ReceiptKeyName, keyholder.AppKeyName} {
		err := m.move(controllerSecrets, secrets, name, maxKeyBytes, true)
		switch {
		case errors.Is(err, fs.ErrNotExist) && (name == keyholder.AppKeyName && !github):
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%s is in neither the controller's nor the keyholder's secrets; reconcile by hand", name)
		case err != nil:
			return fmt.Errorf("%s: %w", name, err)
		default:
			h.audit(VerbUpgrade, name+" held by the keyholder", nil)
		}
	}
	controllerReceipts := filepath.Join(h.Root, "var/controller/receipts")
	if _, err := os.Lstat(controllerReceipts); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	from, err := h.openPrivateDir(controllerReceipts)
	if err != nil {
		return err
	}
	defer from.Close()
	to, err := h.openPrivateDir(h.installPath(deploy.KeyholderReceiptsDir))
	if err != nil {
		return err
	}
	defer to.Close()
	names, err := receiptNames(from)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := m.move(from, to, name, maxReceiptBytes, false); err != nil {
			return fmt.Errorf("receipt %s: %w", name, err)
		}
	}
	if len(names) > 0 {
		h.audit(VerbUpgrade, fmt.Sprintf("%d receipt manifests held by the keyholder", len(names)), nil)
	}
	return nil
}

// receiptNames lists the full receipt manifests (*.json, never a hidden
// pending write) of a controller receipts directory.
func receiptNames(dir *os.Root) ([]string, error) {
	d, err := dir.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	all, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, name := range all {
		if strings.HasSuffix(name, ".json") && !strings.HasPrefix(name, ".") {
			names = append(names, name)
		}
	}
	return names, nil
}

// openPrivateDir opens dir below Root/var, which must be protected root
// directories; dir and every directory between are real directories,
// never symlinks.
func (h *Helper) openPrivateDir(dir string) (*os.Root, error) {
	base := filepath.Join(h.Root, "var")
	if err := h.Store.checkAncestors(base); err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(base, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("%s is not below %s", dir, base)
	}
	current := base
	var last fs.FileInfo
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is not a real directory", current)
		}
		last = info
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if opened, err := root.Stat("."); err != nil || !os.SameFile(opened, last) {
		root.Close()
		return nil, fmt.Errorf("%s changed while it was opened", dir)
	}
	return root, nil
}

// fileMove moves files into a keyholder directory as new files owned by
// uid:gid, mode 0600.
type fileMove struct {
	chown    func(*os.File, uint32, uint32) error
	uid, gid uint32
}

// move moves name from src to dst. The copy is written under a hidden
// temporary name, owned, synced and linked to name (never replacing an
// entry), and read back before the source is removed. A copy an
// interrupted run left behind is kept when it holds the source's bytes,
// and refused otherwise. fs.ErrNotExist: neither has it.
func (m fileMove) move(src, dst *os.Root, name string, max int64, singleLink bool) error {
	temp := "." + name + ".migrating"
	if err := dst.Remove(temp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	data, srcErr := readMovable(src, name, max, singleLink)
	if srcErr != nil && !errors.Is(srcErr, fs.ErrNotExist) {
		return srcErr
	}
	existing, dstErr := readMovable(dst, name, max, true)
	if dstErr != nil && !errors.Is(dstErr, fs.ErrNotExist) {
		return dstErr
	}
	switch {
	case srcErr != nil && dstErr != nil:
		return fs.ErrNotExist
	case srcErr != nil:
		return nil
	case dstErr == nil:
		if subtle.ConstantTimeCompare(existing, data) != 1 {
			return fmt.Errorf("the keyholder already holds a different %s; reconcile by hand", name)
		}
	default:
		if err := m.write(dst, temp, name, data); err != nil {
			return err
		}
	}
	if err := src.Remove(name); err != nil {
		return err
	}
	return syncRoot(src)
}

// write creates temp exclusively, links it to name and checks name.
func (m fileMove) write(dst *os.Root, temp, name string, data []byte) error {
	f, err := dst.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if err := errors.Join(werr, m.chown(f, m.uid, m.gid), f.Chmod(0o600), f.Sync(), f.Close()); err != nil {
		dst.Remove(temp)
		return err
	}
	if err := dst.Link(temp, name); err != nil {
		dst.Remove(temp)
		return err
	}
	if err := dst.Remove(temp); err != nil {
		return err
	}
	if err := syncRoot(dst); err != nil {
		return err
	}
	back, err := readMovable(dst, name, int64(len(data)), true)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(back, data) != 1 {
		return fmt.Errorf("%s does not read back", name)
	}
	return nil
}

// readMovable reads a regular file of root without following a link: at
// most max bytes, no group or other access, and one link if singleLink.
func readMovable(root *os.Root, name string, max int64, singleLink bool) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	_, _, nlink, ok := statOwner(info)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > max || singleLink && nlink != 1 {
		return nil, fmt.Errorf("%s must be a private regular file of at most %d bytes", name, max)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if opened, err := f.Stat(); err != nil || !os.SameFile(opened, info) {
		return nil, fmt.Errorf("%s changed while it was read", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("%s changed while it was read", name)
	}
	return data, nil
}

func syncRoot(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// writeOnce installs data at path (root, 0644) unless path holds exactly
// data already; other content is refused, never replaced.
func (h *Helper) writeOnce(path string, data []byte) error {
	if err := h.Store.checkAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	existing, err := h.Store.readOutput(path, 1<<20)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := h.Store.writeFile(path, data, 0o644); err != nil {
			return err
		}
		h.audit(VerbUpgrade, path+" installed", nil)
		return nil
	case err != nil:
		return err
	case !bytes.Equal(existing, data):
		return fmt.Errorf("%s exists with other content; reconcile by hand", path)
	}
	return nil
}

// migrateConfig rewrites config/name with edit when that changes it; the
// result must load with its consumer (staged first) before it replaces
// the file atomically.
func (h *Helper) migrateConfig(name string, edit func([]byte) ([]byte, error), load func(string) error) error {
	data, err := h.readConfig(name, 1<<20)
	if err != nil {
		return err
	}
	next, err := edit(data)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if bytes.Equal(next, data) {
		return nil
	}
	if err := h.Store.EnsureStaging(); err != nil {
		return err
	}
	staged := h.Store.staged(name)
	if err := h.Store.writePrivate(staged, next); err != nil {
		return err
	}
	defer h.Store.removeStaged(name)
	if err := load(staged); err != nil {
		return fmt.Errorf("the migrated %s would not load: %w", name, err)
	}
	if err := h.Store.writeFile(h.configPath(name), next, 0o644); err != nil {
		return err
	}
	h.audit(VerbUpgrade, "config/"+name+" migrated to the keyholder", nil)
	return nil
}

func decodeStrictJSON(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func indentJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// migratedControllerConfig points controller.json's receipt and github
// keys at the keyholder's secrets and adds the keyholder section. A key
// path must be the controller's deploy layout path or already the
// keyholder's; a keyholder section must already be this one. Every other
// field keeps its decoded value; an already migrated file is returned
// unchanged.
func migratedControllerConfig(data []byte, root string, e deploy.Environment) ([]byte, error) {
	var c controllerconfig.Config
	if err := decodeStrictJSON(data, &c); err != nil {
		return nil, err
	}
	at := func(path string) string { return filepath.Join(root, strings.TrimPrefix(path, deploy.Prefix)) }
	changed := false
	key := func(field *string, name string) error {
		old, next := filepath.Join(root, "var/controller/secrets", name), at(deploy.KeyholderSecretsDir+"/"+name)
		switch *field {
		case next:
		case old:
			*field, changed = next, true
		default:
			return fmt.Errorf("%s is not the deployed %s; reconcile by hand", *field, name)
		}
		return nil
	}
	if err := key(&c.Receipt.PrivateKeyFile, keyholder.ReceiptKeyName); err != nil {
		return nil, err
	}
	if c.GitHub != nil {
		if err := key(&c.GitHub.PrivateKeyFile, keyholder.AppKeyName); err != nil {
			return nil, err
		}
	}
	section := controllerconfig.KeyholderConfig{Socket: at(deploy.KeyholderSocket), UID: e.KeyholderUID}
	switch {
	case c.Keyholder == nil:
		c.Keyholder, changed = &section, true
	case *c.Keyholder != section:
		return nil, errors.New("controller.json names another keyholder; reconcile by hand")
	}
	if !changed {
		return data, nil
	}
	return indentJSON(c)
}

// migratedWorkerConfig adds the lease fields to worker.json: the profile
// registry, the qualification record and the seal key. Fields already
// set must have these values; every other field keeps its decoded value,
// and an already migrated file is returned unchanged.
func migratedWorkerConfig(data []byte, profiles, qualification, sealKey, sealID string) ([]byte, error) {
	var w workerclient.Config
	if err := decodeStrictJSON(data, &w); err != nil {
		return nil, err
	}
	want := [][2]*string{{&w.ProfilesFile, &profiles}, {&w.QualificationFile, &qualification}, {&w.SealKeyFile, &sealKey}, {&w.SealKeyID, &sealID}}
	changed := false
	for _, f := range want {
		switch *f[0] {
		case *f[1]:
		case "":
			*f[0], changed = *f[1], true
		default:
			return nil, fmt.Errorf("worker.json names %s, not %s; reconcile by hand", *f[0], *f[1])
		}
	}
	if !changed {
		return data, nil
	}
	return indentJSON(w)
}
