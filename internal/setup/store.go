package setup

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// StagingDir is the root helper's root-only directory in root's home. It
// exists before /Library/macserve does: it holds the ledger until install
// has created LedgerDir, the inputs staged for deploy-install and the
// helper's audit log.
const StagingDir = "/private/var/root/.macserve-setup"

// Store is the root helper's file state. Outside tests Staging is
// StagingDir, Ledger is LedgerDir, Top is "/" and RootUID/RootGID are 0
// (root:wheel). Every directory from Top down to Staging and Ledger must be
// owned by RootUID and not writable by group or others.
type Store struct {
	Staging, Ledger, Top string
	RootUID, RootGID     uint32
}

// SystemStore is the production store.
func SystemStore() Store {
	return Store{Staging: StagingDir, Ledger: LedgerDir, Top: "/", RootUID: 0, RootGID: 0}
}

// Ledger locations.
const (
	ledgerName = "ledger.json"
	auditName  = "helper.log"
)

// Staged deploy-install inputs, under Staging.
const (
	stagedEnv    = "deploy.env"
	stagedBinary = "macserve"
	stagedAssets = "assets"
)

func (s Store) staged(name string) string { return filepath.Join(s.Staging, name) }

// statOwner returns the owner, group and link count of info.
func statOwner(info fs.FileInfo) (uid, gid uint32, nlink uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return st.Uid, st.Gid, uint64(st.Nlink), true
}

// checkAncestors requires every directory from s.Top to dir (inclusive) to
// be a real directory owned by RootUID without group or other write.
func (s Store) checkAncestors(dir string) error {
	top := filepath.Clean(s.Top)
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || (dir != top && !strings.HasPrefix(dir, strings.TrimSuffix(top, "/")+"/")) {
		return fmt.Errorf("%s is outside %s", dir, top)
	}
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		uid, _, _, ok := statOwner(info)
		if !ok || !info.IsDir() || uid != s.RootUID || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("unsafe directory %s: it must be a root-owned directory without group or other write", current)
		}
		if current == top {
			return nil
		}
	}
}

// ensureDir creates dir (mode perm) if missing and then requires a real
// directory owned by RootUID:RootGID with exactly perm, below safe
// ancestors. An existing symlink, another owner or another mode is refused,
// never repaired.
func (s Store) ensureDir(dir string, perm fs.FileMode) error {
	if err := s.checkAncestors(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, perm); err == nil {
		// A new directory takes its parent's group on macOS.
		if err := os.Lchown(dir, int(s.RootUID), int(s.RootGID)); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	uid, gid, _, ok := statOwner(info)
	if !ok || info.Mode().Type() != fs.ModeDir || uid != s.RootUID || gid != s.RootGID || info.Mode().Perm() != perm {
		return fmt.Errorf("%s exists but is not a %s:%d directory with mode %#o; macserve setup does not repair it: inspect it, remove it (sudo /bin/rm -rf %s) and run macserve setup again", dir, uidName(s.RootUID), s.RootGID, perm, dir)
	}
	opened, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer opened.Close()
	same, err := opened.Stat()
	if err != nil || !os.SameFile(same, info) {
		return fmt.Errorf("%s changed while it was checked", dir)
	}
	return nil
}

func uidName(uid uint32) string {
	if uid == 0 {
		return "root"
	}
	return fmt.Sprint(uid)
}

// EnsureStaging creates or checks the root-only staging directory.
func (s Store) EnsureStaging() error { return s.ensureDir(s.Staging, 0o700) }

// readPrivate reads a RootUID:RootGID 0600 single-link regular file
// without following links. A missing file returns fs.ErrNotExist.
func (s Store) readPrivate(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	uid, gid, nlink, ok := statOwner(info)
	if !ok || !info.Mode().IsRegular() || uid != s.RootUID || gid != s.RootGID || info.Mode().Perm() != 0o600 || nlink != 1 || info.Size() > max {
		return nil, fmt.Errorf("%s must be a root-owned 0600 single-link regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(opened, info) {
		return nil, fmt.Errorf("%s changed while it was read", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is oversized", path)
	}
	return data, nil
}

// readOutput reads a file a root process (launchd) wrote: a RootUID-owned
// single-link regular file without group or other write, at most max bytes.
func (s Store) readOutput(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	uid, _, nlink, ok := statOwner(info)
	if !ok || !info.Mode().IsRegular() || uid != s.RootUID || info.Mode().Perm()&0o022 != 0 || nlink != 1 || info.Size() > max {
		return nil, fmt.Errorf("%s must be a root-owned single-link regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// writePrivate atomically replaces path with data, RootUID:RootGID 0600.
func (s Store) writePrivate(path string, data []byte) error { return s.writeFile(path, data, 0o600) }

// writeFile atomically replaces path with data, RootUID:RootGID with mode:
// a new temporary file beside it, fsync, rename, fsync of the directory.
func (s Store) writeFile(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	temp := filepath.Join(dir, "."+filepath.Base(path)+"."+hex.EncodeToString(suffix[:]))
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temp)
		}
	}()
	_, werr := f.Write(data)
	if err := errors.Join(werr, f.Chown(int(s.RootUID), int(s.RootGID)), f.Chmod(mode), f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	committed = true
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// LedgerLocation says which copy of the ledger is current.
type LedgerLocation int

const (
	// LedgerNone: no ledger yet.
	LedgerNone LedgerLocation = iota
	// LedgerStaged: the ledger is in Staging (before install finished).
	LedgerStaged
	// LedgerInstalled: the ledger is in Ledger (LedgerDir).
	LedgerInstalled
)

// Load returns the ledger and where it is. Before install has finished it
// is in Staging; after, in Ledger. When both copies exist (a move was
// interrupted) they must be byte-identical, and the staged copy is then
// removed; copies that differ are refused. A staged ledger whose install
// step is done is moved now (the earlier move was interrupted).
func (s Store) Load() (*Ledger, LedgerLocation, error) {
	staged, serr := s.readPrivate(s.staged(ledgerName), MaxLedger)
	if serr != nil && !errors.Is(serr, fs.ErrNotExist) {
		return nil, LedgerNone, serr
	}
	installed, ierr := s.readInstalledLedger()
	if ierr != nil && !errors.Is(ierr, fs.ErrNotExist) {
		return nil, LedgerNone, ierr
	}
	switch {
	case serr == nil && ierr == nil:
		if !bytes.Equal(staged, installed) {
			return nil, LedgerNone, fmt.Errorf("two different setup ledgers exist (%s and %s); macserve setup does not choose one: inspect both", s.staged(ledgerName), filepath.Join(s.Ledger, ledgerName))
		}
		l, err := DecodeLedger(installed)
		if err != nil {
			return nil, LedgerNone, err
		}
		if err := s.removeStaged(ledgerName); err != nil {
			return nil, LedgerNone, err
		}
		return l, LedgerInstalled, nil
	case ierr == nil:
		l, err := DecodeLedger(installed)
		return l, LedgerInstalled, err
	case serr == nil:
		l, err := DecodeLedger(staged)
		if err != nil {
			return nil, LedgerNone, err
		}
		if l.record(StepInstall).Status == StatusDone {
			if err := s.MoveLedger(l); err != nil {
				return nil, LedgerNone, err
			}
			return l, LedgerInstalled, nil
		}
		return l, LedgerStaged, nil
	}
	return nil, LedgerNone, nil
}

func (s Store) readInstalledLedger() ([]byte, error) {
	path := filepath.Join(s.Ledger, ledgerName)
	if _, err := os.Lstat(s.Ledger); err != nil {
		return nil, err
	}
	if err := s.checkAncestors(s.Ledger); err != nil {
		return nil, err
	}
	return s.readPrivate(path, MaxLedger)
}

// Save writes the ledger at loc (LedgerNone writes the staged copy).
func (s Store) Save(l *Ledger, loc LedgerLocation) error {
	data, err := l.Encode()
	if err != nil {
		return err
	}
	if loc == LedgerInstalled {
		if err := s.checkAncestors(s.Ledger); err != nil {
			return err
		}
		return s.writePrivate(filepath.Join(s.Ledger, ledgerName), data)
	}
	if err := s.EnsureStaging(); err != nil {
		return err
	}
	return s.writePrivate(s.staged(ledgerName), data)
}

// MoveLedger moves the ledger from Staging into Ledger after install:
// create Ledger (root-owned 0755, so the unprivileged preflight can see
// that a native ledger exists), write and fsync the ledger there, read it
// back and compare, then remove the staged copy.
func (s Store) MoveLedger(l *Ledger) error {
	data, err := l.Encode()
	if err != nil {
		return err
	}
	if err := s.ensureDir(s.Ledger, 0o755); err != nil {
		return err
	}
	path := filepath.Join(s.Ledger, ledgerName)
	if err := s.writePrivate(path, data); err != nil {
		return err
	}
	back, err := s.readPrivate(path, MaxLedger)
	if err != nil {
		return err
	}
	if sha256.Sum256(back) != sha256.Sum256(data) {
		return errors.New("the moved setup ledger does not read back identically")
	}
	return s.removeStaged(ledgerName)
}

// removeStaged removes one staged file or directory tree.
func (s Store) removeStaged(name string) error {
	if err := os.RemoveAll(s.staged(name)); err != nil {
		return err
	}
	return syncDir(s.Staging)
}

// StageFile writes data as the staged input name (0600), replacing an
// earlier staged copy.
func (s Store) StageFile(name string, data []byte) error {
	if err := s.EnsureStaging(); err != nil {
		return err
	}
	return s.writePrivate(s.staged(name), data)
}

// StagedFile reads back a staged input.
func (s Store) StagedFile(name string, max int64) ([]byte, error) {
	return s.readPrivate(s.staged(name), max)
}

// StageTree replaces the staged directory name with files (relative
// slash paths), directories 0700 and files 0600.
func (s Store) StageTree(name string, files map[string][]byte) error {
	if err := s.EnsureStaging(); err != nil {
		return err
	}
	if err := s.removeStaged(name); err != nil {
		return err
	}
	root := s.staged(name)
	if err := s.ensureDir(root, 0o700); err != nil {
		return err
	}
	for rel, data := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if !strings.HasPrefix(path, root+"/") || filepath.Clean(path) != path {
			return fmt.Errorf("unsafe staged path %q", rel)
		}
		for dir := filepath.Dir(path); dir != root; dir = filepath.Dir(dir) {
			if err := s.ensureDir(dir, 0o700); err != nil {
				return err
			}
		}
		if err := s.writePrivate(path, data); err != nil {
			return err
		}
	}
	return nil
}

// RemoveStagedInputs removes the deploy-install inputs after install.
func (s Store) RemoveStagedInputs() error {
	return errors.Join(s.removeStaged(stagedEnv), s.removeStaged(stagedBinary), s.removeStaged(stagedAssets))
}

// AuditEntry is one line of the helper's audit log: every verb's start and
// finish. It never holds secrets: verbs, step names and error text only.
type AuditEntry struct {
	At    time.Time `json:"at"`
	Verb  Verb      `json:"verb"`
	Phase string    `json:"phase"`
	Error string    `json:"error,omitempty"`
}

// Audit appends e to the audit log in Staging (0600, no links followed).
func (s Store) Audit(e AuditEntry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	path := s.staged(auditName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil {
		uid, gid, nlink, ok := statOwner(info)
		if !ok || !info.Mode().IsRegular() || uid != s.RootUID || gid != s.RootGID || info.Mode().Perm() != 0o600 || nlink != 1 {
			err = fmt.Errorf("%s must be a root-owned 0600 single-link regular file", path)
		}
	}
	if err == nil {
		_, err = f.Write(append(line, '\n'))
	}
	return errors.Join(err, f.Close())
}

func digestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
