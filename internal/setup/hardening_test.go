package setup

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}

// TestHelperUnderUmask077: the helper runs with umask 077, so every
// directory and file it creates must get its exact mode explicitly.
func TestHelperUnderUmask077(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	f := newFakeHost(t)
	f.through(StepRound1)
	f.h.audit(VerbStatus, "start", nil)
	if _, loc, err := f.h.Store.Load(); err != nil || loc != LedgerInstalled {
		t.Fatalf("load after install: %v %v", loc, err)
	}
	if r := f.call(VerbStatus, ""); r.Error != "" || r.Ledger == nil {
		t.Fatalf("status after install: %+v", r)
	}
	dir := filepath.Join(f.top, "s")
	lock, err := f.h.Store.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ln, err := f.h.Store.Listen(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for path, want := range map[string]fs.FileMode{
		f.h.Store.Staging: fs.ModeDir | 0o700,
		f.h.Store.Ledger:  fs.ModeDir | 0o755,
		filepath.Join(f.h.Store.Ledger, ledgerName): 0o600,
		filepath.Join(f.h.Store.Staging, auditName): 0o600,
		dir:                            fs.ModeDir | 0o711,
		filepath.Join(dir, LockName):   0o600,
		filepath.Join(dir, SocketName): fs.ModeSocket | 0o600,
	} {
		if got := mode(t, path); got != want {
			t.Errorf("%s: mode %v, want %v", path, got, want)
		}
	}
}

func TestLockIsExclusive(t *testing.T) {
	f := newFakeHost(t)
	dir := filepath.Join(f.top, "s")
	first, err := f.h.Store.Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Store.Lock(dir); err == nil || !strings.Contains(err.Error(), "another macserve setup helper") {
		t.Fatalf("second lock: %v", err)
	}
	first.Close()
	again, err := f.h.Store.Lock(dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again.Close()
	path := filepath.Join(dir, LockName)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Store.Lock(dir); err == nil {
		t.Error("accepted a 0644 lock file")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.top, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Store.Lock(dir); err == nil {
		t.Error("followed a lock symlink")
	}
	if _, err := os.Lstat(filepath.Join(f.top, "elsewhere")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("lock symlink target created")
	}
}

// TestSecondHelperRefused: while one helper serves, a second refuses
// before it reads the ledger, replaces the socket or can reach
// deploy.Install.
func TestSecondHelperRefused(t *testing.T) {
	f := newFakeHost(t)
	f.h.Owner.UID = uint32(os.Getuid())
	dir := filepath.Join(f.top, "s")
	done := make(chan error, 1)
	go func() { done <- f.h.ServeRoot(dir, 5*time.Second) }()
	var socket fs.FileInfo
	deadline := time.Now().Add(5 * time.Second)
	for {
		var err error
		if socket, err = os.Lstat(filepath.Join(dir, SocketName)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	second := newFakeHost(t)
	second.h.Store = f.h.Store
	second.h.Owner = f.h.Owner
	if err := second.h.ServeRoot(dir, time.Second); err == nil || !strings.Contains(err.Error(), "another macserve setup helper") {
		t.Fatalf("second helper: %v", err)
	}
	if after, err := os.Lstat(filepath.Join(dir, SocketName)); err != nil || !os.SameFile(socket, after) {
		t.Error("the second helper replaced the live socket")
	}
	if len(second.installs) != 0 {
		t.Error("the second helper installed")
	}
	c, err := Dial(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(Request{Verb: VerbStatus}); err != nil {
		t.Errorf("first helper after the refusal: %v", err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Errorf("first helper: %v", err)
	}
}

// TestCheckExecutable: the helper re-hashes itself against the digest the
// owner verified, and after install must be the installed binary with the
// digest install recorded.
func TestCheckExecutable(t *testing.T) {
	f := newFakeHost(t)
	if err := f.h.CheckStart(); err != nil {
		t.Fatalf("matching binary: %v", err)
	}
	good := f.h.SHA256
	f.h.SHA256 = strings.Repeat("0", 64)
	if err := f.h.CheckStart(); err == nil || !strings.Contains(err.Error(), "not the verified") {
		t.Errorf("mismatch: %v", err)
	}
	f.h.SHA256 = good
	f.through(StepGitHub)
	if err := f.h.CheckStart(); err == nil || !strings.Contains(err.Error(), "must be") {
		t.Errorf("downloaded binary after install: %v", err)
	}
	installed := filepath.Join(f.h.Root, "bin", "macserve")
	f.h.Executable = installed
	if err := f.h.CheckStart(); err != nil {
		t.Errorf("installed binary: %v", err)
	}
	if err := os.WriteFile(installed, []byte("replaced"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.h.SHA256 = digestHex([]byte("replaced"))
	if err := f.h.CheckStart(); err == nil || !strings.Contains(err.Error(), "the one install recorded") {
		t.Errorf("replaced installed binary: %v", err)
	}
}

func TestToolsRecheckBeforeEachCommand(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepTools)
	calls := 0
	f.h.ToolCheck = func(string, uint32) error {
		calls++
		if calls == 3 {
			return errors.New("ancestor became writable")
		}
		return nil
	}
	if r := f.call(VerbTools, ""); !strings.Contains(r.Error, "not a protected toolchain") {
		t.Fatalf("%+v", r)
	}
	if len(f.execs) != 1 {
		t.Errorf("ran %q after the policy failed", f.execs)
	}
}

func TestInstalledEnvMustMatchInstallRecord(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepTools)
	path := filepath.Join(f.h.Root, "config", "deploy.env")
	env := strings.Replace(testEnv(f.h.Owner), "/Applications/Xcode.app", "/Users/jdoe/Xcode.app", 1)
	if err := os.WriteFile(path, []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := f.call(VerbTools, ""); !strings.Contains(r.Error, "not the one install recorded") || len(f.execs) != 0 {
		t.Errorf("tools: %+v ran %q", r, f.execs)
	}
}

func TestInstallRefusesNonTerminal(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepInstall)
	f.terminalErr = errors.New("not a terminal")
	if r := f.call(VerbInstall, ""); !strings.Contains(r.Error, "not a terminal") || len(f.installs) != 0 {
		t.Fatalf("%+v", r)
	}
	if f.ledger().record(StepInstall).Status != StatusPending {
		t.Error("install began")
	}
}

func TestFDACheckRefusesErrorOutput(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepOwnerActions)
	for _, out := range []string{"error: open TCC.db: no such file\n", "\n", "grantedx\n"} {
		f.fda = out
		if r := f.call(VerbFDACheck, ""); r.Done || !strings.Contains(r.Error, "unexpected") {
			t.Errorf("%q: %+v", out, r)
		}
	}
	f.fda = "granted\n"
	if r := f.call(VerbOwnerActions, ""); r.Error != "" || !r.Done {
		t.Errorf("after errors: %+v", r)
	}
}

func TestAuditLogRefusesSymlink(t *testing.T) {
	f := newFakeHost(t)
	if err := f.h.Store.EnsureStaging(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(f.top, "target")
	if err := os.Symlink(target, filepath.Join(f.h.Store.Staging, auditName)); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Store.Audit(AuditEntry{Verb: VerbStatus, Phase: "start"}); err == nil {
		t.Error("audit followed a symlink")
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Error("symlink target written")
	}
}

// TestStoreRefusesAnotherOwner: files and directories owned by another
// user than RootUID are refused (the tests run as one user, so the store's
// RootUID is moved instead).
func TestStoreRefusesAnotherOwner(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepGitHub)
	s := f.h.Store
	s.RootUID++
	if _, _, err := s.Load(); err == nil {
		t.Error("loaded a ledger owned by another user")
	}
	if err := s.EnsureStaging(); err == nil {
		t.Error("accepted a staging directory owned by another user")
	}
	s = f.h.Store
	s.RootGID++
	if _, _, err := s.Load(); err == nil {
		t.Error("loaded a ledger of another group")
	}
}
