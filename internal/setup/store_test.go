package setup

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagingDirectoryRefusesLinkAndWrongMode(t *testing.T) {
	f := newFakeHost(t)
	s := f.h.Store
	target := filepath.Join(f.top, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, s.Staging); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureStaging(); err == nil || !strings.Contains(err.Error(), "does not repair") {
		t.Errorf("symlink: %v", err)
	}
	if err := os.Remove(s.Staging); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.Staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureStaging(); err == nil {
		t.Error("accepted a 0755 staging directory")
	}
	if err := os.Chmod(s.Staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureStaging(); err != nil {
		t.Errorf("0700: %v", err)
	}
	// An unsafe ancestor is refused too.
	if err := os.Chmod(filepath.Join(f.top, "private/var/root"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureStaging(); err == nil || !strings.Contains(err.Error(), "unsafe directory") {
		t.Errorf("writable ancestor: %v", err)
	}
}

func TestStagedLedgerRefusesLinkAndWrongMode(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepInstall)
	path := filepath.Join(f.h.Store.Staging, ledgerName)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.h.Store.Load(); err == nil {
		t.Error("accepted a 0644 ledger")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.h.Store.Load(); err == nil {
		t.Error("accepted a hard-linked ledger")
	}
}

// TestLedgerMoveResume: an interrupted move resumes. Identical copies keep
// the installed one; different copies are refused; a staged ledger whose
// install is done is moved.
func TestLedgerMoveResume(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepGitHub)
	s := f.h.Store
	installed := filepath.Join(s.Ledger, ledgerName)
	data, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	// Identical copies: the staged one is removed.
	if err := s.writePrivate(filepath.Join(s.Staging, ledgerName), data); err != nil {
		t.Fatal(err)
	}
	if _, loc, err := s.Load(); err != nil || loc != LedgerInstalled {
		t.Fatalf("identical: %v %v", loc, err)
	}
	if _, err := os.Lstat(filepath.Join(s.Staging, ledgerName)); !errors.Is(err, fs.ErrNotExist) {
		t.Error("identical staged copy not removed")
	}
	// Different copies: refused, nothing removed.
	other := NewLedger("jdoe", 501, f.h.Now())
	if err := s.Save(other, LedgerStaged); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "two different setup ledgers") {
		t.Errorf("different: %v", err)
	}
	for _, r := range []Request{{Verb: VerbStatus}, {Verb: VerbGitHub}} {
		if resp := f.h.Handle(r); !strings.Contains(resp.Error, "two different") {
			t.Errorf("%s: %+v", r.Verb, resp)
		}
	}
	if err := os.Remove(filepath.Join(s.Staging, ledgerName)); err != nil {
		t.Fatal(err)
	}
	// Staged with install done, not yet moved: moved on load.
	if err := os.Remove(installed); err != nil {
		t.Fatal(err)
	}
	if err := s.writePrivate(filepath.Join(s.Staging, ledgerName), data); err != nil {
		t.Fatal(err)
	}
	if _, loc, err := s.Load(); err != nil || loc != LedgerInstalled {
		t.Fatalf("staged done: %v %v", loc, err)
	}
	if moved, err := os.ReadFile(installed); err != nil || string(moved) != string(data) {
		t.Errorf("moved ledger %v", err)
	}
}
