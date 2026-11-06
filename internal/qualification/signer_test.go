package qualification

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
)

func testSignerPaths(root string) signerPaths {
	state := filepath.Join(root, "var/signer")
	run := filepath.Join(root, "var/signer-run")
	return signerPaths{
		State: state, KeychainDir: filepath.Join(state, "keychain"), Keychain: filepath.Join(state, "keychain/signing.keychain-db"),
		KeychainSecret: filepath.Join(state, "keychain/keychain.secret"), SocketDir: run, Socket: filepath.Join(run, "signer.sock"),
		Inbox: filepath.Join(root, "var/signer-inbox"),
	}
}

func TestSignerDenialTargetsCoverTheSignerBoundary(t *testing.T) {
	want := []string{
		"list:/Library/macserve/var/signer", "traverse:/Library/macserve/var/signer",
		"list:/Library/macserve/var/signer/keychain", "traverse:/Library/macserve/var/signer/keychain",
		"list:/Library/macserve/var/signer-run", "traverse:/Library/macserve/var/signer-run",
		"list:/Library/macserve/var/signer-inbox", "traverse:/Library/macserve/var/signer-inbox",
		"connect:/Library/macserve/var/signer-run/signer.sock",
		"read:/Library/macserve/var/signer/keychain/signing.keychain-db",
		"read:/Library/macserve/var/signer/keychain/keychain.secret",
	}
	if got := signerDenialTargets(); !slices.Equal(got, want) {
		t.Fatalf("signer_denial targets\n got %q\nwant %q", got, want)
	}
}

func TestSignerDenialCountsOnlyPermissionErrors(t *testing.T) {
	paths := testSignerPaths("/x")
	denied := func(string) error { return &fs.PathError{Op: "open", Path: "p", Err: syscall.EACCES} }
	all := signerOps{list: denied, traverse: denied, connect: denied, read: denied}
	rows := signerDenial(paths, all)
	if len(rows) != len(paths.targets()) {
		t.Fatalf("%d rows for %d targets", len(rows), len(paths.targets()))
	}
	for _, r := range rows {
		if !r.ok || !strings.Contains(r.detail, "permission denied") {
			t.Fatalf("permission denial not counted: %+v", r)
		}
	}
	eperm := func(string) error {
		return &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.EPERM)}
	}
	if rows := signerDenial(paths, signerOps{list: denied, traverse: denied, connect: eperm, read: denied}); !rows[8].ok {
		t.Fatalf("EPERM connect refusal not counted: %+v", rows[8])
	}
	for name, failure := range map[string]func(string) error{
		"success": func(string) error { return nil },
		"absent":  func(string) error { return fs.ErrNotExist },
		"refused": func(string) error { return syscall.ECONNREFUSED },
		"timeout": func(string) error { return errors.New("i/o timeout") },
	} {
		for i, op := range []string{"list", "traverse", "connect", "read"} {
			ops := all
			switch i {
			case 0:
				ops.list = failure
			case 1:
				ops.traverse = failure
			case 2:
				ops.connect = failure
			case 3:
				ops.read = failure
			}
			failed := 0
			for _, r := range signerDenial(paths, ops) {
				if !r.ok {
					failed++
					if !strings.HasPrefix(r.target, op+":") {
						t.Fatalf("%s %s failed the wrong row %s", name, op, r.target)
					}
				}
			}
			if failed == 0 {
				t.Fatalf("%s on %s counted as denial", name, op)
			}
		}
	}
}

// As an unprivileged account the live operations observe real kernel
// denials on a tree the probing account cannot search or read.
func TestSignerDenialLiveOperations(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	root := t.TempDir()
	paths := testSignerPaths(root)
	for _, dir := range []string{paths.KeychainDir, paths.SocketDir, paths.Inbox} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{paths.Keychain, paths.KeychainSecret} {
		if err := os.WriteFile(f, []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	l, err := net.Listen("unix", paths.Socket)
	if err != nil {
		t.Skipf("unix socket unavailable: %v", err)
	}
	defer l.Close()
	ops := liveSignerOps(context.Background())
	// Reachable before the modes deny: the probe would fail.
	for _, r := range signerDenial(paths, ops) {
		if r.ok {
			t.Fatalf("accessible target counted as denied: %+v", r)
		}
	}
	for _, dir := range []string{paths.KeychainDir, paths.State, paths.SocketDir, paths.Inbox} {
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, dir := range []string{paths.State, paths.KeychainDir, paths.SocketDir, paths.Inbox} {
			os.Chmod(dir, 0700)
		}
	})
	for _, r := range signerDenial(paths, ops) {
		if !r.ok {
			t.Fatalf("kernel denial not observed: %+v", r)
		}
	}
}

func signerChallenge() Challenge {
	c := carryChallengeFixture()
	c.Signer = true
	return c
}

func TestSignerDeployedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "signer.json")
	plain := deploy.Environment{}
	withSigner := deploy.Environment{SignerUID: 401, SignerGID: 401, SignRPCGID: 402}
	for name, tc := range map[string]struct {
		env        deploy.Environment
		controller bool
		path       string
		want       bool
	}{
		"none":              {plain, false, absent, false},
		"deploy.env":        {withSigner, false, absent, true},
		"controller signer": {plain, true, absent, true},
		"signer.json":       {plain, false, dir, true},
	} {
		if got, err := signerDeployed(tc.env, tc.controller, tc.path); err != nil || got != tc.want {
			t.Fatalf("%s: deployed=%v err=%v", name, got, err)
		}
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := signerDeployed(plain, false, filepath.Join(file, "signer.json")); err == nil {
		t.Fatal("uninspectable signer configuration skipped the signer probe")
	}
}

func withSignerRows(r Report, ok bool) Report {
	for _, target := range signerDenialTargets() {
		r.Results = append(r.Results, Result{Category: signerDenialCategory, Target: target, Attempt: 1, Success: ok})
	}
	return r
}

func TestSignerDenialRowsAreJobOnlyAndNeedADeployedSigner(t *testing.T) {
	c := signerChallenge()
	job := withSignerRows(deniedReport(c), true)
	if err := checkReport(job, c, "h", "job"); err != nil {
		t.Fatalf("signer_denial rows refused: %v", err)
	}
	if err := checkReport(job, carryChallengeFixture(), "h", "job"); err == nil {
		t.Fatal("signer_denial rows accepted without a deployed signer")
	}
	owner := withSignerRows(Report{Schema: schema, ChallengeSHA256: "h", Role: "owner", Mode: ownerProbeMode, UID: 501, AuditUID: 501, Groups: []int{20}, Started: c.Created, Finished: c.Created.Add(time.Second)}, true)
	if err := checkReport(owner, c, "h", "owner"); err == nil || !strings.Contains(err.Error(), "category") {
		t.Fatalf("owner signer_denial rows accepted: %v", err)
	}
}

func TestUnixSocketBoundaryRequiresSignerDenial(t *testing.T) {
	c := signerChallenge()
	status := func(j Report) string {
		return aggregate(c, j, Report{}, nil, sittingFacts{})["unix_socket_boundary"].Status
	}
	if got := status(withSignerRows(deniedReport(c), true)); got != "pass" {
		t.Fatalf("denied signer boundary: %s", got)
	}
	if got := status(deniedReport(c)); got != "fail" {
		t.Fatalf("missing signer_denial rows: %s", got)
	}
	if got := status(withSignerRows(deniedReport(c), false)); got != "fail" {
		t.Fatalf("reachable signer: %s", got)
	}
	j := withSignerRows(deniedReport(c), true)
	j.Results = j.Results[:len(j.Results)-1]
	if got := status(j); got != "fail" {
		t.Fatalf("incomplete signer_denial rows: %s", got)
	}
	plain := carryChallengeFixture()
	if got := aggregate(plain, deniedReport(plain), Report{}, nil, sittingFacts{})["unix_socket_boundary"].Status; got != "pass" {
		t.Fatalf("deployment without a signer: %s", got)
	}
}

func TestCarryRequiresSignerDenial(t *testing.T) {
	c := signerChallenge()
	approved := c
	approved.Carry = false
	if err := checkCarryJobProbe(withSignerRows(deniedReport(c), true), c, "h", approved); err != nil {
		t.Fatalf("denied signer refused: %v", err)
	}
	for name, r := range map[string]Report{"missing": deniedReport(c), "reachable": withSignerRows(deniedReport(c), false)} {
		if err := checkCarryJobProbe(r, c, "h", approved); err == nil {
			t.Fatalf("%s signer_denial accepted by carry", name)
		}
	}
}
