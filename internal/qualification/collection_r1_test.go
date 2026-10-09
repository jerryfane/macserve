package qualification

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
)

func TestCollectionRetryPreservesFailedAttempt(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	c := Challenge{Created: now.Add(-time.Minute), Expires: now.Add(time.Hour), Environment: deploy.Environment{OwnerUID: uint32(os.Getuid())}, UDP: []string{"127.0.0.1:12345"}}
	receiptPath := filepath.Join(dir, "input-receipts.json")
	bad := []byte(`{"schema":`)
	if err := os.WriteFile(receiptPath, bad, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := collectionAttempt(dir)
	if err != nil {
		t.Fatal(err)
	}
	failed := Candidate{ChallengeSHA256: strings.Repeat("a", 64), Collected: now, Artifacts: map[string]string{}}
	if _, err := collectArtifacts(dir, first, c, failed, []byte(`{"role":"job"}`), []byte(`{"role":"owner"}`), Snapshot{At: now}, receiptPath); err == nil {
		t.Fatal("malformed receipt accepted")
	}
	originals := map[string][]byte{}
	for _, name := range []string{"job-report.json", "owner-report.json", "after.json", "receipts-000.json"} {
		b, err := os.ReadFile(filepath.Join(dir, first+name))
		if err != nil {
			t.Fatal(err)
		}
		originals[first+name] = b
	}
	if !bytes.Equal(originals[first+"receipts-000.json"], bad) {
		t.Fatal("failed receipt evidence not retained")
	}
	valid := Receipts{Schema: 2, ChallengeSHA256: failed.ChallengeSHA256, UID: os.Getuid(), Listen: c.UDP[0], Started: c.Created, Finished: now}
	b, err := encode(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	second, err := collectionAttempt(dir)
	if err != nil {
		t.Fatal(err)
	}
	retried := Candidate{ChallengeSHA256: failed.ChallengeSHA256, Collected: now, Artifacts: map[string]string{}}
	receipts, err := collectArtifacts(dir, second, c, retried, []byte(`{"role":"job","refusal":"new evidence"}`), []byte(`{"role":"owner"}`), Snapshot{At: now.Add(time.Second)}, receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[0].ChallengeSHA256 != valid.ChallengeSHA256 || receipts[0].Listen != valid.Listen {
		t.Fatalf("wrong retry receipts: %+v", receipts)
	}
	for name, original := range originals {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(b, original) {
			t.Fatalf("failed-attempt evidence changed: %s: %v", name, err)
		}
		if _, included := retried.Artifacts[name]; included {
			t.Fatalf("retry includes stale evidence: %s", name)
		}
	}
	for _, name := range []string{"job-report.json", "owner-report.json", "after.json", "receipts-000.json"} {
		b, err := os.ReadFile(filepath.Join(dir, second+name))
		if err != nil {
			t.Fatal(err)
		}
		if retried.Artifacts[second+name] != digest(b) {
			t.Fatalf("retry hash does not bind current artifact: %s", name)
		}
	}
	committed := []byte(`{"schema":2}`)
	if err := os.WriteFile(filepath.Join(dir, "candidate.json"), committed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := collectionAttempt(dir); err == nil {
		t.Fatal("completed candidate permits recollection")
	}
	got, err := os.ReadFile(filepath.Join(dir, "candidate.json"))
	if err != nil || !bytes.Equal(got, committed) {
		t.Fatal("completed candidate changed")
	}
}

func TestCollectionLockReleasedOnProcessExit(t *testing.T) {
	const helper = "MACSERVE_COLLECTION_LOCK_HELPER"
	if dir := os.Getenv(helper); dir != "" {
		if _, err := lockSessionFile(dir); err != nil {
			t.Fatal(err)
		}
		// Exit without invoking the returned cleanup, as after an interruption.
		os.Exit(0)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCollectionLockReleasedOnProcessExit$")
	cmd.Env = append(os.Environ(), helper+"="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lock holder: %v: %s", err, out)
	}
	unlock, err := lockSessionFile(dir)
	if err != nil {
		t.Fatalf("interrupted holder blocked retry: %v", err)
	}
	defer unlock()
	if second, err := lockSessionFile(dir); err == nil {
		second()
		t.Fatal("concurrent session writer admitted")
	}
}

func TestCollectionLockRefusesUnsafeObjects(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "shared-file", "hard-link"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".lock")
			var err error
			switch kind {
			case "directory":
				err = os.Mkdir(path, 0700)
			case "shared-file":
				err = os.WriteFile(path, nil, 0644)
			default:
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(target, path)
				} else {
					err = os.Link(target, path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if unlock, err := lockSessionFile(dir); err == nil {
				unlock()
				t.Fatal("unsafe lock accepted")
			}
		})
	}
}
