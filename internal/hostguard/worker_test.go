package hostguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDedicatedJobIdentityExcludesRootOwnerAndController(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		uid, gid, controller, owner uint32
	}{
		{"root", 0, 502, 503, 501},
		{"system-account", 499, 502, 503, 501},
		{"owner", 501, 502, 503, 501},
		{"controller", 503, 502, 503, 501},
		{"root-group", 502, 0, 503, 501},
		{"root-controller", 502, 502, 0, 501},
		{"missing-owner", 502, 502, 503, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := DistinctJobIdentity(tc.uid, tc.gid, tc.controller, tc.owner); err == nil {
				t.Fatal("unsafe job identity accepted")
			}
		})
	}
	if err := DistinctJobIdentity(502, 20, 503, 501); err != nil {
		t.Fatalf("dedicated standard account rejected: %v", err)
	}
}

func TestUnprivilegedConfigAndSymlinksCannotAuthorizeBroker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "worker.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := RootConfig(path); err == nil {
			t.Fatal("owner-writable config trusted as root-managed")
		}
		if err := Worker(path); err == nil {
			t.Fatal("same-UID production worker remains enabled")
		}
	}
	link := filepath.Join(dir, "config-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := RootConfig(link); err == nil {
		t.Fatal("symlink config trusted")
	}
	if err := RootDirectory(link); err == nil {
		t.Fatal("symlink protected root trusted")
	}
}
