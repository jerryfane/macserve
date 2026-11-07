package hostguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyholderGroupsSeparateFromJob(t *testing.T) {
	id := daemonIdentity{UID: 310, GID: 310, RPCGID: 311, JobUID: 502, JobGID: 502}
	cases := []struct {
		name      string
		keyholder []int
		job       []string
		want      string
	}{
		{"dedicated", []int{310, 311, 12, 61}, []string{"502", "12", "61"}, ""},
		{"no rpc group", []int{310}, []string{"502"}, "keyholder must belong to the RPC group"},
		{"shares job group", []int{310, 311, 502}, []string{"502"}, "keyholder shares group"},
		{"shares job supplementary group", []int{310, 311, 700}, []string{"502", "700"}, "shares group"},
		{"job in rpc group", []int{310, 311}, []string{"502", "311"}, "must not belong to the keyholder"},
		{"job in keyholder group", []int{310, 311}, []string{"502", "310"}, "must not belong to the keyholder"},
		{"keyholder in admin", []int{310, 311, 80}, []string{"502"}, "admin"},
		{"keyholder in wheel", []int{310, 311, 0}, []string{"502"}, "wheel"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := daemonGroups("keyholder", id, c.keyholder, c.job)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("error = %v; want %q", err, c.want)
			}
		})
	}
}

func TestKeyholderSocketDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keyholder-run")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := socketDirectory("keyholder", dir, uid+1, gid); err == nil || !strings.Contains(err.Error(), "keyholder socket directory") {
		t.Fatalf("accepted another owner: %v", err)
	}
}

// ReadOwnedPrivateKey admits root or the named owner, never anyone else,
// and keeps PrivateFile's leaf rules.
func TestReadOwnedPrivateKey(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the key another owner")
	}
	// t.TempDir lies below a world-writable /tmp, which no private path
	// admits; root's own home has protected ancestors.
	home, err := os.UserHomeDir()
	if err == nil {
		home, err = filepath.EvalSymlinks(home)
	}
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".macserve-keyholder-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDirectory(dir); err != nil {
		t.Skipf("root's home is not a protected ancestor here: %v", err)
	}
	key := filepath.Join(dir, "github-app.pem")
	if err := os.WriteFile(key, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(key, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadOwnedPrivateKey(key, 4242); err != nil || string(data) != "pem" {
		t.Fatalf("keyholder-owned key refused: %q %v", data, err)
	}
	if _, err := ReadOwnedPrivateKey(key, 4243); err == nil {
		t.Fatal("accepted a key of another owner")
	}
	if err := PrivateFile(key); err == nil {
		t.Fatal("PrivateFile accepted another account's key")
	}
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwnedPrivateKey(key, 4242); err == nil {
		t.Fatal("accepted a group-readable key")
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, filepath.Join(dir, "second")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwnedPrivateKey(key, 4242); err == nil {
		t.Fatal("accepted a hard-linked key")
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwnedPrivateKey(link, 4242); err == nil {
		t.Fatal("accepted a symlinked key")
	}
}
