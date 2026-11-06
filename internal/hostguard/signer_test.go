package hostguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignerGroupsSeparateFromJob(t *testing.T) {
	id := SignerIdentity{SignerUID: 300, SignerGID: 300, RPCGID: 301, JobUID: 502, JobGID: 502, ControllerUID: 299}
	cases := []struct {
		name   string
		signer []int
		job    []string
		want   string
	}{
		{"dedicated", []int{300, 301, 12, 61}, []string{"502", "12", "61"}, ""},
		{"no rpc group", []int{300}, []string{"502"}, "RPC group"},
		{"shares job group", []int{300, 301, 502}, []string{"502"}, "shares group"},
		{"shares job supplementary group", []int{300, 301, 700}, []string{"502", "700"}, "shares group"},
		{"job in rpc group", []int{300, 301}, []string{"502", "301"}, "must not belong"},
		{"job in signer group", []int{300, 301}, []string{"502", "300"}, "must not belong"},
		{"signer in admin", []int{300, 301, 80}, []string{"502"}, "admin"},
		{"signer in staff", []int{300, 301, 20}, []string{"502"}, "staff"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := signerGroups(id, c.signer, c.job)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("error = %v; want %q", err, c.want)
			}
		})
	}
}

func TestSocketDirectoryRequiresSignerAndRPCGroup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := socketDirectory(dir, uid+1, gid); err == nil {
		t.Fatal("accepted another owner")
	}
	if err := socketDirectory(dir, uid, gid+1); err == nil {
		t.Fatal("accepted another group")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := socketDirectory(dir, uid, gid); err == nil || !strings.Contains(err.Error(), "0750") {
		t.Fatalf("accepted world-traversable socket directory: %v", err)
	}
}
