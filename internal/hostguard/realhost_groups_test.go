//go:build macserve_realhost && darwin

package hostguard

import (
	"os"
	"os/user"
	"strconv"
	"testing"
)

// TestRealHostKeyholderGroups applies the keyholder's group-isolation check to
// the real local directory: the installed _macserve_key account and its RPC
// group against the named job account. The unit tests fake group membership;
// only the host's own directory showed the keyholder sharing _lpoperator (100)
// and com.apple.sharepoint.group.1 (701) with the job account, which crash-
// looped the keyholder after the v0.1.39 activation. It reads directory
// records only and needs no privilege, so it runs as the owner before a sitting.
//
//	MACSERVE_RH_JOB_ACCOUNT=macservejob go test -tags macserve_realhost -run RealHost ./internal/hostguard
func TestRealHostKeyholderGroups(t *testing.T) {
	jobName := os.Getenv("MACSERVE_RH_JOB_ACCOUNT")
	if jobName == "" {
		t.Skip("MACSERVE_RH_JOB_ACCOUNT unset")
	}
	keyholder := lookupAccount(t, KeyholderAccount)
	job := lookupAccount(t, jobName)
	rpc, err := user.LookupGroup(KeyholderAccount + "rpc")
	if err != nil {
		t.Fatalf("keyholder RPC group: %v", err)
	}
	own, err := keyholder.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	jobGroups, err := job.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	ownGIDs := make([]int, 0, len(own))
	for _, raw := range own {
		ownGIDs = append(ownGIDs, int(parseID(t, raw)))
	}
	id := daemonIdentity{
		UID: parseID(t, keyholder.Uid), GID: parseID(t, keyholder.Gid), RPCGID: parseID(t, rpc.Gid),
		JobUID: parseID(t, job.Uid), JobGID: parseID(t, job.Gid),
	}
	if err := daemonGroups("keyholder", id, ownGIDs, append(jobGroups, job.Gid)); err != nil {
		t.Fatalf("keyholder %v vs job %s %v: %v", own, jobName, jobGroups, err)
	}
}

func lookupAccount(t *testing.T, name string) *user.User {
	t.Helper()
	account, err := user.Lookup(name)
	if err != nil {
		t.Fatalf("account %s: %v", name, err)
	}
	return account
}

func parseID(t *testing.T, raw string) uint32 {
	t.Helper()
	id, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		t.Fatalf("id %q: %v", raw, err)
	}
	return uint32(id)
}
