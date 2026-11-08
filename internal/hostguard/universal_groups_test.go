package hostguard

import (
	"errors"
	"strings"
	"testing"
)

// The Studio, 2026-11-08: keyholder 499 and job 6202 both belonged to
// _lpoperator (100) and com.apple.sharepoint.group.1 (701), which nest
// localaccounts and everyone. The keyholder refused to start.
func TestDaemonGroupsAcceptGroupsNestingUniversalGroups(t *testing.T) {
	id := daemonIdentity{UID: 499, GID: 499, RPCGID: 498, JobUID: 6202, JobGID: 6202}
	keyholder := []int{499, 12, 61, 498, 100, 701}
	job := []string{"6202", "12", "61", "398", "100", "701"}
	restore := nestsUniversalGroup
	t.Cleanup(func() { nestsUniversalGroup = restore })
	for _, c := range []struct {
		name      string
		universal map[uint32]bool
		lookupErr error
		want      string
	}{
		{"both nest a universal group", map[uint32]bool{100: true, 701: true}, nil, ""},
		{"one does not", map[uint32]bool{100: true}, nil, "keyholder shares group 701"},
		{"lookup fails", nil, errors.New("local directory group lookup failed"), "keyholder shares group 100"},
	} {
		t.Run(c.name, func(t *testing.T) {
			asked := map[uint32]bool{}
			nestsUniversalGroup = func(gid uint32) (bool, error) {
				asked[gid] = true
				if c.lookupErr != nil {
					return false, c.lookupErr
				}
				return c.universal[gid], nil
			}
			err := daemonGroups("keyholder", id, keyholder, job)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("error = %v; want %q", err, c.want)
			}
			if asked[12] || asked[61] || asked[498] || asked[499] {
				t.Fatalf("looked up groups the job does not share or that are always universal: %v", asked)
			}
		})
	}
}

func TestDirectoryOutputParsing(t *testing.T) {
	search := "_lpoperator\t\tPrimaryGroupID = (\n    100\n)\n"
	if name, err := groupNameFromSearch(search, 100); err != nil || name != "_lpoperator" {
		t.Fatalf("search parse: %q %v", name, err)
	}
	for _, bad := range []string{
		"",
		search + "other\t\tPrimaryGroupID = (\n    100\n)\n",
		"_lpoperator\t\tPrimaryGroupID = (\n    101\n)\n",
		"../x\t\tPrimaryGroupID = (\n    100\n)\n",
	} {
		if _, err := groupNameFromSearch(bad, 100); err == nil {
			t.Fatalf("accepted search output %q", bad)
		}
	}
	nested, err := nestedGroupsFromRead("NestedGroups: ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000062\n")
	if err != nil || len(nested) != 2 || nested[0] != localAccountsGUID {
		t.Fatalf("nested parse: %v %v", nested, err)
	}
	for _, none := range []string{"", "No such key: NestedGroups\n"} {
		if nested, err := nestedGroupsFromRead(none); err != nil || nested != nil {
			t.Fatalf("no nested groups %q: %v %v", none, nested, err)
		}
	}
	for _, bad := range []string{"GroupMembership: x\n", "NestedGroups: not-a-guid\n"} {
		if _, err := nestedGroupsFromRead(bad); err == nil {
			t.Fatalf("accepted nested output %q", bad)
		}
	}
}
