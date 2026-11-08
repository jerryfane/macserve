package hostguard

import (
	"bufio"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// macOS makes every local account a member of everyone (12) and
// localaccounts (61). Some system groups nest one of those two and so are just
// as universal: on the Studio (macOS 27) both the keyholder and the job account
// were members of _lpoperator (100, nests localaccounts) and
// com.apple.sharepoint.group.1 (701, nests everyone), which kept the keyholder
// from ever starting. Sharing such a group grants the job account nothing that
// every other local account lacks.
const (
	everyoneGUID      = "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C"
	localAccountsGUID = "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000003D"
)

// nestsUniversalGroup reports whether the local directory group with this GID
// nests everyone or localaccounts. It is a variable so tests can replace the
// directory lookup.
var nestsUniversalGroup = dsNestsUniversalGroup

func dsNestsUniversalGroup(gid uint32) (bool, error) {
	out, err := dscl(".", "-search", "/Groups", "PrimaryGroupID", strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return false, err
	}
	name, err := groupNameFromSearch(out, gid)
	if err != nil {
		return false, err
	}
	out, err = dscl(".", "-read", "/Groups/"+name, "NestedGroups")
	if err != nil {
		return false, err
	}
	nested, err := nestedGroupsFromRead(out)
	if err != nil {
		return false, err
	}
	for _, guid := range nested {
		if guid == everyoneGUID || guid == localAccountsGUID {
			return true, nil
		}
	}
	return false, nil
}

func dscl(args ...string) (string, error) {
	cmd := exec.Command("/usr/bin/dscl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New("local directory group lookup failed")
	}
	return string(out), nil
}

// groupNameFromSearch parses `dscl . -search /Groups PrimaryGroupID <gid>`:
// exactly one record "<name>\t\tPrimaryGroupID = (\n    <gid>\n)".
func groupNameFromSearch(out string, gid uint32) (string, error) {
	var name string
	records := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, " ") || strings.TrimSpace(line) == "" || strings.TrimSpace(line) == ")" {
			if v := strings.TrimSpace(line); v != "" && v != ")" && v != strconv.FormatUint(uint64(gid), 10) {
				return "", errors.New("unexpected local directory group record")
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "PrimaryGroupID" {
			return "", errors.New("unexpected local directory group record")
		}
		name = fields[0]
		records++
	}
	if records != 1 || name == "" || strings.ContainsAny(name, "/\x00") {
		return "", errors.New("group ID does not name exactly one local directory group")
	}
	return name, nil
}

// nestedGroupsFromRead parses the standard output of
// `dscl . -read /Groups/<name> NestedGroups`: "NestedGroups: GUID ..."
// (possibly continued on indented lines), or nothing for a group that nests
// nothing (dscl then writes "No such key: NestedGroups" to standard error).
func nestedGroupsFromRead(out string) ([]string, error) {
	text := strings.TrimSpace(out)
	if text == "" || text == "No such key: NestedGroups" {
		return nil, nil
	}
	rest, ok := strings.CutPrefix(text, "NestedGroups:")
	if !ok {
		return nil, errors.New("unexpected local directory nested groups")
	}
	guids := strings.Fields(rest)
	for _, g := range guids {
		if len(g) != 36 || strings.Count(g, "-") != 4 {
			return nil, errors.New("unexpected local directory nested group")
		}
	}
	return guids, nil
}
