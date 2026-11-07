package plan

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/deploy"
)

// Default account names and the ID range setup chooses from. 6201/6202
// are used when free, as in docs/install.md.
const (
	DefaultControllerUser = "macservectl"
	DefaultJobUser        = "macservejob"
	DefaultJobRealName    = "macserve build"
	DefaultPort           = 8443
	firstID               = 6201
	lastID                = 6299
)

// pendingRepository stands in for the GitHub step's pin when the plan runs
// before connect-github: it lets the rest of the environment be validated
// by the deploy parser, and is never printed or installed.
const (
	pendingRepositoryName = "pending/pending"
	pendingRepositoryID   = 1
)

var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// Input grammars. They admit only printable ASCII without '=', quotes,
// shell or comment characters, so a value can never add a deploy.env line
// or key; RenderEnvironment re-checks the result line by line anyway.
var (
	accountNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
	realNameRE    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,62}[A-Za-z0-9._-])?$`)
	repositoryRE  = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}):([1-9][0-9]{0,15})$`)
)

// Choices are the few values the user may set. Everything else is
// detected.
type Choices struct {
	ControllerUser string
	JobUser        string
	JobRealName    string
	// Repository is "owner/name:id", or empty before the GitHub step.
	Repository string
}

// DefaultChoices returns the defaults setup uses without questions.
func DefaultChoices() Choices {
	return Choices{ControllerUser: DefaultControllerUser, JobUser: DefaultJobUser, JobRealName: DefaultJobRealName}
}

// Validate applies the input grammars.
func (c Choices) Validate() error {
	if !accountNameRE.MatchString(c.ControllerUser) || !accountNameRE.MatchString(c.JobUser) || c.ControllerUser == c.JobUser {
		return errors.New("account names must be distinct lowercase names of at most 31 characters")
	}
	if !realNameRE.MatchString(c.JobRealName) {
		return errors.New("build account name must be 1-64 letters, digits, spaces, '.', '_' or '-', not starting or ending with a space")
	}
	if c.Repository != "" {
		if _, _, err := parseRepository(c.Repository); err != nil {
			return err
		}
	}
	return nil
}

func parseRepository(pin string) (string, int64, error) {
	m := repositoryRE.FindStringSubmatch(pin)
	if m == nil || strings.Contains(m[1], "..") || strings.HasSuffix(m[1], ".git") {
		return "", 0, errors.New("repository must be lowercase OWNER/NAME:ID with the numeric GitHub repository ID")
	}
	id, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil || id > 1<<53-1 {
		return "", 0, errors.New("repository ID out of range")
	}
	return m[1], id, nil
}

// Directory is what the local and search directory nodes already hold.
type Directory struct {
	Users             []deploy.DirectoryRecord // /Users UniqueID
	Groups            []deploy.DirectoryRecord // /Groups PrimaryGroupID
	UserPrimaryGroups []deploy.DirectoryRecord // /Users PrimaryGroupID
}

// IDs are the numeric identities setup will create: the controller and
// job accounts, and the keyholder's system account and RPC group.
type IDs struct {
	ControllerUID, ControllerGID, JobUID, JobGID uint32
	KeyholderUID, KeyholderGID, KeyRPCGID        uint32
}

// PickIDs chooses the controller and job identities: names that no user or
// group has, and for each account one number free as a user ID, a group
// ID, any user's primary group and any of the owner's groups. It prefers
// 6201 and 6202. The keyholder's system IDs are free the same way
// (deploy.PickKeyholderIDs). assets/create-users.sh repeats every check
// before it creates anything; this is the proposal, not the authority.
func PickIDs(d Directory, c Choices, owner Account) (IDs, error) {
	for _, name := range []string{c.ControllerUser, c.JobUser} {
		if name == owner.Name {
			return IDs{}, fmt.Errorf("account name %s is your own login", name)
		}
		for _, list := range [][]deploy.DirectoryRecord{d.Users, d.Groups} {
			for _, r := range list {
				if r.Name == name {
					return IDs{}, fmt.Errorf("an account or group named %s already exists", name)
				}
			}
		}
	}
	taken := map[int64]bool{}
	for _, list := range [][]deploy.DirectoryRecord{d.Users, d.Groups, d.UserPrimaryGroups} {
		for _, r := range list {
			taken[r.ID] = true
		}
	}
	for _, gid := range owner.GIDs {
		taken[int64(gid)] = true
	}
	taken[int64(owner.UID)] = true
	var free []uint32
	for id := int64(firstID); id <= lastID && len(free) < 2; id++ {
		if !taken[id] {
			free = append(free, uint32(id))
		}
	}
	if len(free) < 2 {
		return IDs{}, fmt.Errorf("no two free user/group IDs in %d-%d", firstID, lastID)
	}
	keyholderUID, keyholderGID, keyRPCGID, err := deploy.PickKeyholderIDs(taken)
	if err != nil {
		return IDs{}, err
	}
	return IDs{ControllerUID: free[0], ControllerGID: free[0], JobUID: free[1], JobGID: free[1], KeyholderUID: keyholderUID, KeyholderGID: keyholderGID, KeyRPCGID: keyRPCGID}, nil
}

// SelectAddresses returns the Tailscale address the API binds to and the
// HOST_ADDRESSES list: the tailnet address first, then every other
// interface address that the deploy parser accepts as a host alias
// (loopback, link-local, multicast and unspecified addresses excluded).
// IPv4 is preferred; more than one tailnet address of the chosen family is
// ambiguous.
func SelectAddresses(addrs []netip.Addr) (netip.Addr, []string, error) {
	var v4, v6, others []netip.Addr
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
			continue
		}
		switch {
		case tailnetV4.Contains(a):
			v4 = append(v4, a)
		case tailnetV6.Contains(a):
			v6 = append(v6, a)
		default:
			others = append(others, a)
		}
	}
	v4, v6 = sortedUnique(v4), sortedUnique(v6)
	var tailnet netip.Addr
	switch {
	case len(v4) == 1:
		tailnet = v4[0]
	case len(v4) > 1:
		return netip.Addr{}, nil, errors.New("more than one Tailscale IPv4 address on this Mac")
	case len(v6) == 1:
		tailnet = v6[0]
	case len(v6) > 1:
		return netip.Addr{}, nil, errors.New("more than one Tailscale IPv6 address on this Mac")
	default:
		return netip.Addr{}, nil, errors.New("no Tailscale address (100.64.0.0/10 or fd7a:115c:a1e0::/48) on this Mac")
	}
	hosts := []string{tailnet.String()}
	for _, a := range sortedUnique(slices.Concat(v4, v6, others)) {
		if a != tailnet {
			hosts = append(hosts, a.String())
		}
	}
	return tailnet, hosts, nil
}

func sortedUnique(a []netip.Addr) []netip.Addr {
	a = slices.Clone(a)
	slices.SortFunc(a, func(x, y netip.Addr) int { return x.Compare(y) })
	return slices.Compact(a)
}

// EnvironmentFacts are the detected values deploy.env is generated from.
type EnvironmentFacts struct {
	Owner         Account
	TailnetIP     netip.Addr
	HostAddresses []string
	Port          uint16
	DeveloperDir  string
}

type envEntry struct{ key, value string }

// RenderEnvironment generates deploy.env: the intended keys in a fixed
// order, one line each. deploy.ParseEnvironment (the deploy-install parser)
// must read it as exactly the intended values, so a value that adds a line,
// comment or key (such as COEXISTING_*) changes its own parsed value and is
// refused. Without a repository (before the GitHub step) REPOSITORIES is
// omitted from the result and a stand-in pin is used for the parser check.
func RenderEnvironment(f EnvironmentFacts, c Choices, ids IDs) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	u := func(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
	port := strconv.FormatUint(uint64(f.Port), 10)
	entries := []envEntry{
		{"CONTROLLER_USER", c.ControllerUser},
		{"CONTROLLER_UID", u(ids.ControllerUID)},
		{"CONTROLLER_GID", u(ids.ControllerGID)},
		{"JOB_USER", c.JobUser},
		{"JOB_REAL_NAME", c.JobRealName},
		{"JOB_UID", u(ids.JobUID)},
		{"JOB_GID", u(ids.JobGID)},
		{"OWNER_USER", f.Owner.Name},
		{"OWNER_UID", u(f.Owner.UID)},
		{"TAILNET_IP", f.TailnetIP.String()},
		{"PORT", port},
		{"PROTECTED_PORTS", port},
		{"HOST_ADDRESSES", strings.Join(f.HostAddresses, ",")},
		{"DEVELOPER_DIR", f.DeveloperDir},
		{"KEYHOLDER_UID", u(ids.KeyholderUID)},
		{"KEYHOLDER_GID", u(ids.KeyholderGID)},
		{"KEYRPC_GID", u(ids.KeyRPCGID)},
	}
	repoName, repoID := pendingRepositoryName, int64(pendingRepositoryID)
	if c.Repository != "" {
		repoName, repoID, _ = parseRepository(c.Repository)
		entries = append(entries, envEntry{"REPOSITORIES", c.Repository})
	}
	var out bytes.Buffer
	for _, e := range entries {
		out.WriteString(e.key + "=" + e.value + "\n")
	}
	check := out.Bytes()
	if c.Repository == "" {
		check = append(bytes.Clone(check), "REPOSITORIES="+pendingRepositoryName+":"+strconv.FormatInt(pendingRepositoryID, 10)+"\n"...)
	}
	want := deploy.Environment{
		ControllerUser: c.ControllerUser, ControllerUID: ids.ControllerUID, ControllerGID: ids.ControllerGID,
		JobUser: c.JobUser, JobRealName: c.JobRealName, JobUID: ids.JobUID, JobGID: ids.JobGID,
		OwnerUser: f.Owner.Name, OwnerUID: f.Owner.UID,
		TailnetIP: f.TailnetIP.String(), Port: f.Port, ProtectedPorts: []uint16{f.Port},
		HostAddresses: f.HostAddresses, DeveloperDir: f.DeveloperDir,
		Repositories: map[string]int64{repoName: repoID},
		KeyholderUID: ids.KeyholderUID, KeyholderGID: ids.KeyholderGID, KeyRPCGID: ids.KeyRPCGID,
	}
	if err := exactEnvironment(check, want); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// exactEnvironment requires the deploy-install parser to read data as
// exactly want: no other key (such as COEXISTING_*) and no changed value.
func exactEnvironment(data []byte, want deploy.Environment) error {
	parsed, err := deploy.ParseEnvironment(data)
	if err != nil {
		return fmt.Errorf("generated deploy.env is invalid: %w", err)
	}
	if !reflect.DeepEqual(parsed, want) {
		return errors.New("deploy-install would read the generated deploy.env differently than intended")
	}
	return nil
}
