package setup

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
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
	portCandidates        = 16
)

// pendingRepository stands in for the GitHub step's pin when the plan runs
// before connect-github: it lets the rest of the environment be validated
// by the deploy parser, and is never printed or installed.
const pendingRepository = "pending/pending:1"

var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
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

// DirectoryRecord is one "name id" line of `dscl -list`.
type DirectoryRecord struct {
	Name string
	ID   int64
}

// Directory is what the local and search directory nodes already hold.
type Directory struct {
	Users             []DirectoryRecord // /Users UniqueID
	Groups            []DirectoryRecord // /Groups PrimaryGroupID
	UserPrimaryGroups []DirectoryRecord // /Users PrimaryGroupID
}

// IDs are the numeric identities setup will create.
type IDs struct {
	ControllerUID, ControllerGID, JobUID, JobGID uint32
}

// ParseDirectoryList parses `dscl NODE -list PATH KEY` output. Like
// assets/create-users.sh it fails closed on a record with extra fields or
// a non-integer value.
func ParseDirectoryList(out string) ([]DirectoryRecord, error) {
	var records []DirectoryRecord
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, errors.New("ambiguous directory record; review manually")
		}
		id, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return nil, errors.New("ambiguous directory record; review manually")
		}
		records = append(records, DirectoryRecord{Name: fields[0], ID: id})
	}
	return records, nil
}

// PickIDs chooses the controller and job identities: names that no user or
// group has, and for each account one number free as a user ID, a group
// ID, any user's primary group and any of the owner's groups. It prefers
// 6201 and 6202. assets/create-users.sh repeats every check before it
// creates anything; this is the proposal, not the authority.
func PickIDs(d Directory, c Choices, owner Account) (IDs, error) {
	for _, name := range []string{c.ControllerUser, c.JobUser} {
		if name == owner.Name {
			return IDs{}, fmt.Errorf("account name %s is your own login", name)
		}
		for _, list := range [][]DirectoryRecord{d.Users, d.Groups} {
			for _, r := range list {
				if r.Name == name {
					return IDs{}, fmt.Errorf("an account or group named %s already exists", name)
				}
			}
		}
	}
	taken := map[int64]bool{}
	for _, list := range [][]DirectoryRecord{d.Users, d.Groups, d.UserPrimaryGroups} {
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
	return IDs{ControllerUID: free[0], ControllerGID: free[0], JobUID: free[1], JobGID: free[1]}, nil
}

// SelectAddresses returns the Tailscale address the API binds to and the
// HOST_ADDRESSES list: the tailnet address first, then every other
// interface address that the deploy parser accepts as a host alias
// (loopback, link-local, multicast and unspecified addresses excluded).
// IPv4 is preferred; more than one tailnet address of the chosen family is
// ambiguous.
func SelectAddresses(addrs []netip.Addr) (netip.Addr, []string, error) {
	var v4, v6 []netip.Addr
	var others []netip.Addr
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

// RenderEnvironment generates deploy.env and validates it with the deploy
// parser that deploy-install uses. Without a repository (before the GitHub
// step) the REPOSITORIES key is omitted from the returned bytes, and the
// rest is validated with a stand-in pin.
func RenderEnvironment(f EnvironmentFacts, c Choices, ids IDs) ([]byte, deploy.Environment, error) {
	var b bytes.Buffer
	line := func(k, v string) { fmt.Fprintf(&b, "%s=%s\n", k, v) }
	u := func(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
	port := strconv.FormatUint(uint64(f.Port), 10)
	line("CONTROLLER_USER", c.ControllerUser)
	line("CONTROLLER_UID", u(ids.ControllerUID))
	line("CONTROLLER_GID", u(ids.ControllerGID))
	line("JOB_USER", c.JobUser)
	line("JOB_REAL_NAME", c.JobRealName)
	line("JOB_UID", u(ids.JobUID))
	line("JOB_GID", u(ids.JobGID))
	line("OWNER_USER", f.Owner.Name)
	line("OWNER_UID", u(f.Owner.UID))
	line("TAILNET_IP", f.TailnetIP.String())
	line("PORT", port)
	line("PROTECTED_PORTS", port)
	line("HOST_ADDRESSES", strings.Join(f.HostAddresses, ","))
	line("DEVELOPER_DIR", f.DeveloperDir)
	var check []byte
	if c.Repository != "" {
		line("REPOSITORIES", c.Repository)
		check = b.Bytes()
	} else {
		check = append(bytes.Clone(b.Bytes()), "REPOSITORIES="+pendingRepository+"\n"...)
	}
	env, err := deploy.ParseEnvironment(check)
	if err != nil {
		return nil, deploy.Environment{}, fmt.Errorf("generated deploy.env is invalid: %w", err)
	}
	if c.Repository == "" {
		env.Repositories = nil
	}
	return b.Bytes(), env, nil
}
