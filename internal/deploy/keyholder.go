package deploy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/keyholder"
)

// The keyholder's fixed account, groups and paths. Owners, modes and the
// account policy are those of assets/create-users.sh, which creates them.
// The keyholder holds the job receipt key and the GitHub App key; the
// controller reaches it only through the RPC socket.
const (
	KeyholderAccount = "_macserve_key"
	KeyRPCGroup      = "_macserve_keyrpc"
	KeyholderLabel   = "org.macserve.keyholder"

	KeyholderConfigPath = Prefix + "/config/keyholder.json"
	// ReleaseScopePath is the owner-written release scope (root:wheel
	// 0644). deploy-install never creates it; absent, the keyholder
	// refuses every release receipt.
	ReleaseScopePath     = Prefix + "/config/release-scope.json"
	KeyholderStateDir    = Prefix + "/var/keyholder"
	KeyholderSecretsDir  = KeyholderStateDir + "/secrets"
	KeyholderReceiptsDir = KeyholderStateDir + "/receipts"
	KeyholderReleaseDir  = KeyholderStateDir + "/release"
	KeyholderLogDir      = KeyholderStateDir + "/log"
	KeyholderReceiptKey  = KeyholderSecretsDir + "/" + keyholder.ReceiptKeyName
	KeyholderAppKey      = KeyholderSecretsDir + "/" + keyholder.AppKeyName
	KeyholderSocketDir   = Prefix + "/var/keyholder-run"
	KeyholderSocket      = KeyholderSocketDir + "/keyholder.sock"
	KeyholderPlist       = "/Library/LaunchDaemons/" + KeyholderLabel + ".plist"

	// SealKeyPath is the root worker's build seal key, root:wheel 0600.
	SealKeyPath = Prefix + "/var/broker/seal-key.pem"
	// ProfilesPath and QualificationPath are the root registry and
	// qualification record worker.json names for lease admission.
	ProfilesPath      = Prefix + "/config/profiles.json"
	QualificationPath = Prefix + "/config/qualification.json"
	// ControllerConfigPath is controller.json.
	ControllerConfigPath = Prefix + "/config/controller.json"
)

// Keyholder reports whether the environment names the keyholder's IDs.
// deploy-install requires them; an installation from before the keyholder
// lacks them until macserve upgrade migrates it.
func (e Environment) Keyholder() bool { return e.KeyholderUID != 0 }

// SealKeyID names the worker seal key of the host hostID in the
// keyholder's pins and in worker.json.
func SealKeyID(hostID string) string { return "macserve-worker-" + hostID }

// KeyholderConfig is the keyholder.json deploy-install and the upgrade
// migration render: every path is the fixed layout and the worker seal key
// of this host is the only pinned seal key.
func KeyholderConfig(e Environment, sealKeyID, sealPublicKey string) keyholder.Config {
	return keyholder.Config{
		KeyholderUID: e.KeyholderUID, KeyholderGID: e.KeyholderGID, RPCGID: e.KeyRPCGID,
		ControllerUID: e.ControllerUID, JobUID: e.JobUID, JobGID: e.JobGID,
		StateDir: KeyholderStateDir, Socket: KeyholderSocket,
		ControllerConfig: ControllerConfigPath, ReleaseScopeFile: ReleaseScopePath,
		SealKeys: map[string]string{sealKeyID: sealPublicKey},
	}
}

// KeyholderSection is controller.json's keyholder section.
func KeyholderSection(e Environment) *controllerconfig.KeyholderConfig {
	return &controllerconfig.KeyholderConfig{Socket: KeyholderSocket, UID: e.KeyholderUID}
}

// KeyholderArgs are the create-users.sh options that add the keyholder.
func KeyholderArgs(e Environment) []string {
	if !e.Keyholder() {
		return nil
	}
	u := func(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
	return []string{"--keyholder-uid", u(e.KeyholderUID), "--keyholder-gid", u(e.KeyholderGID), "--keyrpc-gid", u(e.KeyRPCGID)}
}

// CreateUsersArgs are create-users.sh's identity options for e, without
// the signer, keyholder or mode options.
func CreateUsersArgs(e Environment) []string {
	u := func(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
	return []string{"--controller-user", e.ControllerUser, "--controller-uid", u(e.ControllerUID), "--controller-gid", u(e.ControllerGID), "--job-user", e.JobUser, "--job-real-name", e.JobRealName, "--job-uid", u(e.JobUID), "--job-gid", u(e.JobGID), "--owner-user", e.OwnerUser, "--owner-uid", u(e.OwnerUID)}
}

// DirectoryRecord is one "name id" line of `dscl -list`.
type DirectoryRecord struct {
	Name string
	ID   int64
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

// PickKeyholderIDs proposes KEYHOLDER_UID, KEYHOLDER_GID and KEYRPC_GID:
// system IDs (SignerMinID..SignerMaxID) that are in no taken set (every
// user ID, group ID and user primary group of the directory, and every ID
// the environment already names). The keyholder's UID and primary GID are
// one number; the RPC group is the next free one. It searches downwards
// from SignerMaxID, away from the low IDs macOS gives its own system
// accounts. create-users.sh repeats every collision check before it
// creates anything; this is the proposal, not the authority.
func PickKeyholderIDs(taken map[int64]bool) (uid, gid, rpc uint32, err error) {
	var free []uint32
	for id := int64(SignerMaxID); id >= SignerMinID && len(free) < 2; id-- {
		if !taken[id] {
			free = append(free, uint32(id))
		}
	}
	if len(free) < 2 {
		return 0, 0, 0, fmt.Errorf("no two free system IDs in %d-%d for the keyholder", SignerMinID, SignerMaxID)
	}
	return free[0], free[0], free[1], nil
}

// TakenIDs is every ID the environment names, for PickKeyholderIDs.
func (e Environment) TakenIDs() map[int64]bool {
	taken := map[int64]bool{}
	for _, id := range []uint32{e.ControllerUID, e.ControllerGID, e.JobUID, e.JobGID, e.OwnerUID, e.SignerUID, e.SignerGID, e.SignRPCGID, e.KeyholderUID, e.KeyholderGID, e.KeyRPCGID} {
		if id != 0 {
			taken[int64(id)] = true
		}
	}
	return taken
}

// KeyholderEnvironmentLines are the deploy.env lines that name the
// keyholder's IDs.
func KeyholderEnvironmentLines(uid, gid, rpc uint32) string {
	u := func(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
	return "KEYHOLDER_UID=" + u(uid) + "\nKEYHOLDER_GID=" + u(gid) + "\nKEYRPC_GID=" + u(rpc) + "\n"
}

// RenderKeyholderPlist renders the keyholder's launchd plist from the
// deploy assets as deploy-install does: literal markers only, and it must
// stay disabled and not run at load.
func RenderKeyholderPlist(assets map[string][]byte) ([]byte, error) {
	const name = "launchd/" + KeyholderLabel + ".plist.tmpl"
	source, ok := assets[name]
	if !ok {
		return nil, fmt.Errorf("missing asset %s", name)
	}
	rendered, err := Render(source, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := disabledPlist(rendered); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return rendered, nil
}
