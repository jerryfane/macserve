// Package deploy implements the reviewed, disabled-service deployment workflow.
package deploy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/maintenance"
)

const MaxEnvironment = 64 << 10

type Environment struct {
	ControllerUser               string
	ControllerUID, ControllerGID uint32
	JobUser                      string
	JobRealName                  string
	JobUID, JobGID               uint32
	OwnerUser                    string
	OwnerUID                     uint32
	TailnetIP                    string
	Port                         uint16
	ProtectedPorts               []uint16
	HostAddresses                []string
	DeveloperDir                 string
	Repositories                 map[string]int64
	CoexistingAnchors            []string
	CoexistingServices           []string
	// SignerUID, SignerGID and SignRPCGID are the optional code signer's
	// system account, its dedicated primary group and the RPC group shared
	// only with the controller. All three are zero when no signer is deployed.
	SignerUID, SignerGID, SignRPCGID uint32
	// KeyholderUID, KeyholderGID and KeyRPCGID are the keyholder's system
	// account, its dedicated primary group and the RPC group shared only
	// with the controller. deploy-install requires them; all three are zero
	// in an installation from before the keyholder.
	KeyholderUID, KeyholderGID, KeyRPCGID uint32
}

var accountName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
var repositoryName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9._-]*$`)
var developerPath = regexp.MustCompile(`^/[A-Za-z0-9 /_.+-]+$`)
var interfaceZone = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,63}$`)

// ParseEnvironment accepts data, not shell syntax. Quotes and expansions are rejected.
func ParseEnvironment(data []byte) (Environment, error) {
	var e Environment
	if len(data) == 0 || len(data) > MaxEnvironment || bytes.ContainsAny(data, "\x00\r") {
		return e, errors.New("environment must be bounded LF-delimited data")
	}
	keys := strings.Fields("CONTROLLER_USER CONTROLLER_UID CONTROLLER_GID JOB_USER JOB_UID JOB_GID OWNER_USER OWNER_UID TAILNET_IP PORT PROTECTED_PORTS HOST_ADDRESSES DEVELOPER_DIR REPOSITORIES")
	values := make(map[string]string, len(keys))
	allowed := make(map[string]bool, len(keys))
	for _, k := range keys {
		allowed[k] = true
	}
	for _, k := range strings.Fields("COEXISTING_ANCHORS COEXISTING_SERVICES JOB_REAL_NAME SIGNER_UID SIGNER_GID SIGNRPC_GID KEYHOLDER_UID KEYHOLDER_GID KEYRPC_GID") {
		allowed[k] = true
	}
	for n, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		_, duplicate := values[k]
		if !ok || !allowed[k] || duplicate || strings.TrimSpace(v) != v || strings.ContainsAny(v, "\t\"'`$\\{};<>!\n") {
			return e, fmt.Errorf("invalid, duplicate or unknown environment entry on line %d", n+1)
		}
		values[k] = v
	}
	for _, k := range keys {
		if values[k] == "" {
			return e, fmt.Errorf("missing environment key %s", k)
		}
	}
	e.ControllerUser, e.JobUser, e.OwnerUser = values["CONTROLLER_USER"], values["JOB_USER"], values["OWNER_USER"]
	e.JobRealName = "macserve build"
	if name, present := values["JOB_REAL_NAME"]; present {
		if name == "" {
			return e, errors.New("JOB_REAL_NAME must not be empty")
		}
		for _, r := range name {
			if r < 0x20 || r == 0x7f {
				return e, errors.New("JOB_REAL_NAME must not contain control characters")
			}
		}
		e.JobRealName = name
	}
	for _, name := range []string{e.ControllerUser, e.JobUser, e.OwnerUser} {
		if !accountName.MatchString(name) || strings.Contains(" root wheel admin staff daemon nobody operator everyone guest ", " "+name+" ") {
			return e, errors.New("invalid or reserved identity name")
		}
	}
	if e.ControllerUser == e.JobUser || e.ControllerUser == e.OwnerUser || e.JobUser == e.OwnerUser {
		return e, errors.New("identity names must differ")
	}
	ids := []*uint32{&e.ControllerUID, &e.ControllerGID, &e.JobUID, &e.JobGID, &e.OwnerUID}
	for i, k := range []string{"CONTROLLER_UID", "CONTROLLER_GID", "JOB_UID", "JOB_GID", "OWNER_UID"} {
		n, err := canonicalNumber(values[k], 999999999)
		if err != nil || n < 501 {
			return e, fmt.Errorf("invalid %s", k)
		}
		*ids[i] = uint32(n)
	}
	if e.ControllerUID == e.JobUID || e.ControllerUID == e.OwnerUID || e.JobUID == e.OwnerUID || e.ControllerGID == e.JobGID {
		return e, errors.New("identity IDs conflict")
	}
	if err := parseSigner(&e, values); err != nil {
		return e, err
	}
	if err := parseKeyholder(&e, values); err != nil {
		return e, err
	}
	ip, err := canonicalAddress(values["TAILNET_IP"])
	if err != nil || !(netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip)) {
		return e, errors.New("TAILNET_IP must be a canonical tailnet address")
	}
	e.TailnetIP = ip.String()
	n, err := canonicalNumber(values["PORT"], 65535)
	if err != nil {
		return e, errors.New("invalid PORT")
	}
	e.Port = uint16(n)
	seenPorts := map[uint16]bool{}
	for _, s := range strings.Split(values["PROTECTED_PORTS"], ",") {
		n, err := canonicalNumber(s, 65535)
		if err != nil || seenPorts[uint16(n)] {
			return e, errors.New("invalid or repeated protected port")
		}
		seenPorts[uint16(n)] = true
		e.ProtectedPorts = append(e.ProtectedPorts, uint16(n))
	}
	if !seenPorts[e.Port] {
		return e, errors.New("PROTECTED_PORTS must include PORT")
	}
	seenAddresses := map[string]bool{}
	for _, s := range strings.Split(values["HOST_ADDRESSES"], ",") {
		_, err := canonicalHostAddress(s)
		if err != nil || seenAddresses[s] {
			return e, errors.New("invalid or repeated host address")
		}
		seenAddresses[s] = true
		e.HostAddresses = append(e.HostAddresses, s)
	}
	if !seenAddresses[e.TailnetIP] {
		return e, errors.New("HOST_ADDRESSES must include TAILNET_IP")
	}
	e.DeveloperDir = values["DEVELOPER_DIR"]
	if !developerPath.MatchString(e.DeveloperDir) || filepath.Clean(e.DeveloperDir) != e.DeveloperDir || e.DeveloperDir == "/" {
		return e, errors.New("DEVELOPER_DIR must be a clean literal absolute path")
	}
	e.Repositories = map[string]int64{}
	seenIDs := map[uint64]bool{}
	for _, pin := range strings.Split(values["REPOSITORIES"], ",") {
		name, id, ok := strings.Cut(pin, ":")
		n, err := canonicalNumber(id, 9007199254740991)
		owner, repo, split := strings.Cut(name, "/")
		if !ok || !split || err != nil || !repositoryName.MatchString(name) || len(owner) > 100 || len(repo) > 100 || strings.Contains(name, "..") || strings.HasSuffix(name, ".git") || e.Repositories[name] != 0 || seenIDs[n] || len(e.Repositories) >= 1000 {
			return e, errors.New("invalid, aliased or repeated repository pin")
		}
		e.Repositories[name] = int64(n)
		seenIDs[n] = true
	}
	list := func(key string) []string {
		if values[key] == "" {
			return nil
		}
		return strings.Split(values[key], ",")
	}
	coexistence := maintenance.Config{
		CoexistingAnchors:  list("COEXISTING_ANCHORS"),
		CoexistingServices: list("COEXISTING_SERVICES"),
	}
	if err := maintenance.ValidateCoexistenceConfig(&coexistence); err != nil {
		return e, fmt.Errorf("deploy coexistence configuration: %w", err)
	}
	e.CoexistingAnchors, e.CoexistingServices = coexistence.CoexistingAnchors, coexistence.CoexistingServices
	return e, nil
}

// parseSigner reads the optional SIGNER_UID, SIGNER_GID and SIGNRPC_GID:
// all three or none. They are system IDs (200..499), so never a service,
// job or owner ID, and the signer's two groups differ from each other.
func parseSigner(e *Environment, values map[string]string) error {
	keys := []string{"SIGNER_UID", "SIGNER_GID", "SIGNRPC_GID"}
	present := 0
	for _, k := range keys {
		if _, ok := values[k]; ok {
			present++
		}
	}
	if present == 0 {
		return nil
	}
	if present != len(keys) {
		return errors.New("SIGNER_UID, SIGNER_GID and SIGNRPC_GID are required together")
	}
	ids := []*uint32{&e.SignerUID, &e.SignerGID, &e.SignRPCGID}
	for i, k := range keys {
		n, err := canonicalNumber(values[k], SignerMaxID)
		if err != nil || n < SignerMinID {
			return fmt.Errorf("invalid %s: signer IDs are system IDs %d..%d", k, SignerMinID, SignerMaxID)
		}
		*ids[i] = uint32(n)
	}
	for _, uid := range []uint32{e.ControllerUID, e.JobUID, e.OwnerUID} {
		if e.SignerUID == uid {
			return errors.New("SIGNER_UID must differ from the controller, job and owner UIDs")
		}
	}
	for _, gid := range []uint32{e.ControllerGID, e.JobGID} {
		if e.SignerGID == gid || e.SignRPCGID == gid {
			return errors.New("signer GIDs must differ from the controller and job GIDs")
		}
	}
	if e.SignerGID == e.SignRPCGID {
		return errors.New("SIGNER_GID and SIGNRPC_GID must differ")
	}
	return nil
}

// parseKeyholder reads the optional KEYHOLDER_UID, KEYHOLDER_GID and
// KEYRPC_GID: all three or none. They are system IDs (200..499), so never a
// service, job or owner ID; the keyholder's two groups differ from each
// other and from the signer's, and its UID is not the signer's.
func parseKeyholder(e *Environment, values map[string]string) error {
	keys := []string{"KEYHOLDER_UID", "KEYHOLDER_GID", "KEYRPC_GID"}
	present := 0
	for _, k := range keys {
		if _, ok := values[k]; ok {
			present++
		}
	}
	if present == 0 {
		return nil
	}
	if present != len(keys) {
		return errors.New("KEYHOLDER_UID, KEYHOLDER_GID and KEYRPC_GID are required together")
	}
	ids := []*uint32{&e.KeyholderUID, &e.KeyholderGID, &e.KeyRPCGID}
	for i, k := range keys {
		n, err := canonicalNumber(values[k], SignerMaxID)
		if err != nil || n < SignerMinID {
			return fmt.Errorf("invalid %s: keyholder IDs are system IDs %d..%d", k, SignerMinID, SignerMaxID)
		}
		*ids[i] = uint32(n)
	}
	for _, uid := range []uint32{e.ControllerUID, e.JobUID, e.OwnerUID, e.SignerUID} {
		if e.KeyholderUID == uid {
			return errors.New("KEYHOLDER_UID must differ from the controller, job, owner and signer UIDs")
		}
	}
	for _, gid := range []uint32{e.ControllerGID, e.JobGID, e.SignerGID, e.SignRPCGID} {
		if gid != 0 && (e.KeyholderGID == gid || e.KeyRPCGID == gid) {
			return errors.New("keyholder GIDs must differ from the controller, job and signer GIDs")
		}
	}
	if e.KeyholderGID == e.KeyRPCGID {
		return errors.New("KEYHOLDER_GID and KEYRPC_GID must differ")
	}
	return nil
}
func canonicalNumber(s string, max uint64) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || n > max || strconv.FormatUint(n, 10) != s {
		return 0, errors.New("noncanonical number")
	}
	return n, nil
}
func canonicalAddress(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.String() != s || a.Is4In6() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("noncanonical or unsafe address")
	}
	return a, nil
}

func canonicalHostAddress(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err == nil && a.String() == s && a.IsLinkLocalUnicast() && !a.Is4In6() {
		if a.Zone() == "" || (a.Is6() && interfaceZone.MatchString(a.Zone())) {
			return a, nil
		}
	}
	return canonicalAddress(s)
}
func LoadEnvironment(path string) (Environment, error) {
	data, err := readRegular(path, MaxEnvironment)
	if err != nil {
		return Environment{}, err
	}
	return ParseEnvironment(data)
}
func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("input must be a bounded nonsymlink regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, actual) {
		return nil, errors.New("input changed during read")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("input exceeds limit")
	}
	return b, nil
}
