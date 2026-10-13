package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jerryfane/macserve/internal/hostguard"
)

// PersistenceManifest is also the review-candidate format. A candidate is not
// authority: only the separate digest-pinned accept operation writes the
// protected configured path. Problems make a candidate unconditionally invalid.
type PersistenceManifest struct {
	Version  int                       `json:"version"`
	JobUID   uint32                    `json:"job_uid"`
	OSBuild  string                    `json:"os_build"`
	Census   BTMCensus                 `json:"census"`
	Code     map[string]RegisteredCode `json:"code"`
	Problems []string                  `json:"problems,omitempty"`
}

func persistenceBytes(m PersistenceManifest) ([]byte, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	return append(data, '\n'), err
}

func persistenceHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readPersistence(path string, uid uint32) (PersistenceManifest, []byte, error) {
	return readPersistenceContext(context.Background(), path, uid)
}

func readPersistenceContext(ctx context.Context, path string, uid uint32) (PersistenceManifest, []byte, error) {
	var m PersistenceManifest
	if err := ctx.Err(); err != nil {
		return m, nil, err
	}
	var protectionErr error
	if runtime.GOOS == "darwin" {
		protectionErr = hostguard.CheckProtectedPathContext(ctx, path, false)
	} else {
		// Native inspection/acceptance are Darwin-only. Portable readers/tests
		// still enforce the root-owned, non-writable authority file contract.
		protectionErr = hostguard.RootConfig(path)
	}
	if protectionErr != nil {
		return m, nil, protectionErr
	}
	file, err := os.Open(path)
	if err != nil {
		return m, nil, err
	}
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		file.Close()
		return m, nil, errors.New("persistence review data must have mode 0600")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return m, nil, errors.New("reviewed persistence file unreadable or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return m, nil, err
	}
	canonical, err := persistenceBytes(m)
	if err != nil || !bytes.Equal(canonical, data) {
		return m, nil, errors.New("persistence file must be canonical generated JSON, without duplicate or trailing data")
	}
	if m.Version != 1 || m.JobUID != uid || m.OSBuild == "" || len(m.Problems) != 0 || m.Census.Identifier == "" || m.Code == nil {
		return m, nil, errors.New("reviewed persistence authority is incomplete or belongs to another account")
	}
	paths, problems := registrationPaths(m.Census)
	if len(problems) != 0 || len(paths) != len(m.Code) {
		return m, nil, errors.New("persistence manifest contains unresolved registrations")
	}
	for id, path := range paths {
		code, ok := m.Code[id]
		if !ok || code.Path != path || code.TreeSHA256 == "" || code.CDHash == "" || code.Requirement == "" {
			return m, nil, errors.New("persistence manifest contains incomplete code binding")
		}
	}
	return m, data, nil
}

// PersistenceDigest is consumed by host qualification: replacing the manifest
// invalidates previous approval even if the GUI PID baseline is unchanged.
func PersistenceDigest(path string, uid uint32) (string, error) {
	_, data, err := readPersistence(path, uid)
	if err != nil {
		return "", err
	}
	return persistenceHash(data), nil
}

func backgroundCensus(ctx context.Context, options Options) (BTMCensus, error) {
	out, diagnostic, err := inspectCommand(ctx, nil, "/usr/bin/sfltool", "dumpbtm")
	if err != nil || strings.TrimSpace(diagnostic) != "" {
		return BTMCensus{}, errors.New("background census unavailable")
	}
	census, err := parseBackgroundItems(out, options.JobUID)
	if err != nil {
		return census, err
	}
	return withoutOwnServices(ctx, census, options.HelperPath, verifyOwnService)
}

func collectPersistence(ctx context.Context, options Options) (PersistenceManifest, error) {
	ctx, cancel := context.WithTimeout(ctx, PersistenceFullScanTimeout)
	defer cancel()
	m := PersistenceManifest{Version: 1, JobUID: options.JobUID, Code: map[string]RegisteredCode{}}
	if runtime.GOOS != "darwin" {
		return m, errors.New("native registration inspection requires macOS")
	}
	writers, err := registrationWriterPolicy(ctx, options)
	if err != nil {
		return m, err
	}
	build, diagnostic, err := inspectCommand(ctx, nil, "/usr/bin/sw_vers", "-buildVersion")
	if err != nil || strings.TrimSpace(diagnostic) != "" || strings.TrimSpace(build) == "" {
		return m, errors.New("OS build unavailable")
	}
	m.OSBuild = strings.TrimSpace(build)
	m.Census, err = backgroundCensus(ctx, options)
	if err != nil {
		return m, err
	}
	if err := collectRegistrationCode(ctx, &m, writers, protectedTreeACL, protectedTreeDigest, codeCommand); err != nil {
		return m, err
	}
	if _, err := registrationWriterPolicy(ctx, options); err != nil {
		return m, err
	}
	if err := ctx.Err(); err != nil {
		return m, err
	}
	second, err := backgroundCensus(ctx, options)
	if err != nil {
		return m, err
	}
	firstJSON, _ := json.Marshal(m.Census)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		return m, errors.New("background registrations changed during inspection")
	}
	return m, nil
}

// Collect successful measurements separately from failures so only measured
// trees enter the signing-race recheck. Failed trees remain candidate Problems.
func collectRegistrationCode(ctx context.Context, m *PersistenceManifest, writers registrationWriters, treeACL func(context.Context, string, registrationWriters) error, treeDigest func(context.Context, string, registrationWriters) (string, error), command func(context.Context, ...string) (string, error)) error {
	paths, problems := registrationPaths(m.Census)
	m.Problems = problems
	trees := map[string]string{}
	treeErrors := map[string]error{}
	byID := map[string]BTMRecord{}
	for _, r := range m.Census.Records {
		byID[r.Fields["Identifier"]] = r
	}
	for _, r := range m.Census.Records {
		id := r.Fields["Identifier"]
		path, ok := paths[id]
		if !ok {
			continue
		}
		root := path
		if parent := r.Fields["Parent Identifier"]; parent != "" {
			root = byID[parent].Fields["URL"]
		}
		if _, ok := trees[root]; !ok && treeErrors[root] == nil {
			treeErrors[root] = treeACL(ctx, root, writers)
			if treeErrors[root] == nil {
				digest, err := treeDigest(ctx, root, writers)
				if err != nil {
					treeErrors[root] = err
				} else {
					trees[root] = digest
				}
			}
		}
		if treeErrors[root] != nil {
			m.Problems = append(m.Problems, id+": protected code tree unavailable: "+treeErrors[root].Error())
			continue
		}
		code, err := verifyRegisteredCode(ctx, path, r, writers, command)
		// Preserve a successfully measured tree even if subsequent signature
		// inspection fails; changed bytes are positive evidence, not just an
		// inability to inspect the signing identity.
		code.Path, code.TreeRoot, code.TreeSHA256 = path, root, trees[root]
		m.Code[id] = code
		if err != nil {
			m.Problems = append(m.Problems, id+": "+err.Error())
		}
	}
	// Signing commands must not bridge a changed tree or mutable ancestry.
	// Recheck ACLs too: a newly granted writer need not change any code bytes.
	for root, before := range trees {
		if err := treeACL(ctx, root, writers); err != nil {
			return err
		}
		after, err := treeDigest(ctx, root, writers)
		if err != nil {
			return err
		}
		if before != after {
			return errors.New("registered code tree changed during inspection")
		}
	}
	return nil
}

func matchPersistence(expected, current PersistenceManifest) error {
	if err := matchPersistenceCensus(expected, current.OSBuild, current.Census); err != nil {
		return err
	}
	for id, code := range current.Code {
		if reviewed, ok := expected.Code[id]; ok && code.TreeSHA256 != "" && code.TreeSHA256 != reviewed.TreeSHA256 {
			return fmt.Errorf("%w: registered code tree changed", ErrContamination)
		}
	}
	if len(current.Problems) != 0 {
		return errors.New("registered code inspection incomplete or protection unavailable")
	}
	accepted, err := persistenceBytes(expected)
	if err != nil {
		return err
	}
	actual, err := persistenceBytes(current)
	if err != nil {
		return err
	}
	if !bytes.Equal(accepted, actual) {
		return fmt.Errorf("%w: registered code or review binding changed", ErrContamination)
	}
	return nil
}

// ReviewPersistence writes only an exclusive root-private candidate. It never
// imports authority, removes persistence, changes quarantine or signals a PID.
func ReviewPersistence(ctx context.Context, options Options, output string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, PersistenceOperationTimeout)
	defer cancel()
	if err := hostguard.BrokerIdentity(options.JobUID, options.JobGID, options.ControllerUID, options.OwnerUID); err != nil {
		return "", err
	}
	if output == options.PersistencePath || output == options.BaselinePath || output == options.HelperPath || output == filepath.Join(filepath.Dir(options.PersistencePath), persistenceAttestationFile) || output == filepath.Join(filepath.Dir(options.PersistencePath), persistenceAttestationFile+".lock") || output == filepath.Join(filepath.Dir(options.PersistencePath), persistenceAttestationFile+".scan.lock") {
		return "", errors.New("candidate must be separate from trusted state")
	}
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return "", errors.New("candidate requires a clean absolute path")
	}
	if err := hostguard.CheckProtectedPath(filepath.Dir(output), true); err != nil {
		return "", err
	}
	candidate, err := collectPersistence(ctx, options)
	if err != nil {
		return "", err
	}
	data, err := persistenceBytes(candidate)
	if err != nil || len(data) > 1<<20 {
		return "", errors.New("review candidate exceeds format bound")
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if len(candidate.Problems) != 0 {
		return persistenceHash(data), errors.New("private candidate records unresolved registrations; acceptance is prohibited")
	}
	return persistenceHash(data), nil
}

// AcceptPersistence is deliberately separate from inspection and reset. Root
// must supply the digest of the exact individually reviewed candidate. A second
// live inspection must match it, under the same exclusive broker ownership lock.
func AcceptPersistence(ctx context.Context, options Options, candidate, reviewedSHA256 string) error {
	ctx, cancel := context.WithTimeout(ctx, PersistenceOperationTimeout)
	defer cancel()
	if len(reviewedSHA256) != 64 {
		return errors.New("explicit reviewed candidate SHA256 required")
	}
	if _, err := hex.DecodeString(reviewedSHA256); err != nil {
		return errors.New("invalid reviewed candidate SHA256")
	}
	if candidate == options.PersistencePath {
		return errors.New("accept requires a separate review candidate")
	}
	if err := hostguard.BrokerIdentity(options.JobUID, options.JobGID, options.ControllerUID, options.OwnerUID); err != nil {
		return err
	}
	options.Runner = nil
	engine, err := New(options)
	if err != nil {
		return fmt.Errorf("stop broker before accepting reviewed persistence: %w", err)
	}
	defer engine.Close()
	_, data, err := readPersistence(candidate, options.JobUID)
	if err != nil {
		return err
	}
	if persistenceHash(data) != reviewedSHA256 {
		return errors.New("reviewed candidate digest mismatch")
	}
	current, err := collectPersistence(ctx, options)
	if err != nil {
		return err
	}
	actual, err := persistenceBytes(current)
	if err != nil {
		return err
	}
	if len(current.Problems) != 0 || !bytes.Equal(data, actual) {
		return errors.New("live registrations or code differ from reviewed candidate")
	}
	if err := hostguard.CheckProtectedPath(filepath.Dir(options.PersistencePath), true); err != nil {
		return err
	}
	if _, err := os.Lstat(options.PersistencePath); err == nil {
		if err := hostguard.CheckProtectedPath(options.PersistencePath, false); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	parent, err := os.OpenRoot(filepath.Dir(options.PersistencePath))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := durableFile(parent, filepath.Base(options.PersistencePath), data); err != nil {
		return err
	}
	return markPersistenceReviewed(options)
}
