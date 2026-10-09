package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/workerclient"
)

type Options struct {
	EnvironmentPath, BinaryPath, SHA256, AssetsPath string
	Apply                                           bool
}

// Install has no test bypass, alternate prefix, or injected native executor.
func Install(o Options, stdout, stderr io.Writer) error {
	if o.Apply && (runtime.GOOS != "darwin" || os.Getuid() != 0 || os.Geteuid() != 0) {
		return errors.New("--apply requires Darwin and real/effective root; no inspection performed")
	}
	if !validDigest(o.SHA256) {
		return errors.New("--sha256 requires a lowercase SHA-256 digest")
	}
	for _, path := range []string{o.EnvironmentPath, o.BinaryPath, o.AssetsPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("input paths must be clean absolute paths")
		}
	}
	if o.Apply {
		for _, path := range []string{o.EnvironmentPath, o.BinaryPath} {
			if err := CheckProtectedPath(path, false); err != nil {
				return err
			}
		}
		if err := CheckProtectedPath(o.AssetsPath, true); err != nil {
			return err
		}
	}
	envData, err := readRegular(o.EnvironmentPath, MaxEnvironment)
	if err != nil {
		return err
	}
	e, err := ParseEnvironment(envData)
	if err != nil {
		return err
	}
	if err := verifyBinary(o.BinaryPath, o.SHA256, nil); err != nil {
		return err
	}
	assets := map[string][]byte{}
	for _, name := range assetNames {
		path := filepath.Join(o.AssetsPath, name)
		if o.Apply {
			if err := CheckProtectedPath(path, false); err != nil {
				return err
			}
		}
		data, err := readRegular(path, 1<<20)
		if err != nil {
			return err
		}
		assets[name] = data
	}
	rendered, err := renderAssets(e, assets)
	if err != nil {
		return err
	}
	if !o.Apply {
		_, err := fmt.Fprintf(stdout, "PLAN ONLY: verified binary SHA256 %s.\nController: %s uid=%d gid=%d\nJob GUI: %s uid=%d gid=%d\nOwner: %s uid=%d\nTLS listener: %s port=%d\nPF protected ports: %v\nPF host addresses: %v\nDeveloper directory: %s\nRepository numeric pins: %v\nWould preflight root-controlled inputs and absent targets, run create-users --apply, install /Library/macserve, generate TLS/receipt keys and a hash-only API credential, and install three disabled launchd plists.\nProfiles remain empty; qualification/health absent; owner.pause set. No accounts, owner homes, services, PF, ACLs, passwords or GUI sessions inspected or changed. Apply requires an exclusive reviewed administration window.\n", o.SHA256, e.ControllerUser, e.ControllerUID, e.ControllerGID, e.JobUser, e.JobUID, e.JobGID, e.OwnerUser, e.OwnerUID, e.TailnetIP, e.Port, e.ProtectedPorts, e.HostAddresses, e.DeveloperDir, e.Repositories)
		return err
	}
	return apply(o, e, envData, assets, rendered, stdout, stderr)
}
func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}
func verifyBinary(path, expected string, destination io.Writer) error {
	if !validDigest(expected) {
		return errors.New("invalid binary digest")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 256<<20 {
		return errors.New("binary must be a bounded regular nonsymlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, actual) {
		return errors.New("binary changed while opening")
	}
	hash := sha256.New()
	var writer io.Writer = hash
	if destination != nil {
		writer = io.MultiWriter(hash, destination)
	}
	n, err := io.Copy(writer, io.LimitReader(f, (256<<20)+1))
	if err != nil {
		return err
	}
	if n != info.Size() || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("binary SHA-256 mismatch or changed input")
	}
	return nil
}

// CheckProtectedPath enforces root ownership, non-writable ancestors and native
// ACL protection. Deny-only ACLs cannot grant writes; other ACLs require review.
func CheckProtectedPath(path string, directory bool) error {
	var err error
	if directory {
		err = hostguard.RootDirectory(path)
	} else {
		err = hostguard.RootConfig(path)
	}
	if err != nil {
		return err
	}
	for current := path; ; current = filepath.Dir(current) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "/bin/ls", "-lde", current)
		cmd.Env = nativeEnv()
		output, runErr := cmd.Output()
		cancel()
		if runErr != nil {
			return fmt.Errorf("cannot inspect protected input ACL: %w", runErr)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")[1:] {
			if !strings.Contains(line, " deny ") {
				return fmt.Errorf("ACL requires manual review: %s", current)
			}
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}
func nativeEnv() []string {
	return []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "HOME=/private/var/root"}
}
func requireAbsent(paths []string) error {
	for _, path := range paths {
		_, err := os.Lstat(path)
		if err == nil {
			return fmt.Errorf("existing deployment target; no overwrite or retry: %s", path)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
func apply(o Options, e Environment, envData []byte, assets, rendered map[string][]byte, stdout, stderr io.Writer) (result error) {
	targets := []string{Prefix, "/Users/" + e.JobUser, "/Library/LaunchDaemons/org.macserve.controller.plist", "/Library/LaunchDaemons/org.macserve.worker.plist", "/Library/LaunchDaemons/org.macserve.maintenance.plist"}
	for _, dir := range []string{"/Library", "/Library/LaunchDaemons", "/Users", "/private/var/root"} {
		if err := CheckProtectedPath(dir, true); err != nil {
			return err
		}
	}
	if err := requireAbsent(targets); err != nil {
		return err
	}
	for _, path := range []string{"/usr/bin/plutil", "/bin/bash"} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0111 == 0 {
			return fmt.Errorf("required native tool unavailable: %s", path)
		}
	}
	stage, err := os.MkdirTemp("/private/var/root", ".macserve-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0700); err != nil {
		return err
	}
	stagedBinary := filepath.Join(stage, "macserve")
	f, err := os.OpenFile(stagedBinary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	err = verifyBinary(o.BinaryPath, o.SHA256, f)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	m, err := makeMaterial(e, envData, rendered, time.Now().UTC())
	if err != nil {
		return err
	}
	// Validate actual staged configs using the consumers before any account changes.
	for _, item := range m.Files {
		path := filepath.Join(stage, filepath.Base(item.Path))
		if err := os.WriteFile(path, item.Data, 0600); err != nil {
			return err
		}
		switch filepath.Base(path) {
		case "controller.json":
			if _, err := controller.LoadConfig(path); err != nil {
				return err
			}
		case "worker.json":
			if _, err := workerclient.LoadConfig(path); err != nil {
				return err
			}
		case "maintenance.json":
			if _, err := maintenance.LoadConfig(path); err != nil {
				return err
			}
		case "profiles.json":
			if _, err := profiles.Load(path); err != nil {
				return err
			}
		}
		if strings.HasSuffix(path, ".plist") {
			if err := nativeCommand(30*time.Second, stderr, "/usr/bin/plutil", "-lint", path); err != nil {
				return err
			}
		}
	}
	script := filepath.Join(stage, "create-users.sh")
	if err := os.WriteFile(script, assets["create-users.sh"], 0600); err != nil {
		return err
	}
	// Recheck destinations immediately before crossing the irreversible boundary.
	if err := requireAbsent(targets); err != nil {
		return err
	}
	tokenDelivery := false
	defer func() {
		if result != nil {
			credential := "API token was not emitted"
			if tokenDelivery {
				credential = "one-time API token delivery failed; treat any partially delivered credential as sensitive and rotate it through reviewed configuration"
			}
			result = fmt.Errorf("PARTIAL FAILURE: %w; no rollback attempted; do not rerun. Keep services disabled and manually reconcile the named accounts, job home, /Library/macserve and three launchd plists. %s", result, credential)
		}
	}()
	args := []string{script, "--controller-user", e.ControllerUser, "--controller-uid", strconv.FormatUint(uint64(e.ControllerUID), 10), "--controller-gid", strconv.FormatUint(uint64(e.ControllerGID), 10), "--job-user", e.JobUser, "--job-uid", strconv.FormatUint(uint64(e.JobUID), 10), "--job-gid", strconv.FormatUint(uint64(e.JobGID), 10), "--owner-user", e.OwnerUser, "--owner-uid", strconv.FormatUint(uint64(e.OwnerUID), 10), "--apply"}
	if err := nativeCommand(2*time.Minute, stderr, "/bin/bash", args...); err != nil {
		return err
	}
	if err := installBinary(stagedBinary, o.SHA256); err != nil {
		return err
	}
	if err := installFile(File{Prefix + "/bin/qualify.sh", assets["qualify.sh"], 0755, 0, 0}, e); err != nil {
		return err
	}
	for _, item := range m.Files {
		if err := installFile(item, e); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(stdout, "Installed with every service disabled; PF unchanged; empty profiles and owner.pause require reviewed qualification. Public verification pins: %s/config/deployment-pins.json\n", Prefix); err != nil {
		return err
	}
	// This is the sole token emission. No persistent file ever contains it.
	tokenDelivery = true
	if _, err := fmt.Fprintf(stdout, "API_BEARER_TOKEN=%s\n", m.Token); err != nil {
		return errors.New("installation completed but one-time credential delivery failed; do not rerun; rotate the API credential through reviewed configuration")
	}
	return nil
}
func nativeCommand(timeout time.Duration, output io.Writer, path string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = "/"
	cmd.Env = nativeEnv()
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", path, err)
	}
	return nil
}
func installBinary(source, sha string) error {
	if err := CheckProtectedPath(Prefix+"/bin", true); err != nil {
		return err
	}
	f, err := os.OpenFile(Prefix+"/bin/macserve", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	err = verifyBinary(source, sha, f)
	if err == nil {
		err = f.Chown(0, 0)
	}
	if err == nil {
		err = f.Chmod(0755)
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
func installFile(item File, e Environment) error {
	// Traverse every ancestor without following links, including the private
	// controller-owned subtree created by create-users. No caller-provided roots.
	for current := filepath.Dir(item.Path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		uid := uint32(0)
		if current == Prefix+"/var/controller" || strings.HasPrefix(current, Prefix+"/var/controller/") {
			uid = e.ControllerUID
		}
		if !ok || !info.IsDir() || stat.Uid != uid || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("unsafe installation parent: %s", current)
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	f, err := os.OpenFile(item.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(item.Data)
	if err == nil {
		err = f.Chown(int(item.UID), int(item.GID))
	}
	if err == nil {
		err = f.Chmod(item.Mode)
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
