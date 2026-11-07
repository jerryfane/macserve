package setup

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/hostguard"
)

// github detects the connect-github result: controller.json has a github
// section whose policy repository deploy.env pins, and its App key exists.
// Only then is the step begun and completed; until then the ledger is
// unchanged and the wizard prints the commands to run.
func (h *Helper) github(l *Ledger, loc LedgerLocation) (Response, error) {
	if next, _, _ := l.Next(); next.Step != StepGitHub {
		return Response{}, fmt.Errorf("setup continues at %s, not github", next.Step)
	}
	e, _, err := h.installedEnv(l)
	if err != nil {
		return Response{}, err
	}
	raw, err := h.readConfig("controller.json", 1<<20)
	if err != nil {
		return Response{}, err
	}
	c, err := controllerconfig.LoadConfig(h.configPath("controller.json"))
	if err != nil {
		return Response{}, fmt.Errorf("controller.json: %w", err)
	}
	if c.GitHub == nil {
		return Response{Detail: "controller.json has no github section yet"}, nil
	}
	for _, p := range c.GitHub.Policies {
		if id, ok := e.Repositories[p.Repository]; !ok || id != p.RepositoryID {
			return Response{}, fmt.Errorf("the github policy for %s is not a repository deploy.env pins", p.Repository)
		}
	}
	if info, err := os.Lstat(c.GitHub.PrivateKeyFile); err != nil || !info.Mode().IsRegular() {
		return Response{}, fmt.Errorf("the App key %s is missing: %v", c.GitHub.PrivateKeyFile, err)
	}
	profiles, err := h.readConfig("profiles.json", 4<<20)
	if err != nil {
		return Response{}, err
	}
	boot, err := h.begin(l, loc, StepGitHub)
	if err != nil {
		return Response{}, err
	}
	inputs := map[string]string{"controller.json": digestHex(raw), "profiles.json": digestHex(profiles)}
	if err := h.complete(l, loc, StepGitHub, boot, inputs); err != nil {
		return Response{}, err
	}
	return Response{Done: true}, nil
}

// FDA detection. The transient job runs the installed macserve as a
// launchd daemon, the context the controller, worker and maintenance run
// in: an interactive check can pass while daemons are denied.
const (
	FDALabel = "org.macserve.setup.fda-check"
	// TCCDatabase is readable only with Full Disk Access, even by root.
	TCCDatabase = "/Library/Application Support/com.apple.TCC/TCC.db"
	fdaOut      = "fda-check.out"
)

// FDAGranted and FDADenied are the first word of the check's output.
const (
	FDAGranted = "granted"
	FDADenied  = "denied"
)

func (h *Helper) ownerActionsNext(l *Ledger) error {
	if next, _, _ := l.Next(); next.Step != StepOwnerActions {
		return fmt.Errorf("setup continues at %s, not owner-actions", next.Step)
	}
	return nil
}

func (h *Helper) fdaVerb(l *Ledger, loc LedgerLocation) (Response, error) {
	if err := h.ownerActionsNext(l); err != nil {
		return Response{}, err
	}
	if _, err := h.begin(l, loc, StepOwnerActions); err != nil {
		return Response{}, err
	}
	granted, detail, err := h.checkFDA()
	return Response{Done: granted, Detail: detail}, err
}

// jobLoginVerb checks the build account's GUI session and the console
// owner. At owner-actions it begins that step; before a round (the job
// account logs in again after the restart) it only checks.
func (h *Helper) jobLoginVerb(l *Ledger, loc LedgerLocation) (Response, error) {
	e, _, err := h.installedEnv(l)
	if err != nil {
		return Response{}, err
	}
	if next, _, _ := l.Next(); next.Step == StepOwnerActions {
		if _, err := h.begin(l, loc, StepOwnerActions); err != nil {
			return Response{}, err
		}
	}
	if ok, detail, err := h.jobLogoutGate(l, loc, e.JobUID); err != nil || !ok {
		return Response{Detail: detail}, err
	}
	ok, detail := h.checkJobLogin(e.JobUID, e.OwnerUID)
	return Response{Done: ok, Detail: detail}, nil
}

// ownerActions re-runs both checks itself and completes the step only if
// both pass. It records the installed binary's digest: Full Disk Access is
// granted to that binary.
func (h *Helper) ownerActions(l *Ledger, loc LedgerLocation) (Response, error) {
	if err := h.ownerActionsNext(l); err != nil {
		return Response{}, err
	}
	e, envData, err := h.installedEnv(l)
	if err != nil {
		return Response{}, err
	}
	boot, err := h.begin(l, loc, StepOwnerActions)
	if err != nil {
		return Response{}, err
	}
	granted, detail, err := h.checkFDA()
	if err != nil || !granted {
		return Response{Detail: detail}, err
	}
	if ok, detail, err := h.jobLogoutGate(l, loc, e.JobUID); err != nil || !ok {
		return Response{Detail: detail}, err
	}
	if ok, detail := h.checkJobLogin(e.JobUID, e.OwnerUID); !ok {
		return Response{Detail: detail}, nil
	}
	onDisk, err := h.installedBinary()
	if err != nil {
		return Response{}, err
	}
	bin, err := h.releaseDigest(deploy.BinaryName, onDisk)
	if err != nil {
		return Response{}, err
	}
	inputs := map[string]string{"deploy.env": digestHex(envData), "macserve": bin}
	if err := h.complete(l, loc, StepOwnerActions, boot, inputs); err != nil {
		return Response{}, err
	}
	return Response{Done: true}, nil
}

// installedBinary checks /Library/macserve/bin/macserve and returns its
// sha256.
func (h *Helper) installedBinary() (string, error) {
	return h.installedFile(h.installedPath())
}

// installedController checks /Library/macserve/bin/macserve-controller and
// returns its sha256; fs.ErrNotExist passes through (an installation from
// before the controller binary has none).
func (h *Helper) installedController() (string, error) {
	return h.installedFile(h.installedControllerPath())
}

// installedFile checks one installed binary (a root-owned regular file,
// not group- or world-writable, with one link) and returns its sha256.
func (h *Helper) installedFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	uid, _, nlink, ok := statOwner(info)
	if !ok || !info.Mode().IsRegular() || uid != h.Store.RootUID || info.Mode().Perm()&0o022 != 0 || nlink != 1 || info.Size() > maxBinary {
		return "", fmt.Errorf("%s must be a root-owned regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBinary+1))
	if err != nil {
		return "", err
	}
	return digestHex(data), nil
}

// installedBinariesName is deploy.InstalledBinariesPath under config/.
const installedBinariesName = "installed-binaries.json"

// installedBinaries reads config/installed-binaries.json, which the
// administrator's installer writes when it installs Developer ID signed
// binaries; nil when absent (the installed bytes are the release's).
func (h *Helper) installedBinaries() (*deploy.InstalledBinaries, error) {
	data, err := h.readConfig(installedBinariesName, 1<<16)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return deploy.ParseInstalledBinaries(data)
}

// releaseDigest maps the on-disk digest of the installed binary name
// (deploy.BinaryName or deploy.ControllerBinaryName) to its release digest
// through installed-binaries.json; without it they are equal. The ledger,
// SHA256SUMS and carry proofs hold release digests, so every comparison of
// an installed file with them goes through here. An absent binary ("")
// stays "".
func (h *Helper) releaseDigest(name, onDisk string) (string, error) {
	if onDisk == "" {
		return "", nil
	}
	inv, err := h.installedBinaries()
	if err != nil {
		return "", err
	}
	return inv.ReleaseDigest(name, onDisk)
}

// fdaPlist is the transient daemon: the installed macserve runs
// _fda-check once, its output goes to out.
func fdaPlist(binary, out string) []byte {
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + FDALabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + esc(binary) + `</string>
		<string>_fda-check</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
	<key>WorkingDirectory</key>
	<string>/</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>StandardOutPath</key>
	<string>` + esc(out) + `</string>
	<key>StandardErrorPath</key>
	<string>` + esc(out) + `</string>
</dict>
</plist>
`)
}

func launchctl(args ...string) Cmd {
	return Cmd{Argv: append([]string{"/bin/launchctl"}, args...), Env: []string{FixedPath}, Timeout: 30 * time.Second}
}

// checkFDA bootstraps the transient one-shot daemon in the system domain,
// waits for its result and boots it out again. Nothing else is loaded.
func (h *Helper) checkFDA() (bool, string, error) {
	binary := filepath.Join(h.Root, "bin", "macserve")
	if _, err := h.installedBinary(); err != nil {
		return false, "", err
	}
	if err := h.Store.EnsureStaging(); err != nil {
		return false, "", err
	}
	plist, out := h.Store.staged(FDALabel+".plist"), h.Store.staged(fdaOut)
	ctx := context.Background()
	_ = h.Probe(ctx, launchctl("bootout", "system/"+FDALabel))
	for _, path := range []string{plist, out} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, "", err
		}
	}
	if err := h.Store.writeFile(plist, fdaPlist(binary, out), 0o644); err != nil {
		return false, "", err
	}
	defer func() {
		_ = h.Probe(ctx, launchctl("bootout", "system/"+FDALabel))
		_ = os.Remove(plist)
		_ = os.Remove(out)
	}()
	if err := h.Probe(ctx, launchctl("bootstrap", "system", plist)); err != nil {
		return false, "", fmt.Errorf("launchctl bootstrap of the Full Disk Access check: %w", err)
	}
	deadline := time.Now().Add(h.FDAWait)
	for {
		data, err := h.Store.readOutput(out, 4096)
		if err == nil {
			first, _, _ := strings.Cut(string(data), "\n")
			word, _, _ := strings.Cut(first, ":")
			switch word {
			case FDAGranted:
				return true, "Full Disk Access is granted to " + binary + " in launchd context", nil
			case FDADenied:
				return false, "Full Disk Access is not granted to " + binary + " in launchd context", nil
			}
			if strings.HasSuffix(string(data), "\n") {
				return false, "", fmt.Errorf("unexpected Full Disk Access check output %q", first)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return false, "", err
		}
		if time.Now().After(deadline) {
			return false, "", errors.New("the Full Disk Access check did not report in time")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// checkJobLogin applies the rule the worker uses: the job GUI domain
// exists (the job account logged in at loginwindow once) and the console
// is the owner or the login window (the job session is not in the
// foreground; hostguard.ConsoleAdmissible).
func (h *Helper) checkJobLogin(jobUID, ownerUID uint32) (bool, string) {
	if err := h.Probe(context.Background(), launchctl("print", "gui/"+strconv.FormatUint(uint64(jobUID), 10))); err != nil {
		return false, "the build account has no GUI session yet"
	}
	console, err := h.ConsoleUID()
	if err != nil {
		return false, "cannot read the console owner: " + err.Error()
	}
	if err := hostguard.ConsoleAdmissible(console, ownerUID); err != nil {
		return false, "the build account is in the foreground; use Switch User to return to your own login"
	}
	return true, "the build account is logged in in the background and you are at the screen"
}

// FDACheck is `macserve _fda-check`: run only by launchd (parent pid 1),
// it opens TCCDatabase read-only and prints granted or denied. open is
// os.Open outside tests.
func FDACheck(stdout io.Writer, ppid int, open func(string) (io.Closer, error)) int {
	if ppid != 1 {
		fmt.Fprintln(stdout, "not-launchd: _fda-check runs only as the transient launchd job macserve setup bootstraps")
		return 2
	}
	f, err := open(TCCDatabase)
	if err == nil {
		f.Close()
		fmt.Fprintln(stdout, FDAGranted)
		return 0
	}
	if errors.Is(err, fs.ErrPermission) {
		fmt.Fprintln(stdout, FDADenied+": "+err.Error())
		return 1
	}
	fmt.Fprintln(stdout, "error: "+err.Error())
	return 1
}
