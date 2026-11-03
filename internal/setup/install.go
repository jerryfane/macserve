package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/jerryfane/macserve/assets"
	"github.com/jerryfane/macserve/internal/deploy"
)

// maxBinary is deploy-install's binary bound.
const maxBinary = 256 << 20

// install runs the install step: the deploy.env recorded at preflight,
// this macserve binary (its digest must equal SHA256) and the embedded
// assets are staged root-only, then deploy.Install applies them exactly as
// `deploy-install --apply` does, with the owner's terminal for the job
// password prompt and the one-time API token. On success the ledger moves
// into LedgerDir and the staged inputs are removed. A failure, or an
// interruption, blocks setup: deploy-install must not be rerun.
func (h *Helper) install(l *Ledger, loc LedgerLocation) (Response, error) {
	if r := l.record(StepInstall); r.Status == StatusRunning {
		return Response{}, errors.New("install was interrupted; deploy-install is not rerun. Keep services disabled and reconcile by hand: the controller and build accounts and groups, the build account's home, /Library/macserve and /Library/LaunchDaemons/org.macserve.{controller,worker,maintenance}.plist")
	}
	if next, _, _ := l.Next(); next.Step != StepInstall {
		return Response{}, fmt.Errorf("setup continues at %s, not install", next.Step)
	}
	if err := h.TerminalCheck(); err != nil {
		return Response{}, err
	}
	env, err := h.Store.StagedFile(stagedEnv, deploy.MaxEnvironment)
	if err != nil {
		return Response{}, fmt.Errorf("staged deploy.env: %w", err)
	}
	if digestHex(env) != l.record(StepPreflight).Inputs["deploy.env"] {
		return Response{}, errors.New("the staged deploy.env is not the one preflight recorded")
	}
	if err := h.stageBinary(); err != nil {
		return Response{}, err
	}
	if !slices.Equal(sortedKeys(h.Assets), slices.Sorted(slices.Values(assets.DeployNames))) {
		return Response{}, errors.New("the deploy assets of this release are incomplete")
	}
	if err := h.Store.StageTree(stagedAssets, h.Assets); err != nil {
		return Response{}, err
	}
	boot, err := h.begin(l, loc, StepInstall)
	if err != nil {
		return Response{}, err
	}
	opts := deploy.Options{
		EnvironmentPath: h.Store.staged(stagedEnv),
		BinaryPath:      h.Store.staged(stagedBinary),
		SHA256:          h.SHA256,
		AssetsPath:      h.Store.staged(stagedAssets),
		Apply:           true,
	}
	if err := h.Install(opts, h.Terminal, h.Terminal); err != nil {
		return Response{}, h.fail(l, loc, StepInstall, err)
	}
	inputs := map[string]string{"deploy.env": digestHex(env), "macserve": h.SHA256, "assets": assetsDigest(h.Assets)}
	if err := h.complete(l, LedgerStaged, StepInstall, boot, inputs); err != nil {
		return Response{}, err
	}
	if err := h.Store.MoveLedger(l); err != nil {
		return Response{}, fmt.Errorf("installed, but the setup ledger could not be moved into %s (run macserve setup again to retry the move): %w", h.Store.Ledger, err)
	}
	return Response{Done: true}, h.Store.RemoveStagedInputs()
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// assetsDigest is the sha256 over "name\0sha256\n" for each asset in name
// order.
func assetsDigest(assets map[string][]byte) string {
	var b strings.Builder
	for _, name := range sortedKeys(assets) {
		b.WriteString(name + "\x00" + digestHex(assets[name]) + "\n")
	}
	return digestHex([]byte(b.String()))
}

// stageBinary copies Executable, without following links and bounded,
// into Staging as root-only 0700 and requires its digest to be SHA256.
func (h *Helper) stageBinary() error {
	if !sha256Hex.MatchString(h.SHA256) {
		return errors.New("expected macserve digest missing")
	}
	if err := h.Store.EnsureStaging(); err != nil {
		return err
	}
	info, err := os.Lstat(h.Executable)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxBinary {
		return errors.New("the running macserve is not a bounded regular file")
	}
	src, err := os.OpenFile(h.Executable, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	target := h.Store.staged(stagedBinary)
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o700)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, cerr := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(src, maxBinary+1))
	err = errors.Join(cerr, dst.Chown(int(h.Store.RootUID), int(h.Store.RootGID)), dst.Chmod(0o700), dst.Sync(), dst.Close())
	if err == nil && (n > maxBinary || n != info.Size()) {
		err = errors.New("the running macserve changed while it was copied")
	}
	if err == nil && hex.EncodeToString(hash.Sum(nil)) != h.SHA256 {
		err = fmt.Errorf("the running macserve does not have the expected SHA-256 %s; nothing was installed", h.SHA256)
	}
	if err != nil {
		_ = os.Remove(target)
		return err
	}
	return syncDir(filepath.Dir(target))
}
