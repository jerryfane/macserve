package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
// password prompt. deploy-install's one-time API token line is taken out
// of that output (tokenFilter) and returned in the response only, for the
// wizard to put into the owner's login keychain (decision D11); it is
// never printed, logged or written to a file. On success the ledger moves
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
	stdout := &tokenFilter{out: h.Terminal}
	err = h.Install(opts, stdout, h.Terminal)
	if err != nil {
		return Response{}, h.fail(l, loc, StepInstall, err)
	}
	// From here the install is done: the token goes back to the wizard
	// even if a later step errs, so it reaches the owner's keychain.
	resp := Response{Token: stdout.token()}
	if resp.Token == "" {
		return Response{}, h.fail(l, loc, StepInstall, errors.New("deploy-install finished without the one-time API token; reconcile by hand"))
	}
	inputs := map[string]string{"deploy.env": digestHex(env), "macserve": h.SHA256, "assets": assetsDigest(h.Assets)}
	if err := h.complete(l, LedgerStaged, StepInstall, boot, inputs); err != nil {
		return resp, err
	}
	if err := h.Store.MoveLedger(l); err != nil {
		return resp, fmt.Errorf("installed, but the setup ledger could not be moved into %s (run macserve setup again to retry the move): %w", h.Store.Ledger, err)
	}
	resp.Done = true
	return resp, h.Store.RemoveStagedInputs()
}

// tokenPrefix starts deploy-install's one-time API token line.
const tokenPrefix = "API_BEARER_TOKEN="

// tokenFilter passes deploy-install's output to out as it comes (the
// account helper's password prompt has no newline), except a line that
// starts with tokenPrefix: that line is kept, never written.
type tokenFilter struct {
	mu   sync.Mutex
	out  io.Writer
	line []byte // the current line while it may still be the token line
	keep bool   // the current line is the token line
	pass bool   // the current line is passed through
	tok  []byte
}

func (f *tokenFilter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i < len(p); {
		switch {
		case f.keep:
			j := bytes.IndexByte(p[i:], '\n')
			if j < 0 {
				f.tok = append(f.tok, p[i:]...)
				return len(p), nil
			}
			f.tok = append(f.tok, p[i:i+j]...)
			f.keep, f.tok = false, append(f.tok, '\n')
			i += j + 1
		case f.pass:
			j := bytes.IndexByte(p[i:], '\n')
			end := len(p)
			if j >= 0 {
				end = i + j + 1
				f.pass = false
			}
			if _, err := f.out.Write(p[i:end]); err != nil {
				return i, err
			}
			i = end
		default:
			// At a line start: hold bytes while they may begin the token line.
			for i < len(p) && len(f.line) < len(tokenPrefix) && p[i] == tokenPrefix[len(f.line)] {
				f.line = append(f.line, p[i])
				i++
			}
			if len(f.line) == len(tokenPrefix) {
				f.keep, f.line = true, nil
				continue
			}
			if i == len(p) {
				return len(p), nil
			}
			held := f.line
			f.line, f.pass = nil, true
			if _, err := f.out.Write(held); err != nil {
				return i, err
			}
		}
	}
	return len(p), nil
}

// token is the last complete token line's value.
func (f *tokenFilter) token() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	lines := strings.Split(strings.TrimSuffix(string(f.tok), "\n"), "\n")
	t := lines[len(lines)-1]
	if !strings.HasSuffix(string(f.tok), "\n") || t == "" {
		return ""
	}
	return t
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
