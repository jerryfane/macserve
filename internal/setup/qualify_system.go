package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/onboarding"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/qualification"
	"github.com/jerryfane/macserve/internal/source"
	"github.com/jerryfane/macserve/internal/worker"
	"github.com/jerryfane/macserve/internal/workerclient"
)

// SystemQualifier is the production Qualifier: each method calls the
// existing qualification, worker, source and controller code exactly as
// the corresponding macserve command does (qualify, worker-persistence,
// worker-reset, _qualify-tool-evidence, the controller's source exporter
// and readiness gate).
type SystemQualifier struct {
	// Root is /Library/macserve; Staging is the helper's root-only
	// staging directory (the exporter's private work area).
	Root, Staging string
}

func (q *SystemQualifier) config(name string) string { return filepath.Join(q.Root, "config", name) }

// workerOptions loads worker.json as worker-persistence and worker-reset do.
func (q *SystemQualifier) workerOptions() (worker.Options, error) {
	path := q.config("worker.json")
	if err := hostguard.Worker(path); err != nil {
		return worker.Options{}, err
	}
	cfg, err := workerclient.LoadConfig(path)
	if err != nil {
		return worker.Options{}, err
	}
	return cfg.EngineOptions(), nil
}

func (q *SystemQualifier) ReviewPersistence(ctx context.Context, candidate string) (string, error) {
	o, err := q.workerOptions()
	if err != nil {
		return "", err
	}
	return worker.ReviewPersistence(ctx, o, candidate)
}

func (q *SystemQualifier) AcceptPersistence(ctx context.Context, candidate, reviewed string) error {
	o, err := q.workerOptions()
	if err != nil {
		return err
	}
	return worker.AcceptPersistence(ctx, o, candidate, reviewed)
}

func (q *SystemQualifier) PersistenceDigest() (string, error) {
	o, err := q.workerOptions()
	if err != nil {
		return "", err
	}
	return worker.PersistenceDigest(o.PersistencePath, o.JobUID)
}

func (q *SystemQualifier) ResetBaseline(ctx context.Context, pids []int) error {
	o, err := q.workerOptions()
	if err != nil {
		return err
	}
	_, err = worker.ResetGUIBaseline(ctx, o, pids)
	return err
}

func (q *SystemQualifier) CheckBaseline(ctx context.Context) error {
	o, err := q.workerOptions()
	if err != nil {
		return err
	}
	return worker.CheckBaselinePolicy(ctx, o.BaselinePath, o.JobUID)
}

func (q *SystemQualifier) JobProcesses(jobUID uint32) ([]JobProcess, error) {
	return jobProcesses(jobUID)
}

func (q *SystemQualifier) Begin(ctx context.Context, o qualification.BeginOptions) error {
	ctx, cancel := context.WithTimeout(ctx, worker.PersistenceOperationTimeout)
	defer cancel()
	return qualification.Begin(ctx, o)
}

func (q *SystemQualifier) ToolEvidence(ctx context.Context, session string) error {
	return qualification.RunToolEvidence(ctx, session)
}

func (q *SystemQualifier) Collect(ctx context.Context, dir, owner, receipts string) error {
	ctx, cancel := context.WithTimeout(ctx, worker.PersistenceOperationTimeout)
	defer cancel()
	return qualification.Collect(ctx, dir, owner, receipts)
}

func (q *SystemQualifier) Approve(ctx context.Context, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, worker.PersistenceOperationTimeout)
	defer cancel()
	return qualification.Approve(ctx, dir)
}

func (q *SystemQualifier) ActivationCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, worker.PersistenceOperationTimeout)
	defer cancel()
	return qualification.ActivationCheck(ctx)
}

// Health is the controller's readiness gate, built as `macserve
// controller` builds it.
func (q *SystemQualifier) Health(ctx context.Context) ([]string, error) {
	c, err := controllerconfig.LoadConfig(q.config("controller.json"))
	if err != nil {
		return nil, err
	}
	registry, err := profiles.Load(c.ProfilesFile)
	if err != nil {
		return nil, err
	}
	guard, err := health.NewGuard(health.GuardOptions{Root: c.Root, HealthFile: c.HealthFile, PauseFile: c.PauseFile, JobUID: c.JobUID, OwnerUID: c.OwnerUID, Profiles: registry.Digests(), Lanes: c.Lanes()})
	if err != nil {
		return nil, err
	}
	state, err := guard.Check(ctx)
	return state.Blockers, err
}

// app is the GitHub App client, from controller.json and the App key the
// keyholder holds (root reads it: owned by the keyholder UID, 0600, below
// root- or keyholder-owned directories), as the keyholder builds it.
func (q *SystemQualifier) app() (*githubapi.Client, error) {
	c, err := controllerconfig.LoadConfig(q.config("controller.json"))
	if err != nil {
		return nil, err
	}
	if c.GitHub == nil || c.GitHub.AppID == 0 {
		return nil, errors.New("controller.json has no GitHub App")
	}
	if c.Keyholder == nil {
		return nil, errors.New("controller.json has no keyholder section; the GitHub App key is the keyholder's")
	}
	pem, err := hostguard.ReadOwnedPrivateKey(c.GitHub.PrivateKeyFile, c.Keyholder.UID)
	if err != nil {
		return nil, err
	}
	key, err := onboarding.ParseAppKey(pem)
	if err != nil {
		return nil, err
	}
	return githubapi.NewApp(githubapi.AppOptions{AppID: c.GitHub.AppID, InstallationID: c.GitHub.InstallationID, Installations: c.GitHub.Installations, PrivateKey: key, Repositories: c.Receipt.Repositories, Owners: c.Receipt.Owners})
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s exceeds its size bound", path)
	}
	return data, nil
}

var commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Source exports repo at its default branch head (decision D8) through the
// controller's exporter (internal/source) with the App's contents token,
// and stores the archive root-owned as dir/<sha256>.tar.
func (q *SystemQualifier) Source(ctx context.Context, repo, dir string) (worker.Source, error) {
	app, err := q.app()
	if err != nil {
		return worker.Source{}, err
	}
	commit, err := defaultHead(ctx, app, repo)
	if err != nil {
		return worker.Source{}, err
	}
	exporter, err := source.New(source.Options{Root: filepath.Join(q.Staging, "source"), Token: app.SourceToken})
	if err != nil {
		return worker.Source{}, err
	}
	defer exporter.Close()
	job := model.Job{ID: "setup-qualification-source", Request: model.Request{Repo: repo, SHA: commit}, Profile: model.Profile{Repo: repo}}
	desc, err := exporter.Prepare(ctx, job)
	if err != nil {
		return worker.Source{}, err
	}
	defer exporter.Remove(job.ID)
	if err := copyArchive(desc.Path, filepath.Join(dir, desc.Source.SHA256+".tar"), desc.Source); err != nil {
		return worker.Source{}, err
	}
	return desc.Source, nil
}

// defaultHead is the commit at the default branch head:
// GET /repos/OWNER/NAME/commits/HEAD with the App's contents token.
func defaultHead(ctx context.Context, app *githubapi.Client, repo string) (string, error) {
	token, err := app.SourceToken(ctx, repo)
	if err != nil {
		return "", errors.New("GitHub contents token unavailable for " + repo)
	}
	owner, name, _ := strings.Cut(repo, "/")
	u := "https://api.github.com/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/commits/HEAD"
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github.sha")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("GitHub default branch lookup failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub default branch lookup: HTTP status %d", resp.StatusCode)
	}
	sha := strings.TrimSpace(string(body))
	if !commitSHA.MatchString(sha) {
		return "", errors.New("invalid GitHub commit reply")
	}
	return sha, nil
}

// copyArchive copies the exported archive to dst (root-owned 0644,
// written to a temporary name, synced, then renamed), checking its size
// and sha256 against the exporter's descriptor.
func copyArchive(src, dst string, want worker.Source) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	if _, err := os.Lstat(dst); err == nil {
		return verifyArchive(dst, want)
	}
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, want.SizeBytes+1))
	err = errors.Join(err, out.Chmod(0o644), out.Sync(), out.Close())
	if err == nil && (n != want.SizeBytes || hex.EncodeToString(h.Sum(nil)) != want.SHA256) {
		err = errors.New("exported source archive does not match its descriptor")
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(dst))
}

func verifyArchive(path string, want worker.Source) error {
	if err := hostguard.RootConfig(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, want.SizeBytes+1))
	if err != nil || n != want.SizeBytes || hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
		return errors.Join(err, fmt.Errorf("%s exists and is not the exported archive", path))
	}
	return nil
}

func (q *SystemQualifier) CarryPreflight(ctx context.Context, proof []byte, target qualification.CarryBinaries) error {
	return qualification.CarryPreflight(ctx, proof, target)
}
