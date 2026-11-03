package onboarding

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/githubpull"
	"github.com/jerryfane/macserve/internal/profiles"
)

const maxControllerConfig = 1 << 20

// DefaultPollSeconds is the pull-request poll interval written for a new
// App (the controller default; validation allows 30–60).
const DefaultPollSeconds = 45

// ErrGitHubConfigured refuses to replace an existing github section.
var ErrGitHubConfigured = errors.New("controller.json already has a github section; connect-github does not change an existing App")

// CheckPolicyProfiles checks, before anything is created on GitHub, that
// the pull-request policy can name profileIDs for repo.
//
// Temporary until PR-policy templates (O7): a policy may only name
// per-repository profiles whose recipe repository is repo, because the
// poller refuses anything else (internal/githubpull/poller.go). O7 widens
// policyProfile alone to template ids; this stays the only check.
func CheckPolicyProfiles(registry *profiles.Registry, repo string, profileIDs []string) error {
	if len(profileIDs) == 0 {
		return errors.New("at least one --profile is required: GitHub pull-request checks run a profile of this repository (temporary until PR-policy templates, O7)")
	}
	for i, id := range profileIDs {
		if slices.Contains(profileIDs[:i], id) {
			return fmt.Errorf("profile %q is repeated", id)
		}
		if err := policyProfile(registry, repo, id); err != nil {
			return err
		}
	}
	return nil
}

func policyProfile(registry *profiles.Registry, repo, id string) error {
	for _, profile := range registry.List() {
		if profile.ID == id {
			if profile.Repo != repo {
				return fmt.Errorf("profile %q builds %q, not %q", id, profile.Repo, repo)
			}
			return nil
		}
	}
	for _, template := range registry.Templates() {
		if template.ID == id {
			return fmt.Errorf("%q is a template; pull-request policies cannot name templates yet (temporary until PR-policy templates, O7)", id)
		}
	}
	return fmt.Errorf("profile %q is not in profiles.json", id)
}

// Enrollment is everything confirmed with GitHub for the github section.
type Enrollment struct {
	AppID          int64
	InstallationID int64
	Repository     string
	RepositoryID   int64
	AuthorIDs      []int64
	BaseBranches   []string
	Profiles       []string
	KeyFile        string
}

// Section is the controller github section for e: one policy for the one
// selected repository, revision 1, polled every DefaultPollSeconds.
func (e Enrollment) Section() *controller.GitHubConfig {
	return &controller.GitHubConfig{
		AppID: e.AppID, InstallationID: e.InstallationID, PrivateKeyFile: e.KeyFile,
		Policies: []githubpull.Policy{{
			RepositoryID: e.RepositoryID, Repository: e.Repository,
			AuthorIDs: slices.Clone(e.AuthorIDs), BaseBranches: slices.Clone(e.BaseBranches),
			Profiles: slices.Clone(e.Profiles), PolicyRevision: 1,
		}},
		PollSeconds: DefaultPollSeconds,
	}
}

// ConfigFile is the root-owned controller.json the github section goes to.
type ConfigFile struct {
	Path    string
	RootUID uint32
}

func (f ConfigFile) open() (controller.Config, fs.FileInfo, error) {
	var c controller.Config
	if err := checkTrustedDir(filepath.Dir(f.Path), []uint32{f.RootUID}, false); err != nil {
		return c, nil, err
	}
	info, err := os.Lstat(f.Path)
	if err != nil {
		return c, nil, err
	}
	uid, _, nlink, ok := owner(info)
	if !info.Mode().IsRegular() || !ok || uid != f.RootUID || info.Mode().Perm() != 0o644 || nlink != 1 || info.Size() > maxControllerConfig {
		return c, nil, fmt.Errorf("%s must be a root-owned 0644 single-link regular file", f.Path)
	}
	file, err := os.OpenFile(f.Path, os.O_RDONLY|nofollow, 0)
	if err != nil {
		return c, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(opened, info) {
		return c, nil, errors.New("controller.json changed during validation")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxControllerConfig+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return c, nil, fmt.Errorf("controller.json: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return c, nil, errors.New("controller.json has trailing data")
	}
	return c, info, nil
}

// Check reads controller.json, refusing a file that already names an App.
func (f ConfigFile) Check() (controller.Config, error) {
	c, _, err := f.open()
	if err != nil {
		return c, err
	}
	if c.GitHub != nil {
		return c, ErrGitHubConfigured
	}
	return c, nil
}

// WriteGitHub adds e's github section to controller.json. The repository
// must already be pinned in receipt.repositories with the same numeric ID
// (deploy-install pins it from deploy.env). The new file is written beside
// the old one and validated by controller.LoadConfig; only then does
// beforeCommit run (it installs the App key), and only if it succeeds does
// the new file atomically replace the old one. Every other field keeps its
// decoded value.
func (f ConfigFile) WriteGitHub(e Enrollment, beforeCommit func() error) error {
	c, info, err := f.open()
	if err != nil {
		return err
	}
	if c.GitHub != nil {
		return ErrGitHubConfigured
	}
	if id := c.Receipt.Repositories[e.Repository]; id != e.RepositoryID || id <= 0 {
		return fmt.Errorf("%s is not pinned to repository ID %d in controller.json receipt.repositories", e.Repository, e.RepositoryID)
	}
	c.GitHub = e.Section()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	dir := filepath.Dir(f.Path)
	temp := filepath.Join(dir, "."+filepath.Base(f.Path)+"."+hex.EncodeToString(suffix[:]))
	_, gid, _, _ := owner(info)
	out, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|nofollow, 0o644)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temp)
		}
	}()
	_, werr := io.Copy(out, bytes.NewReader(data))
	err = errors.Join(werr, out.Chown(int(f.RootUID), int(gid)), out.Chmod(0o644), out.Sync(), out.Close())
	if err != nil {
		return err
	}
	if _, err := controller.LoadConfig(temp); err != nil {
		return fmt.Errorf("the new controller.json would not load: %w", err)
	}
	current, err := os.Lstat(f.Path)
	if err != nil || !os.SameFile(current, info) || current.ModTime() != info.ModTime() || current.Size() != info.Size() {
		return errors.New("controller.json changed while the github section was written")
	}
	if err := beforeCommit(); err != nil {
		return err
	}
	if err := os.Rename(temp, f.Path); err != nil {
		return fmt.Errorf("the App key is installed but controller.json was not updated: %w", err)
	}
	committed = true
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
