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

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/githubwire"
	"github.com/jerryfane/macserve/internal/profiles"
)

const maxControllerConfig = 1 << 20

// DefaultPollSeconds is the pull-request poll interval written for a new
// App (the controller default; validation allows 30–60).
const DefaultPollSeconds = 45

// ErrGitHubConfigured refuses to replace an existing github section.
var ErrGitHubConfigured = errors.New("controller.json already has a github section; connect-github does not change an existing App")

// Scope is what the pull-request policy needs from the App installation.
type Scope struct {
	// SelectedOnly requires an installation on "Only select repositories"
	// that grants exactly the policy repository.
	SelectedOnly bool
}

// PolicyScope checks, before anything is created on GitHub, that the
// pull-request policy can name profileIDs for repo, and returns what the
// installation must then grant. policyProfile decides both.
func PolicyScope(registry *profiles.Registry, repo string, profileIDs []string) (Scope, error) {
	var scope Scope
	if len(profileIDs) == 0 {
		return scope, errors.New("at least one --profile is required: GitHub pull-request checks run a profile of this repository (temporary until PR-policy templates, O7)")
	}
	for i, id := range profileIDs {
		if slices.Contains(profileIDs[:i], id) {
			return scope, fmt.Errorf("profile %q is repeated", id)
		}
		selectedOnly, err := policyProfile(registry, repo, id)
		if err != nil {
			return scope, err
		}
		scope.SelectedOnly = scope.SelectedOnly || selectedOnly
	}
	return scope, nil
}

// policyProfile is the single interim restriction, temporary until
// PR-policy templates (O7). A policy may only name per-repository profiles
// whose recipe repository is repo, because the poller refuses anything
// else (internal/githubpull/poller.go). Such a policy only ever builds that
// one repository, so the App is installed on it alone (D10, least
// privilege) and an all-repositories installation is refused. O7 widens
// this function alone: a template id is accepted and, since a template
// admits every repository of its owners, needs no selected installation.
func policyProfile(registry *profiles.Registry, repo, id string) (selectedOnly bool, err error) {
	for _, profile := range registry.List() {
		if profile.ID == id {
			if profile.Repo != repo {
				return false, fmt.Errorf("profile %q builds %q, not %q", id, profile.Repo, repo)
			}
			return true, nil
		}
	}
	for _, template := range registry.Templates() {
		if template.ID == id {
			return false, fmt.Errorf("%q is a template; pull-request policies cannot name templates yet (temporary until PR-policy templates, O7)", id)
		}
	}
	return false, fmt.Errorf("profile %q is not in profiles.json", id)
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
}

// Section is the controller github section for e with the App key at
// keyFile: one policy for the one repository, revision 1, polled every
// DefaultPollSeconds.
func (e Enrollment) Section(keyFile string) *controllerconfig.GitHubConfig {
	return &controllerconfig.GitHubConfig{
		AppID: e.AppID, InstallationID: e.InstallationID, PrivateKeyFile: keyFile,
		Policies: []githubwire.Policy{{
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

func (f ConfigFile) open() (controllerconfig.Config, fs.FileInfo, error) {
	var c controllerconfig.Config
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
func (f ConfigFile) Check() (controllerconfig.Config, error) {
	c, _, err := f.open()
	if err != nil {
		return c, err
	}
	if c.GitHub != nil {
		return c, ErrGitHubConfigured
	}
	return c, nil
}

// renameConfig is os.Rename; tests make the final replace fail.
var renameConfig = os.Rename

// WriteGitHub installs the App key pem at key and adds e's github section,
// naming that key, to controller.json. The repository must already be
// pinned in receipt.repositories with the same numeric ID (deploy-install
// pins it from deploy.env). The new file is written beside the old one
// and validated by controller.LoadConfig; only then is the key installed,
// and only if that succeeds does the new file atomically replace the old
// one. If the replace fails, the key this call created is removed again,
// so a failed run leaves neither. Every other field keeps its decoded
// value.
func (f ConfigFile) WriteGitHub(e Enrollment, key KeyTarget, pem []byte) error {
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
	c.GitHub = e.Section(key.Path())
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
	if _, err := controllerconfig.LoadConfig(temp); err != nil {
		return fmt.Errorf("the new controller.json would not load: %w", err)
	}
	current, err := os.Lstat(f.Path)
	if err != nil || !os.SameFile(current, info) || current.ModTime() != info.ModTime() || current.Size() != info.Size() {
		return errors.New("controller.json changed while the github section was written")
	}
	created, err := installAppKey(key, pem)
	if err != nil {
		return err
	}
	if err := renameConfig(temp, f.Path); err != nil {
		if rerr := removeAppKey(key, created); rerr != nil {
			return fmt.Errorf("controller.json was not updated (%v) and the new App key could not be removed (%v); delete %s before running connect-github again", err, rerr, key.Path())
		}
		return fmt.Errorf("controller.json was not updated, the new App key was removed again: %w", err)
	}
	committed = true
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
