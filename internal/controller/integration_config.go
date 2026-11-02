package controller

import (
	"errors"
	"regexp"
	"slices"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubpull"
)

// ReceiptConfig pins receipt repository identity. Repositories maps exact
// repositories to numeric GitHub IDs; Owners approves every repository of
// those GitHub account logins, whose IDs come from the GitHub App's
// installation token reply when the source is fetched.
type ReceiptConfig struct {
	KeyID            string            `json:"key_id"`
	PrivateKeyFile   string            `json:"private_key_file"`
	ServiceID        string            `json:"service_id"`
	HostID           string            `json:"host_id"`
	Repositories     map[string]int64  `json:"repositories"`
	Owners           []string          `json:"owners,omitempty"`
	VerificationKeys map[string]string `json:"verification_keys,omitempty"`
}

// GitHubConfig names the App. InstallationID is the legacy single
// installation; Installations selects one per repository owner login and takes
// precedence over it.
type GitHubConfig struct {
	AppID          int64               `json:"app_id"`
	InstallationID int64               `json:"installation_id"`
	Installations  map[string]int64    `json:"installations,omitempty"`
	PrivateKeyFile string              `json:"private_key_file"`
	Policies       []githubpull.Policy `json:"policies"`
	PollSeconds    int                 `json:"poll_seconds,omitempty"`
}

var repositoryName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9_.-]+$`)

func (c *Config) validateIntegrations() error {
	r := c.Receipt
	if r.KeyID == "" || r.ServiceID == "" || r.HostID == "" || !cleanAbsolute(r.PrivateKeyFile) || len(r.Repositories) == 0 && len(r.Owners) == 0 {
		return errors.New("receipt key, service identity, host identity and repository IDs or owners are required")
	}
	ids := make(map[int64]bool, len(r.Repositories))
	for name, id := range r.Repositories {
		if !repositoryName.MatchString(name) || id <= 0 || id > 9007199254740991 || ids[id] {
			return errors.New("receipt repositories require unique numeric IDs and canonical lowercase names")
		}
		ids[id] = true
	}
	for i, owner := range r.Owners {
		if !githubapi.ValidOwner(owner) || slices.Contains(r.Owners[:i], owner) {
			return errors.New("receipt owners must be unique lowercase GitHub account logins")
		}
	}
	if len(r.Owners) > 0 && c.GitHub == nil {
		return errors.New("receipt owners require a GitHub App to verify repository IDs")
	}
	if g := c.GitHub; g != nil {
		if g.AppID <= 0 || g.InstallationID < 0 || g.InstallationID == 0 && len(g.Installations) == 0 || !cleanAbsolute(g.PrivateKeyFile) || len(g.Policies) == 0 {
			return errors.New("GitHub App identity, installation, private key and policies are required")
		}
		for owner, id := range g.Installations {
			if !githubapi.ValidOwner(owner) || id <= 0 || id > 9007199254740991 {
				return errors.New("GitHub installations map lowercase owner logins to numeric IDs")
			}
		}
		if g.PollSeconds == 0 {
			g.PollSeconds = 45
		}
		if g.PollSeconds < 30 || g.PollSeconds > 60 {
			return errors.New("GitHub poll interval must be 30–60 seconds")
		}
		for _, p := range g.Policies {
			if r.Repositories[p.Repository] != p.RepositoryID || p.RepositoryID <= 0 {
				return errors.New("GitHub policies must match pinned receipt repository IDs")
			}
		}
	}
	return nil
}
