package controller

import (
	"errors"
	"github.com/jerryfane/macserve/internal/githubpull"
	"regexp"
)

type ReceiptConfig struct {
	KeyID            string            `json:"key_id"`
	PrivateKeyFile   string            `json:"private_key_file"`
	ServiceID        string            `json:"service_id"`
	HostID           string            `json:"host_id"`
	Repositories     map[string]int64  `json:"repositories"`
	VerificationKeys map[string]string `json:"verification_keys,omitempty"`
}

type GitHubConfig struct {
	AppID          int64               `json:"app_id"`
	InstallationID int64               `json:"installation_id"`
	PrivateKeyFile string              `json:"private_key_file"`
	Policies       []githubpull.Policy `json:"policies"`
	PollSeconds    int                 `json:"poll_seconds,omitempty"`
}

var repositoryName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9_.-]+$`)

func (c *Config) validateIntegrations() error {
	r := c.Receipt
	if r.KeyID == "" || r.ServiceID == "" || r.HostID == "" || !cleanAbsolute(r.PrivateKeyFile) || len(r.Repositories) == 0 {
		return errors.New("receipt key, service identity, host identity and repository IDs are required")
	}
	ids := make(map[int64]bool, len(r.Repositories))
	for name, id := range r.Repositories {
		if !repositoryName.MatchString(name) || id <= 0 || id > 9007199254740991 || ids[id] {
			return errors.New("receipt repositories require unique numeric IDs and canonical lowercase names")
		}
		ids[id] = true
	}
	if g := c.GitHub; g != nil {
		if g.AppID <= 0 || g.InstallationID <= 0 || !cleanAbsolute(g.PrivateKeyFile) || len(g.Policies) == 0 {
			return errors.New("GitHub App identity, private key and policies are required")
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
