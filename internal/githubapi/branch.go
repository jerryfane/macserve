package githubapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/jerryfane/macserve/internal/model"
)

// BranchHead is a repository's default branch and the commit it names.
type BranchHead struct {
	RepositoryID int64
	Branch       string
	SHA          string
}

type refWire struct {
	Ref    string `json:"ref"`
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

// DefaultBranchHead resolves a repository's numeric ID and default branch
// and the commit at that branch's head, through a GitHub App installation
// token only. The ref must name exactly refs/heads/<branch> and a commit:
// GitHub answers a missing ref with a prefix match list, and an annotated
// tag object does not name the commit a job builds.
func (c *Client) DefaultBranchHead(ctx context.Context, repo string) (BranchHead, error) {
	if c.appID == 0 {
		return BranchHead{}, errors.New("default-branch resolution requires a GitHub App")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.repositoryToken(ctx, repo)
	if err != nil {
		return BranchHead{}, err
	}
	repository, err := c.repository(ctx, repo, token)
	if err != nil {
		return BranchHead{}, err
	}
	branch := repository.DefaultBranch
	if !model.ValidBranch(branch) {
		return BranchHead{}, errors.New("invalid GitHub default branch")
	}
	var ref refWire
	if _, _, err := c.request(ctx, http.MethodGet, "/repos/"+repo+"/git/ref/heads/"+branch, token, "", nil, &ref); err != nil {
		return BranchHead{}, err
	}
	if ref.Ref != "refs/heads/"+branch || ref.Object.Type != "commit" || !validSHA(ref.Object.SHA) {
		return BranchHead{}, errors.New("GitHub default branch does not name a commit")
	}
	return BranchHead{RepositoryID: repository.ID, Branch: branch, SHA: ref.Object.SHA}, nil
}
