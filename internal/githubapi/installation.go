package githubapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxInstallationRepositories bounds one owner's installation listing: a
// larger listing is refused whole rather than silently truncated.
const MaxInstallationRepositories = 500

var errListingBound = errors.New("GitHub installation lists more repositories than the bound")

// InstallationRepositories lists the approved owner's repositories that its
// App installation covers: each with a numeric ID, a valid full name under
// owner and a numeric owner ID. Repositories of another account (a legacy
// single installation) are dropped. A brokered client asks its Listing
// source; an App client lists with an installation token that has metadata
// read permission only and never leaves this client.
func (c *Client) InstallationRepositories(ctx context.Context, owner string) ([]Repository, error) {
	if c.appID == 0 || !ValidOwner(owner) || !c.owners[owner] {
		return nil, errors.New("GitHub owner is not approved")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var repos []Repository
	var err error
	switch {
	case c.key != nil:
		repos, err = c.listInstallation(ctx, owner)
	case c.list != nil:
		repos, err = c.list(ctx, owner)
	default:
		return nil, errors.New("GitHub owner repository listing is unavailable")
	}
	if err != nil {
		return nil, err
	}
	if len(repos) > MaxInstallationRepositories {
		return nil, errListingBound
	}
	seen := make(map[int64]bool, len(repos))
	owned := make([]Repository, 0, len(repos))
	for _, r := range repos {
		if r.ID <= 0 || r.ID > 9007199254740991 || seen[r.ID] || !validRepo(r.FullName) || r.Owner.ID <= 0 || r.Owner.ID > 9007199254740991 {
			return nil, errors.New("invalid GitHub installation repository")
		}
		seen[r.ID] = true
		if strings.EqualFold(r.Owner.Login, owner) && repoOwner(r.FullName) == owner {
			owned = append(owned, r)
		}
	}
	return owned, nil
}

func (c *Client) listInstallation(ctx context.Context, owner string) ([]Repository, error) {
	installation, err := c.installation(owner + "/")
	if err != nil {
		return nil, err
	}
	token, err := c.listingToken(ctx, installation)
	if err != nil {
		return nil, err
	}
	c.cacheMu.Lock()
	cached := c.listings[owner]
	c.cacheMu.Unlock()
	pageCount, total := 0, 0
	repos, etag, unchanged, err := pages(ctx, c, "/installation/repositories?per_page=100", cached.etag,
		func(ctx context.Context, path, etag string) ([]Repository, http.Header, bool, error) {
			var body struct {
				TotalCount   int          `json:"total_count"`
				Repositories []Repository `json:"repositories"`
			}
			header, unchanged, err := c.request(ctx, http.MethodGet, path, token, etag, nil, &body)
			if err != nil || unchanged {
				return nil, header, unchanged, err
			}
			pageCount++
			total += len(body.Repositories)
			if body.TotalCount < 0 || body.TotalCount > MaxInstallationRepositories || len(body.Repositories) > 100 || total > MaxInstallationRepositories {
				return nil, nil, false, errListingBound
			}
			return body.Repositories, header, false, nil
		})
	if err != nil {
		return nil, err
	}
	if unchanged {
		return slices.Clone(cached.value), nil
	}
	// Only a one-page listing is replayed from a 304: a later page can change
	// while the first does not.
	c.cacheMu.Lock()
	if pageCount == 1 && etag != "" {
		c.listings[owner] = cachedListing{etag: etag, value: slices.Clone(repos)}
	} else {
		delete(c.listings, owner)
	}
	c.cacheMu.Unlock()
	return repos, nil
}

// listingToken mints (or returns the cached) installation-wide token with
// metadata read permission only, which can list but not read any repository.
func (c *Client) listingToken(ctx context.Context, installation int64) (string, error) {
	key := "installation:" + strconv.FormatInt(installation, 10)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if t := c.tokens[key]; t.value != "" && c.now().Add(time.Minute).Before(t.expires) {
		return t.value, nil
	}
	jwt, err := c.jwt()
	if err != nil {
		return "", err
	}
	input := struct {
		Permissions map[string]string `json:"permissions"`
	}{map[string]string{"metadata": "read"}}
	var reply struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires_at"`
	}
	if _, _, err = c.request(ctx, http.MethodPost, "/app/installations/"+strconv.FormatInt(installation, 10)+"/access_tokens", jwt, "", input, &reply); err != nil {
		return "", err
	}
	if !validToken(reply.Token) || !c.now().Add(time.Minute).Before(reply.Expires) {
		return "", errors.New("invalid GitHub installation token response")
	}
	c.tokens[key] = cachedToken{reply.Token, reply.Expires}
	return reply.Token, nil
}

// RegularFile returns the bytes of the root file name at commit sha of repo.
// found is false when the path is absent, is not a regular file (a symlink,
// directory or submodule) or exceeds max bytes: none is a file a job reads.
func (c *Client) RegularFile(ctx context.Context, repo, sha, name string, max int) (data []byte, found bool, err error) {
	if c.appID == 0 {
		return nil, false, errors.New("repository file reads require a GitHub App")
	}
	if !validSHA(sha) || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\?#%") || max <= 0 {
		return nil, false, errors.New("invalid repository file request")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.auth(ctx, repo)
	if err != nil {
		return nil, false, err
	}
	var raw json.RawMessage
	_, _, err = c.request(ctx, http.MethodGet, "/repos/"+repo+"/contents/"+name+"?ref="+strings.ToLower(sha), token, "", nil, &raw)
	var remote *Error
	if errors.As(err, &remote) && remote.Status == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	// A directory answers with a JSON array.
	if raw = bytes.TrimSpace(raw); len(raw) > 0 && raw[0] == '[' {
		return nil, false, nil
	}
	var file struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Size     int    `json:"size"`
		Content  string `json:"content"`
	}
	if err = json.Unmarshal(raw, &file); err != nil {
		return nil, false, errors.New("invalid GitHub repository file response")
	}
	if file.Type != "file" || file.Size < 0 || file.Size > max {
		return nil, false, nil
	}
	if file.Encoding != "base64" {
		return nil, false, errors.New("invalid GitHub repository file encoding")
	}
	data, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	if err != nil || len(data) != file.Size {
		return nil, false, errors.New("invalid GitHub repository file content")
	}
	return data, true, nil
}
