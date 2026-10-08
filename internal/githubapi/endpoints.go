package githubapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type pullWire struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Draft  bool   `json:"draft"`
	Head   struct {
		SHA  string      `json:"sha"`
		Repo *Repository `json:"repo"`
	} `json:"head"`
	User struct {
		ID int64 `json:"id"`
	} `json:"user"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (p pullWire) value() PullRequest {
	var repoID int64
	if p.Head.Repo != nil {
		repoID = p.Head.Repo.ID
	}
	return PullRequest{Number: p.Number, State: p.State, Draft: p.Draft, HeadSHA: p.Head.SHA, HeadRepositoryID: repoID, AuthorID: p.User.ID, BaseRef: p.Base.Ref, UpdatedAt: p.UpdatedAt}
}

type commentWire struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User struct {
		ID int64 `json:"id"`
	} `json:"user"`
	App *struct {
		ID int64 `json:"id"`
	} `json:"performed_via_github_app"`
	IssueURL  string    `json:"issue_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (c *Client) comment(repo string, w commentWire) (Comment, error) {
	u, err := url.Parse(w.IssueURL)
	if err != nil || !u.IsAbs() || u.User != nil || u.Scheme != c.base.Scheme || u.Host != c.base.Host || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return Comment{}, errors.New("invalid GitHub comment issue URL")
	}
	prefix := "/repos/" + repo + "/issues/"
	if !strings.HasPrefix(strings.ToLower(u.Path), strings.ToLower(prefix)) {
		return Comment{}, errors.New("GitHub comment repository mismatch")
	}
	number := u.Path[len(prefix):]
	pr, err := strconv.Atoi(number)
	if err != nil || pr <= 0 || strconv.Itoa(pr) != number || w.ID <= 0 {
		return Comment{}, errors.New("invalid GitHub comment identity")
	}
	var appID int64
	if w.App != nil {
		appID = w.App.ID
	}
	return Comment{ID: w.ID, Body: w.Body, AuthorID: w.User.ID, AppID: appID, PullRequest: pr, CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt}, nil
}

type checkWire struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	ExternalID string `json:"external_id"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HTMLURL    string `json:"html_url"`
	App        struct {
		ID int64 `json:"id"`
	} `json:"app"`
	Output CheckOutput `json:"output"`
}

func (w checkWire) value() Check {
	return Check{ID: w.ID, Name: w.Name, HeadSHA: w.HeadSHA, ExternalID: w.ExternalID, Status: w.Status, Conclusion: w.Conclusion, HTMLURL: w.HTMLURL, AppID: w.App.ID, Output: w.Output}
}

func (c *Client) repository(ctx context.Context, repo, token string) (Repository, error) {
	var result Repository
	_, _, err := c.request(ctx, http.MethodGet, "/repos/"+repo, token, "", nil, &result)
	if err != nil {
		return Repository{}, err
	}
	if result.ID <= 0 || !strings.EqualFold(result.FullName, repo) || (c.appID != 0 && result.ID != c.repositories[strings.ToLower(repo)]) {
		return Repository{}, errors.New("GitHub repository identity mismatch")
	}
	return result, nil
}

func (c *Client) Repository(ctx context.Context, repo string) (Repository, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.repositoryToken(ctx, repo)
	if err != nil {
		return Repository{}, err
	}
	return c.repository(ctx, repo, token)
}

// pages never exposes partial results on a failed, looping, or excessive scan.
func pages[T any](ctx context.Context, c *Client, path, etag string, decode func(context.Context, string, string) ([]T, http.Header, bool, error)) ([]T, string, bool, error) {
	seen := make(map[string]bool)
	var all []T
	var nextETag string
	for page := 0; path != ""; page++ {
		u, err := c.resolve(path)
		if err != nil {
			return nil, "", false, err
		}
		if page >= maxPages || seen[u.String()] {
			return nil, "", false, errors.New("GitHub pagination limit or cycle")
		}
		seen[u.String()] = true
		items, header, unchanged, err := decode(ctx, path, etag)
		if err != nil {
			return nil, "", false, err
		}
		if page == 0 {
			nextETag = header.Get("ETag")
			if unchanged {
				if nextETag == "" {
					nextETag = etag
				}
				return nil, nextETag, true, nil
			}
		}
		if unchanged {
			return nil, "", false, errors.New("unexpected conditional GitHub page")
		}
		if len(all)+len(items) > maxItems {
			return nil, "", false, errors.New("GitHub pagination item limit")
		}
		all = append(all, items...)
		path, err = c.nextPage(header, path)
		if err != nil {
			return nil, "", false, err
		}
		etag = ""
	}
	return all, nextETag, false, nil
}

func (c *Client) ListPulls(ctx context.Context, repo, etag string) ([]PullRequest, string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.auth(ctx, repo)
	if err != nil {
		return nil, "", false, err
	}
	wire, nextETag, unchanged, err := pages(ctx, c, "/repos/"+repo+"/pulls?state=open&per_page=100&sort=updated&direction=asc", etag,
		func(ctx context.Context, path, etag string) ([]pullWire, http.Header, bool, error) {
			var items []pullWire
			header, unchanged, err := c.request(ctx, http.MethodGet, path, token, etag, nil, &items)
			return items, header, unchanged, err
		})
	if err != nil {
		return nil, "", false, err
	}
	items := make([]PullRequest, 0, len(wire))
	for _, p := range wire {
		if p.Number <= 0 {
			return nil, "", false, errors.New("invalid GitHub pull request identity")
		}
		items = append(items, p.value())
	}
	return items, nextETag, unchanged, nil
}

func (c *Client) Pull(ctx context.Context, repo string, number int) (PullRequest, error) {
	if number <= 0 {
		return PullRequest{}, errors.New("invalid GitHub pull request number")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.auth(ctx, repo)
	if err != nil {
		return PullRequest{}, err
	}
	var wire pullWire
	_, _, err = c.request(ctx, http.MethodGet, "/repos/"+repo+"/pulls/"+strconv.Itoa(number), token, "", nil, &wire)
	if err != nil {
		return PullRequest{}, err
	}
	if wire.Number != number {
		return PullRequest{}, errors.New("GitHub pull request identity mismatch")
	}
	return wire.value(), nil
}

// CommentsPage returns at most 100 comments and a forward-only continuation.
// Callers commit the page only after admitting every relevant request.
func (c *Client) CommentsPage(ctx context.Context, repo string, since time.Time, page int) ([]Comment, int, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.auth(ctx, repo)
	if err != nil {
		return nil, 0, err
	}
	if since.IsZero() || page < 1 {
		return nil, 0, errors.New("invalid GitHub comment cursor")
	}
	query := url.Values{"per_page": {"100"}, "sort": {"updated"}, "direction": {"asc"}, "since": {since.UTC().Format(time.RFC3339)}, "page": {strconv.Itoa(page)}}
	path := "/repos/" + repo + "/issues/comments?" + query.Encode()
	var wire []commentWire
	header, _, err := c.request(ctx, http.MethodGet, path, token, "", nil, &wire)
	if err != nil {
		return nil, 0, err
	}
	if len(wire) > 100 {
		return nil, 0, errors.New("GitHub comment page exceeds limit")
	}
	next, err := c.nextPage(header, path)
	if err != nil {
		return nil, 0, err
	}
	nextPage := 0
	if next != "" {
		u, err := url.Parse(next)
		if err != nil {
			return nil, 0, err
		}
		nextPage, err = strconv.Atoi(u.Query().Get("page"))
		if err != nil || nextPage <= page || nextPage-page != 1 {
			return nil, 0, errors.New("GitHub comment pagination did not advance")
		}
	}
	items := make([]Comment, 0, len(wire))
	for _, w := range wire {
		item, err := c.comment(repo, w)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, nextPage, nil
}

func validSHA(sha string) bool {
	if len(sha) != 40 {
		return false
	}
	for _, r := range sha {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (c *Client) Checks(ctx context.Context, repo, sha string) ([]Check, error) {
	if !validSHA(sha) {
		return nil, errors.New("invalid GitHub commit SHA")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.auth(ctx, repo)
	if err != nil {
		return nil, err
	}
	largestTotal := 0
	wire, _, _, err := pages(ctx, c, "/repos/"+repo+"/commits/"+sha+"/check-runs?per_page=100&filter=all", "",
		func(ctx context.Context, path, etag string) ([]checkWire, http.Header, bool, error) {
			var result struct {
				Total *int        `json:"total_count"`
				Items []checkWire `json:"check_runs"`
			}
			header, unchanged, err := c.request(ctx, http.MethodGet, path, token, etag, nil, &result)
			if err != nil {
				return nil, header, unchanged, err
			}
			if result.Total == nil || *result.Total < 0 || result.Items == nil {
				return nil, header, false, errors.New("invalid GitHub check list response")
			}
			if *result.Total > maxItems {
				return nil, header, false, errors.New("GitHub check list exceeds item limit")
			}
			largestTotal = max(largestTotal, *result.Total)
			return result.Items, header, unchanged, nil
		})
	if err != nil {
		return nil, err
	}
	if len(wire) < largestTotal {
		return nil, errors.New("incomplete GitHub check pagination")
	}
	items := make([]Check, 0, len(wire))
	for _, w := range wire {
		if w.ID <= 0 || w.HeadSHA != sha {
			return nil, errors.New("GitHub check identity mismatch")
		}
		items = append(items, w.value())
	}
	return items, nil
}

func (c *Client) Check(ctx context.Context, repo string, id int64) (Check, error) {
	if id <= 0 {
		return Check{}, errors.New("invalid GitHub check ID")
	}
	return c.checkRequest(ctx, repo, http.MethodGet, id, nil)
}

func (c *Client) CreateCheck(ctx context.Context, repo string, input CheckInput) (Check, error) {
	if input.Name == "" || !validSHA(input.HeadSHA) {
		return Check{}, errors.New("GitHub check requires a name and exact SHA")
	}
	return c.checkRequest(ctx, repo, http.MethodPost, 0, &input)
}

func (c *Client) UpdateCheck(ctx context.Context, repo string, id int64, input CheckInput) (Check, error) {
	if id <= 0 {
		return Check{}, errors.New("invalid GitHub check ID")
	}
	// GitHub cannot change the head commit of an existing check run.
	input.HeadSHA = ""
	return c.checkRequest(ctx, repo, http.MethodPatch, id, &input)
}

func (c *Client) checkRequest(ctx context.Context, repo, method string, id int64, input *CheckInput) (Check, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.auth(ctx, repo)
	if err != nil {
		return Check{}, err
	}
	path := "/repos/" + repo + "/check-runs"
	if id != 0 {
		path += "/" + strconv.FormatInt(id, 10)
	}
	var body any
	if input != nil {
		body = input
	}
	var wire checkWire
	_, _, err = c.request(ctx, method, path, token, "", body, &wire)
	if err != nil {
		return Check{}, err
	}
	if wire.ID <= 0 || (id != 0 && wire.ID != id) || (c.appID != 0 && wire.App.ID != c.appID) || (input != nil && input.HeadSHA != "" && wire.HeadSHA != input.HeadSHA) {
		return Check{}, errors.New("GitHub check identity mismatch")
	}
	return wire.value(), nil
}

func (c *Client) CreateComment(ctx context.Context, repo string, number int, body string) (Comment, error) {
	if number <= 0 || body == "" {
		return Comment{}, errors.New("GitHub comment requires a pull request and body")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.auth(ctx, repo)
	if err != nil {
		return Comment{}, err
	}
	var wire commentWire
	_, _, err = c.request(ctx, http.MethodPost, "/repos/"+repo+"/issues/"+strconv.Itoa(number)+"/comments", token, "", struct {
		Body string `json:"body"`
	}{body}, &wire)
	if err != nil {
		return Comment{}, err
	}
	comment, err := c.comment(repo, wire)
	if err != nil {
		return Comment{}, err
	}
	if comment.PullRequest != number || comment.Body != body {
		return Comment{}, errors.New("GitHub created comment mismatch")
	}
	return comment, nil
}
