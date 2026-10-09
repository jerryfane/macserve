package githubapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	productionOrigin = "https://api.github.com"
	maxResponseBytes = 8 << 20
	maxPages         = 100
	maxItems         = 10000
	requestTimeout   = 30 * time.Second
	operationTimeout = 2 * time.Minute
)

type cachedToken struct {
	value   string
	expires time.Time
}

type Client struct {
	http                  *http.Client
	base                  *url.URL
	now                   func() time.Time
	appID, installationID int64
	key                   *rsa.PrivateKey
	repositories          map[string]int64
	token                 string
	mu                    sync.Mutex
	tokens                map[string]cachedToken
	rateMu                sync.Mutex
	blockedUntil          time.Time
	blockedStatus         int
}

func newClient(o HTTPOptions) (*Client, error) {
	origin := o.BaseURL
	if origin == "" {
		origin = productionOrigin
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid GitHub API origin")
	}
	u.Path = ""
	u.RawPath = ""
	var h http.Client
	if o.Client != nil {
		h = *o.Client
	} else {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.ResponseHeaderTimeout = requestTimeout
		transport.MaxResponseHeaderBytes = 64 << 10
		h.Transport = transport
	}
	// A supplied test client cannot override the redirect or cookie policy.
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h.Jar = nil
	if h.Timeout <= 0 || h.Timeout > requestTimeout {
		h.Timeout = requestTimeout
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Client{http: &h, base: u, now: now, tokens: make(map[string]cachedToken)}, nil
}

func NewToken(token string, o HTTPOptions) (*Client, error) {
	if !validToken(token) {
		return nil, errors.New("invalid GitHub token")
	}
	c, err := newClient(o)
	if err != nil {
		return nil, err
	}
	c.token = token
	return c, nil
}

func NewApp(o AppOptions) (*Client, error) {
	if o.AppID <= 0 || o.InstallationID <= 0 || o.PrivateKey == nil || o.PrivateKey.N == nil || o.PrivateKey.N.BitLen() < 2048 || len(o.Repositories) == 0 {
		return nil, errors.New("invalid GitHub App configuration")
	}
	if err := o.PrivateKey.Validate(); err != nil {
		return nil, errors.New("invalid GitHub App private key")
	}
	c, err := newClient(o.HTTP)
	if err != nil {
		return nil, err
	}
	c.appID, c.installationID, c.key = o.AppID, o.InstallationID, o.PrivateKey
	c.repositories = make(map[string]int64, len(o.Repositories))
	for repo, id := range o.Repositories {
		if !validRepo(repo) || id <= 0 {
			return nil, errors.New("invalid approved GitHub repository")
		}
		canonical := strings.ToLower(repo)
		if _, exists := c.repositories[canonical]; exists {
			return nil, errors.New("duplicate approved GitHub repository")
		}
		c.repositories[canonical] = id
	}
	return c, nil
}

func (c *Client) AppID() int64 { return c.appID }

func validToken(token string) bool {
	if token == "" || len(token) > 16384 {
		return false
	}
	for _, b := range []byte(token) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func validRepo(repo string) bool {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 100 {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
				return false
			}
		}
	}
	return true
}

func (c *Client) approved(repo string) error {
	if !validRepo(repo) {
		return errors.New("invalid GitHub repository name")
	}
	if c.appID != 0 && c.repositories[strings.ToLower(repo)] == 0 {
		return errors.New("GitHub repository is not approved")
	}
	return nil
}

func (c *Client) jwt() (string, error) {
	now := c.now()
	payload, err := json.Marshal(struct {
		Issued  int64 `json:"iat"`
		Expires int64 `json:"exp"`
		Issuer  int64 `json:"iss"`
	}{now.Add(-time.Minute).Unix(), now.Add(8 * time.Minute).Unix(), c.appID})
	if err != nil {
		return "", errors.New("cannot encode GitHub App JWT")
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("cannot sign GitHub App JWT")
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *Client) repositoryToken(ctx context.Context, repo string) (string, error) {
	if err := c.approved(repo); err != nil {
		return "", err
	}
	if c.appID == 0 {
		return c.token, nil
	}
	repo = strings.ToLower(repo)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if t := c.tokens[repo]; t.value != "" && c.now().Add(time.Minute).Before(t.expires) {
		return t.value, nil
	}
	jwt, err := c.jwt()
	if err != nil {
		return "", err
	}
	input := struct {
		RepositoryIDs []int64           `json:"repository_ids"`
		Permissions   map[string]string `json:"permissions"`
	}{[]int64{c.repositories[repo]}, map[string]string{"contents": "read", "metadata": "read", "pull_requests": "read", "checks": "write"}}
	var reply struct {
		Token        string       `json:"token"`
		Expires      time.Time    `json:"expires_at"`
		Repositories []Repository `json:"repositories"`
	}
	_, _, err = c.request(ctx, http.MethodPost, "/app/installations/"+strconv.FormatInt(c.installationID, 10)+"/access_tokens", jwt, "", input, &reply)
	if err != nil {
		return "", err
	}
	if !validToken(reply.Token) || !c.now().Add(time.Minute).Before(reply.Expires) {
		return "", errors.New("invalid GitHub installation token response")
	}
	if len(reply.Repositories) > 0 && (len(reply.Repositories) != 1 || reply.Repositories[0].ID != c.repositories[repo] || !strings.EqualFold(reply.Repositories[0].FullName, repo)) {
		return "", errors.New("GitHub installation token repository scope mismatch")
	}
	c.tokens[repo] = cachedToken{reply.Token, reply.Expires}
	return reply.Token, nil
}

// SourceToken checks current repository identity even on a cache hit. It is not
// available on an Actions token client and must only feed controller Git env.
func (c *Client) SourceToken(ctx context.Context, repo string) (string, error) {
	if c.appID == 0 {
		return "", errors.New("source access requires a GitHub App")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	token, err := c.repositoryToken(ctx, repo)
	if err != nil {
		return "", err
	}
	_, err = c.repository(ctx, repo, token)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (c *Client) auth(ctx context.Context, repo string) (string, error) {
	token, err := c.repositoryToken(ctx, repo)
	if err == nil && c.appID != 0 {
		_, err = c.repository(ctx, repo, token)
	}
	return token, err
}

func (c *Client) resolve(path string) (*url.URL, error) {
	u, err := url.Parse(path)
	if err != nil {
		return nil, errors.New("invalid GitHub API URL")
	}
	u = c.base.ResolveReference(u)
	if u.Scheme != c.base.Scheme || u.Host != c.base.Host || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("GitHub API URL escaped approved origin")
	}
	return u, nil
}

func (c *Client) request(ctx context.Context, method, path, token, etag string, input, output any) (http.Header, bool, error) {
	u, err := c.resolve(path)
	if err != nil {
		return nil, false, err
	}
	c.rateMu.Lock()
	delay := c.blockedUntil.Sub(c.now())
	status := c.blockedStatus
	c.rateMu.Unlock()
	if delay > 0 {
		return nil, false, &Error{Status: status, RetryAfter: delay}
	}
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return nil, false, errors.New("cannot encode GitHub request")
		}
		if len(data) > maxResponseBytes {
			return nil, false, errors.New("GitHub request exceeds size limit")
		}
		body = bytes.NewReader(data)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, false, errors.New("cannot construct GitHub request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "macserve")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, false, errors.New("GitHub request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && etag != "" {
		return resp.Header, true, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := c.retryAfter(resp)
		if retry > 0 {
			c.rateMu.Lock()
			until := c.now().Add(retry)
			if until.After(c.blockedUntil) {
				c.blockedUntil, c.blockedStatus = until, resp.StatusCode
			}
			c.rateMu.Unlock()
		}
		return nil, false, &Error{Status: resp.StatusCode, RetryAfter: retry}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, false, errors.New("cannot read GitHub response")
	}
	if len(data) > maxResponseBytes {
		return nil, false, errors.New("GitHub response exceeds size limit")
	}
	if output != nil {
		if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || json.Unmarshal(data, output) != nil {
			return nil, false, errors.New("invalid GitHub JSON response")
		}
	}
	return resp.Header, false, nil
}

func (c *Client) retryAfter(resp *http.Response) time.Duration {
	value := resp.Header.Get("Retry-After")
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		const maximum = time.Duration(1<<63 - 1)
		if seconds > int64(maximum/time.Second) {
			return maximum
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil && when.After(c.now()) {
		return when.Sub(c.now())
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			if seconds, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
				if delay := time.Unix(seconds, 0).Sub(c.now()); delay > 0 {
					return delay
				}
			}
		}
		return time.Minute
	}
	return 0
}

func (c *Client) nextPage(header http.Header, current string) (string, error) {
	var next string
	for _, line := range header.Values("Link") {
		for _, entry := range strings.Split(line, ",") {
			parts := strings.Split(strings.TrimSpace(entry), ";")
			isNext := false
			for _, parameter := range parts[1:] {
				key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
				if ok && strings.TrimSpace(key) == "rel" {
					for _, relation := range strings.Fields(strings.Trim(strings.TrimSpace(value), `"`)) {
						if relation == "next" {
							isNext = true
						}
					}
				}
			}
			if !isNext {
				continue
			}
			if next != "" || !strings.HasPrefix(parts[0], "<") || !strings.HasSuffix(parts[0], ">") {
				return "", errors.New("invalid GitHub pagination link")
			}
			cur, err := c.resolve(current)
			if err != nil {
				return "", err
			}
			ref, err := url.Parse(strings.TrimSuffix(strings.TrimPrefix(parts[0], "<"), ">"))
			if err != nil {
				return "", errors.New("invalid GitHub pagination URL")
			}
			u, err := c.resolve(cur.ResolveReference(ref).String())
			if err != nil {
				return "", err
			}
			if u.Path != cur.Path || u.RawPath != cur.RawPath {
				return "", errors.New("GitHub pagination changed endpoint")
			}
			next = u.String()
		}
	}
	return next, nil
}
