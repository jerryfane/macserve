// Package githubapi implements the bounded GitHub REST protocol used by the
// controller and the credential-separated Actions waiter.
package githubapi

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"
)

type HTTPOptions struct {
	Client *http.Client
	// BaseURL is a library test seam, never a production configuration option.
	BaseURL string
	Now     func() time.Time
}

// AppOptions configures a GitHub App client. InstallationID is the legacy
// single installation; Installations selects an installation by repository
// owner login and takes precedence. Repositories pins exact repositories to
// numeric IDs; Owners approves every repository of those account logins, whose
// IDs are learned from, and verified against, the installation token reply.
type AppOptions struct {
	AppID, InstallationID int64
	Installations         map[string]int64
	PrivateKey            *rsa.PrivateKey
	Repositories          map[string]int64
	Owners                []string
	HTTP                  HTTPOptions
}

// InstallationToken is a short-lived installation token scoped to one
// repository, its expiry and that repository's verified numeric ID and owner ID.
type InstallationToken struct {
	Token        string    `json:"token"`
	ExpiresAt    time.Time `json:"expires_at"`
	RepositoryID int64     `json:"repository_id"`
	OwnerID      int64     `json:"owner_id,omitempty"`
}

// TokenSource mints per-repository installation tokens for a client that
// holds no App key (the keyholder mints them for the controller).
type TokenSource func(ctx context.Context, repo string) (InstallationToken, error)

// RepositorySource lists an owner's installation repositories for a client
// that holds no App key (the keyholder lists them for the controller).
type RepositorySource func(ctx context.Context, owner string) ([]Repository, error)

// BrokeredOptions configures an App client whose tokens come from Tokens and
// whose owner repository listings come from Listing (optional). AppID still
// identifies the App's check runs and comments; Repositories and Owners are
// the same approval policy as AppOptions.
type BrokeredOptions struct {
	AppID        int64
	Tokens       TokenSource
	Listing      RepositorySource
	Repositories map[string]int64
	Owners       []string
	HTTP         HTTPOptions
}

// Error contains no response body, URL, credential, or remote error message.
// RetryAfter is also set for GitHub's secondary rate limits without that header.
type Error struct {
	Status     int
	RetryAfter time.Duration
}

func (e *Error) Error() string { return fmt.Sprintf("GitHub HTTP status %d", e.Status) }

type Repository struct {
	ID            int64           `json:"id"`
	FullName      string          `json:"full_name"`
	Owner         RepositoryOwner `json:"owner"`
	DefaultBranch string          `json:"default_branch"`
}

type RepositoryOwner struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

type PullRequest struct {
	Number           int
	State            string
	Draft            bool
	HeadSHA          string
	HeadRepositoryID int64
	AuthorID         int64
	BaseRef          string
	UpdatedAt        time.Time
}

type Comment struct {
	ID                   int64
	Body                 string
	AuthorID             int64
	AppID                int64
	PullRequest          int
	CreatedAt, UpdatedAt time.Time
}

type Check struct {
	ID                                                     int64
	Name, HeadSHA, ExternalID, Status, Conclusion, HTMLURL string
	AppID                                                  int64
	Output                                                 CheckOutput
}

type CheckOutput struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Text    string `json:"text,omitempty"`
}

type CheckInput struct {
	Name        string      `json:"name,omitempty"`
	HeadSHA     string      `json:"head_sha,omitempty"`
	ExternalID  string      `json:"external_id,omitempty"`
	Status      string      `json:"status,omitempty"`
	Conclusion  string      `json:"conclusion,omitempty"`
	StartedAt   *time.Time  `json:"started_at,omitempty"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
	Output      CheckOutput `json:"output,omitzero"`
}
