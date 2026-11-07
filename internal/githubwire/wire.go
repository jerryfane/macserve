// Package githubwire holds the GitHub pull-request intake types shared by the
// controller's poller, the root-owned controller configuration and the
// owner-side waiter. It is class B: it has no store or runtime dependency.
package githubwire

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
)

// Policy admits pull requests of one pinned repository. Each Profiles entry
// names either an explicit profile whose Repo is that repository or an
// org template whose owners include the repository owner; the template owner
// rule is the one enforced by API admission (profiles.Registry.Resolve), and a
// repository with an explicit profile of the template's kind cannot name it.
// Policies stay per repository: the numeric ID pin is what binds GitHub
// events, check runs and receipts to one repository, so there is no
// owner-wide policy.
type Policy struct {
	RepositoryID   int64    `json:"repository_id"`
	Repository     string   `json:"repository"`
	AuthorIDs      []int64  `json:"author_ids"`
	BaseBranches   []string `json:"base_branches"`
	Profiles       []string `json:"profiles"`
	PolicyRevision int      `json:"policy_revision"`
	ActionsBotID   int64    `json:"actions_bot_id"`
	ActionsAppID   int64    `json:"actions_app_id"`
}

// Packet is the evidence packet published in a check run.
type Packet struct {
	Schema        int             `json:"schema"`
	JobID         string          `json:"job_id"`
	AttemptID     string          `json:"attempt_id"`
	Requests      []Correlation   `json:"requests"`
	Receipt       json.RawMessage `json:"receipt,omitempty"`
	ReceiptDigest string          `json:"receipt_digest,omitempty"`
}

type Correlation struct {
	CommentID  int64  `json:"comment_id"`
	RequestID  string `json:"request_id"`
	BodySHA256 string `json:"body_sha256"`
}

// Request is one parsed /mac-evidence machine command.
type Request struct{ SHA, Profile, RequestID, Mode string }

var requestPattern = regexp.MustCompile(`^/mac-evidence sha=([0-9a-f]{40}) profile=([A-Za-z0-9][A-Za-z0-9_.-]{0,127}) request=(actions:([1-9][0-9]{0,18}):([1-9][0-9]{0,18})) mode=(ensure|rerun)$`)

func ParseRequest(body string) (Request, error) {
	m := requestPattern.FindStringSubmatch(body)
	if m == nil {
		return Request{}, errors.New("invalid machine request")
	}
	for _, s := range m[4:6] {
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return Request{}, errors.New("invalid machine request identity")
		}
	}
	return Request{SHA: m[1], Profile: m[2], RequestID: m[3], Mode: m[6]}, nil
}
