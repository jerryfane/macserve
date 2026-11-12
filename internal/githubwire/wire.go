// Package githubwire holds the GitHub pull-request intake types shared by the
// controller's poller, the root-owned controller configuration and the
// owner-side waiter. It is class B: it has no store or runtime dependency.
package githubwire

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"

	"github.com/jerryfane/macserve/internal/model"
)

// Policy admits pull requests in one of two forms; a policy that names both a
// repository and an owner, or neither, is refused (CheckForm).
//
// The repository form pins one repository: RepositoryID binds GitHub events,
// check runs and receipts to it, and Repository is its current name. Each
// Profiles entry names either an explicit profile whose Repo is that
// repository or an org template whose owners include the repository owner;
// the template owner rule is the one enforced by API admission
// (profiles.Registry.Resolve), and a repository with an explicit profile of
// the template's kind cannot name it.
//
// The owner form covers every repository of one GitHub account that the App
// installation lists: Owner is the account's lowercase login and OwnerID its
// numeric ID, so a renamed or re-registered login never matches. BaseBranches
// and, with DefaultBranch, each repository's default branch are the allowed
// bases. Profiles name org build templates only; a pull request runs the first
// one whose owners include Owner and that the head's .macserve.json admits. A
// repository a repository-form policy pins is governed by that policy alone.
//
// Matrix (repository form only) runs simulator test and script templates:
// each entry is one job per eligible head, of one of Profiles with a shard of
// the head's .macserve.json on one of the template's simulators. A profile
// that is a simulator test or script template runs only through its matrix
// entries. With MatrixSkipDrafts a draft pull request's head admits no matrix
// entry; marking it ready admits them, and converting it back to a draft
// ends none.
type Policy struct {
	RepositoryID     int64         `json:"repository_id,omitempty"`
	Repository       string        `json:"repository,omitempty"`
	Owner            string        `json:"owner,omitempty"`
	OwnerID          int64         `json:"owner_id,omitempty"`
	DefaultBranch    bool          `json:"default_branch,omitempty"`
	AuthorIDs        []int64       `json:"author_ids"`
	BaseBranches     []string      `json:"base_branches"`
	Profiles         []string      `json:"profiles"`
	Matrix           []MatrixEntry `json:"matrix,omitempty"`
	MatrixSkipDrafts bool          `json:"matrix_skip_drafts,omitempty"`
	PolicyRevision   int           `json:"policy_revision"`
	ActionsBotID     int64         `json:"actions_bot_id"`
	ActionsAppID     int64         `json:"actions_app_id"`
}

// MatrixEntry is one simulator job of a repository-form policy: a profile of
// the policy, a shard name the head's .macserve.json declares for that
// profile's kind (ui_test, unit_test or script) and a simulator the template
// pins.
type MatrixEntry struct {
	Profile   string          `json:"profile"`
	Shard     string          `json:"shard"`
	Simulator model.Simulator `json:"simulator"`
}

// CheckName is the GitHub check run name of a run of profile and, for a
// matrix entry, shard: mac-evidence/<profile>[/<shard>]. Every publisher,
// reader and API report of a check name uses it.
func CheckName(profile, shard string) string {
	if shard == "" {
		return "mac-evidence/" + profile
	}
	return "mac-evidence/" + profile + "/" + shard
}

var shardPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// CheckMatrix refuses a matrix (or matrix_skip_drafts) on an owner-form
// policy, a matrix_skip_drafts without a matrix, and a matrix entry that is
// not one of the policy's profiles, has an invalid shard name or an
// incomplete simulator, or repeats a profile and shard. Whether the profile
// is a simulator template pinning that simulator is checked against the
// profile registry when the controller starts.
func (p Policy) CheckMatrix() error {
	if p.OwnerScoped() && (len(p.Matrix) != 0 || p.MatrixSkipDrafts) || p.MatrixSkipDrafts && len(p.Matrix) == 0 {
		return errors.New("a GitHub policy matrix (and matrix_skip_drafts) requires the repository form and at least one entry")
	}
	seen := make(map[[2]string]bool, len(p.Matrix))
	for _, entry := range p.Matrix {
		key := [2]string{entry.Profile, entry.Shard}
		sim := entry.Simulator
		if !slices.Contains(p.Profiles, entry.Profile) || !shardPattern.MatchString(entry.Shard) || sim.Runtime == "" || sim.RuntimeBuild == "" || sim.DeviceType == "" || seen[key] {
			return errors.New("each GitHub policy matrix entry names one of its profiles, a unique shard of that profile and a simulator runtime, runtime build and device type")
		}
		seen[key] = true
	}
	return nil
}

// OwnerScoped reports whether p uses any owner-form field.
func (p Policy) OwnerScoped() bool { return p.Owner != "" || p.OwnerID != 0 || p.DefaultBranch }

// ErrPolicyForm refuses a policy naming both or neither of a repository and an owner.
var ErrPolicyForm = errors.New("a GitHub policy names exactly one of a repository or an owner")

// CheckForm refuses a policy that mixes, or lacks, the repository and owner forms.
func (p Policy) CheckForm() error {
	if p.OwnerScoped() == (p.Repository != "" || p.RepositoryID != 0) {
		return ErrPolicyForm
	}
	return nil
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
