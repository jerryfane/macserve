// Package githubwire holds the GitHub pull-request intake types shared by the
// controller's poller, the root-owned controller configuration and the
// owner-side waiter. It is class B: it has no store or runtime dependency.
package githubwire

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
// ends none. With MatrixSkipPaths a head whose every changed file (against
// its base, as GitHub compares them) was added or modified and is one the
// paths match (SkipPaths.Match) runs no matrix entry: each gets a neutral
// check that says so. Any doubt (a failed or possibly truncated comparison,
// no base commit, a removed, renamed, copied or mode-changed file, no changed
// file) runs the matrix.
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
	MatrixSkipPaths  *SkipPaths    `json:"matrix_skip_paths,omitempty"`
	PolicyRevision   int           `json:"policy_revision"`
	ActionsBotID     int64         `json:"actions_bot_id"`
	ActionsAppID     int64         `json:"actions_app_id"`
}

// SkipPaths selects the files a change may touch and still skip a policy
// matrix: a path matches when an Include glob matches it and no Exclude glob
// does (exclude wins). Globs follow MatchPath.
type SkipPaths struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude,omitempty"`
}

// Match reports whether the repository-relative file path name is one the
// paths select, and the first Include glob that matches it.
func (s SkipPaths) Match(name string) (string, bool) {
	for _, glob := range s.Exclude {
		if MatchPath(glob, name) {
			return "", false
		}
	}
	for _, glob := range s.Include {
		if MatchPath(glob, name) {
			return glob, true
		}
	}
	return "", false
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

// Bounds of matrix_skip_paths: the globs of each list, their length and their
// ** segments.
const (
	MaxSkipPaths         = 32
	maxSkipPathBytes     = 96
	maxSkipPathGlobstars = 2
)

// CheckMatrix refuses a matrix (or matrix_skip_drafts or matrix_skip_paths)
// on an owner-form policy, either option without a matrix, a matrix entry
// that is not one of the policy's profiles, has an invalid shard name or an
// incomplete simulator, or repeats a profile and shard, and skip paths
// without an include glob, with more than MaxSkipPaths globs in a list, or
// with an invalid (ValidSkipPath) or repeated glob. Whether the profile is a
// simulator template pinning that simulator is checked against the profile
// registry when the controller starts.
func (p Policy) CheckMatrix() error {
	options := p.MatrixSkipDrafts || p.MatrixSkipPaths != nil
	if p.OwnerScoped() && (len(p.Matrix) != 0 || options) || options && len(p.Matrix) == 0 {
		return errors.New("a GitHub policy matrix (and matrix_skip_drafts and matrix_skip_paths) requires the repository form and at least one entry")
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
	if s := p.MatrixSkipPaths; s != nil {
		if len(s.Include) == 0 || len(s.Include) > MaxSkipPaths || len(s.Exclude) > MaxSkipPaths {
			return fmt.Errorf("GitHub policy matrix_skip_paths has 1 to %d include and at most %d exclude globs", MaxSkipPaths, MaxSkipPaths)
		}
		for _, globs := range [][]string{s.Include, s.Exclude} {
			for i, glob := range globs {
				if !ValidSkipPath(glob) || slices.Contains(globs[:i], glob) {
					return fmt.Errorf("GitHub policy matrix_skip_paths glob %q is invalid or repeated", glob)
				}
			}
		}
	}
	return nil
}

// ValidSkipPath reports a matrix_skip_paths glob: a slash-separated relative
// path of at most 96 bytes whose segments are each "**" (at most two) or a
// non-empty path.Match pattern other than "." and "..".
func ValidSkipPath(glob string) bool {
	if glob == "" || len(glob) > maxSkipPathBytes || !utf8.ValidString(glob) || strings.ContainsFunc(glob, unicode.IsControl) {
		return false
	}
	stars := 0
	for _, segment := range strings.Split(glob, "/") {
		if segment == "**" {
			stars++
			continue
		}
		if segment == "" || segment == "." || segment == ".." || strings.Contains(segment, "**") {
			return false
		}
		if _, err := path.Match(segment, ""); err != nil {
			return false
		}
	}
	return stars <= maxSkipPathGlobstars
}

// MatchPath reports whether the repository-relative file path name matches
// glob: segment by segment with path.Match (so * and ? never cross a /),
// where a "**" segment matches zero or more whole segments. Matching is
// case-sensitive.
func MatchPath(glob, name string) bool {
	return matchSegments(strings.Split(glob, "/"), strings.Split(name, "/"))
}

func matchSegments(glob, name []string) bool {
	for len(glob) > 0 {
		if glob[0] == "**" {
			for i := 0; i <= len(name); i++ {
				if matchSegments(glob[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if ok, err := path.Match(glob[0], name[0]); !ok || err != nil {
			return false
		}
		glob, name = glob[1:], name[1:]
	}
	return len(name) == 0
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
