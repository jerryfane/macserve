package store

import (
	"encoding/json"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// An ios_archive job's release provenance: the controller's server-derived
// default-branch facts at admission. Rows admitted before this column read
// back with no provenance.
const releaseSchema = `
ALTER TABLE jobs ADD COLUMN release_provenance BLOB;
PRAGMA user_version=4;
`

// releaseBytes checks the kind-specific release binding of an admission and
// returns its provenance column value: for an ios_archive job the snapshot's
// release equals the request's and the provenance names the default-branch
// head the request builds, resolved through the GitHub App; every other kind
// carries neither, and its column is NULL.
func releaseBytes(admission model.Admission) ([]byte, error) {
	request, profile, provenance := admission.Request, admission.Profile, admission.ReleaseProvenance
	if request.Kind != model.IOSArchive {
		if request.Release != nil || profile.Release != nil || provenance != nil {
			return nil, ErrInvalid
		}
		return nil, nil
	}
	if request.Release == nil || profiles.ValidateRelease(*request.Release, request.Flutter != nil) != nil || !profiles.SameRelease(profile.Release, request.Release) || provenance == nil {
		return nil, ErrInvalid
	}
	p := *provenance
	if p.Source != model.ProvenanceGitHubApp || p.RepositoryID <= 0 || p.HeadSHA != request.SHA || !model.ValidBranch(p.DefaultBranch) || p.ResolvedAt.Location() != time.UTC || !validTime(p.ResolvedAt) {
		return nil, ErrInvalid
	}
	return json.Marshal(p)
}
