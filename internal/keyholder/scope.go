package keyholder

import (
	"errors"
	"fmt"
	"maps"
	"regexp"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// ReleaseScopeSchema names the release scope document format.
const ReleaseScopeSchema = "macserve-release-scope/1"

// ReleaseScope is the root-owned release-scope.json: per repository (the
// lowercase owner/name a job requests), every input that changes an
// Apple-signed build's output except its version labels.
type ReleaseScope struct {
	Schema       string                  `json:"schema"`
	Repositories map[string]ReleaseEntry `json:"repositories"`
}

// ReleaseEntry is one repository's release scope: its numeric GitHub ID,
// the exact profile or template identity, the toolchain pins and the exact
// Dart defines map (empty for a non-Flutter or define-free release).
type ReleaseEntry struct {
	RepositoryID   int64             `json:"repository_id"`
	ProfileID      string            `json:"profile_id"`
	ProfileVersion int               `json:"profile_version"`
	ProfileDigest  string            `json:"profile_digest"`
	Xcode          model.Xcode       `json:"xcode"`
	Flutter        *model.FlutterPin `json:"flutter,omitempty"`
	DartDefines    map[string]string `json:"dart_defines,omitempty"`
}

// The only output-affecting inputs K may choose for a scoped release are its
// version labels, constrained to these forms.
var (
	BuildNamePattern   = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,2}$`)
	BuildNumberPattern = regexp.MustCompile(`^[0-9]{1,9}$`)
	sha256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	repositoryPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9_.-]+$`)
)

// LoadReleaseScope reads a release scope. A missing file is reported as
// os.ErrNotExist so the caller refuses every release receipt.
func LoadReleaseScope(path string) (ReleaseScope, error) {
	var s ReleaseScope
	raw, err := readBounded(path, maxConfigBytes)
	if err != nil {
		return s, err
	}
	if err := decodeStrict(raw, &s); err != nil {
		return s, fmt.Errorf("release scope: %w", err)
	}
	return s, s.Validate()
}

// Validate checks every entry names a complete, well-formed scope.
func (s ReleaseScope) Validate() error {
	if s.Schema != ReleaseScopeSchema {
		return fmt.Errorf("release scope: schema must be %q", ReleaseScopeSchema)
	}
	ids := map[int64]bool{}
	for repo, e := range s.Repositories {
		if !repositoryPattern.MatchString(repo) || e.RepositoryID <= 0 || e.RepositoryID > 9007199254740991 || ids[e.RepositoryID] {
			return fmt.Errorf("release scope %s: canonical lowercase repository with a unique numeric ID required", repo)
		}
		ids[e.RepositoryID] = true
		if e.ProfileID == "" || e.ProfileVersion <= 0 || !sha256Pattern.MatchString(e.ProfileDigest) || e.Xcode.Version == "" || e.Xcode.Build == "" {
			return fmt.Errorf("release scope %s: profile id, version, digest and Xcode pins are required", repo)
		}
		// The scope's defines must themselves be admissible release defines.
		if err := profiles.ValidateRelease(model.ReleaseRequest{BuildName: "1", BuildNumber: "1", DartDefines: e.DartDefines}, e.Flutter != nil); err != nil {
			return fmt.Errorf("release scope %s: %w", repo, err)
		}
	}
	return nil
}

// Check reports why a sealed release is outside entry, or nil when the
// profile identity, toolchain pins and Dart defines match exactly and the
// version labels have the permitted forms.
func (e ReleaseEntry) Check(profileID string, profileVersion int, profileDigest string, xcode model.Xcode, flutter *model.FlutterPin, release *model.ReleaseRequest) error {
	if profileID != e.ProfileID || profileVersion != e.ProfileVersion || profileDigest != e.ProfileDigest {
		return errors.New("sealed profile identity is outside the release scope")
	}
	if xcode != e.Xcode || !sameFlutterPin(flutter, e.Flutter) {
		return errors.New("sealed toolchain pins are outside the release scope")
	}
	if release == nil {
		return errors.New("sealed request has no release")
	}
	if !BuildNamePattern.MatchString(release.BuildName) {
		return fmt.Errorf("build_name must match %s", BuildNamePattern)
	}
	if !BuildNumberPattern.MatchString(release.BuildNumber) {
		return fmt.Errorf("build_number must match %s", BuildNumberPattern)
	}
	// Exact map equality: any extra, missing or different define refuses.
	if !maps.Equal(release.DartDefines, e.DartDefines) {
		return errors.New("dart_defines differ from the release scope")
	}
	return nil
}

func sameFlutterPin(a, b *model.FlutterPin) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
