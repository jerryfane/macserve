package profiles

import (
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/jerryfane/macserve/internal/model"
)

const (
	// ArchivePath is the workspace-relative .xcarchive an ios_archive job's
	// run writes; the worker's trusted sealing step reads it after the run.
	ArchivePath = "App.xcarchive"
	// ArchiveArtifact and SigningManifestArtifact are an ios_archive job's two
	// required artifacts: the deterministic tar of ArchivePath and its
	// canonical signing manifest, both exported by the worker's sealing step.
	ArchiveArtifact         = "App.xcarchive.tar"
	SigningManifestArtifact = "signing-manifest.json"
)

// Release request limits. The aggregate bound keeps a compact receipt, which
// carries the release in its request and its release field, below the
// receipt publication limit.
const (
	maxDartDefines      = 32
	maxDartDefineValue  = 1024
	maxDartDefinesBytes = 4096
)

var (
	buildNamePattern     = regexp.MustCompile(`^[0-9]{1,4}(\.[0-9]{1,4}){0,2}$`)
	buildNumberPattern   = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)
	dartDefineKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// ValidateRelease checks an ios_archive request's release: build_name is one
// to three dot-separated numbers of one to four digits, build_number one to
// nine digits without a leading zero (except "0"), and dart_defines, only
// for a Flutter template, at most 32 entries whose keys match
// ^[A-Z][A-Z0-9_]{0,63}$ and whose values are at most 1024 printable ASCII
// characters without '$' (the worker substitutes ${...} placeholders in
// recipe arguments), at most 4096 key and value bytes in all.
func ValidateRelease(r model.ReleaseRequest, flutter bool) error {
	if !buildNamePattern.MatchString(r.BuildName) {
		return fmt.Errorf("%w: release build_name must match %s", ErrInvalid, buildNamePattern)
	}
	if !buildNumberPattern.MatchString(r.BuildNumber) {
		return fmt.Errorf("%w: release build_number must be 1 to 9 digits without a leading zero", ErrInvalid)
	}
	if len(r.DartDefines) == 0 {
		return nil
	}
	if !flutter {
		return fmt.Errorf("%w: only Flutter ios_archive templates accept dart_defines", ErrUnsupported)
	}
	if len(r.DartDefines) > maxDartDefines {
		return fmt.Errorf("%w: release dart_defines lists at most %d entries", ErrInvalid, maxDartDefines)
	}
	total := 0
	for key, value := range r.DartDefines {
		if !dartDefineKeyPattern.MatchString(key) {
			return fmt.Errorf("%w: dart_defines key %q must match %s", ErrInvalid, key, dartDefineKeyPattern)
		}
		if len(value) > maxDartDefineValue {
			return fmt.Errorf("%w: dart_defines %s value exceeds %d bytes", ErrInvalid, key, maxDartDefineValue)
		}
		for i := range len(value) {
			if value[i] < 0x20 || value[i] > 0x7e || value[i] == '$' {
				return fmt.Errorf("%w: dart_defines %s value must be printable ASCII without '$'", ErrInvalid, key)
			}
		}
		total += len(key) + len(value)
	}
	if total > maxDartDefinesBytes {
		return fmt.Errorf("%w: release dart_defines exceed %d bytes in all", ErrInvalid, maxDartDefinesBytes)
	}
	return nil
}

// cloneRelease copies a release; an empty dart_defines map becomes nil, as
// its JSON encoding omits it.
func cloneRelease(r *model.ReleaseRequest) *model.ReleaseRequest {
	if r == nil {
		return nil
	}
	copy := *r
	copy.DartDefines = nil
	if len(r.DartDefines) > 0 {
		copy.DartDefines = maps.Clone(r.DartDefines)
	}
	return &copy
}

// SameRelease reports whether two releases are both absent or equal.
func SameRelease(a, b *model.ReleaseRequest) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.BuildName == b.BuildName && a.BuildNumber == b.BuildNumber && maps.Equal(a.DartDefines, b.DartDefines)
}

// archiveRun is an ios_archive job's run: the unsigned Release archive for
// any iOS device into ArchivePath at the release's marketing version and
// build number.
func archiveRun(scheme string, release model.ReleaseRequest) []string {
	return []string{"-scheme", scheme, "-configuration", "Release", "-sdk", "iphoneos", "-destination", "generic/platform=iOS", "-archivePath", "${WORKSPACE}/" + ArchivePath, "-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "MARKETING_VERSION=" + release.BuildName, "CURRENT_PROJECT_VERSION=" + release.BuildNumber, "archive"}
}

// flutterConfigArgs are the mode arguments of a Flutter job's
// `flutter build ios --config-only`: the simulator debug configuration, or
// for an ios_archive job the release configuration without signing at the
// release's build name and number, with each Dart define, by key, as its own
// --dart-define argument.
func flutterConfigArgs(release *model.ReleaseRequest) []string {
	if release == nil {
		return []string{"--simulator", "--debug"}
	}
	args := []string{"--release", "--no-codesign", "--build-name", release.BuildName, "--build-number", release.BuildNumber}
	for _, key := range slices.Sorted(maps.Keys(release.DartDefines)) {
		args = append(args, "--dart-define", key+"="+release.DartDefines[key])
	}
	return args
}
