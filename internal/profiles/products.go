package profiles

import (
	"strings"
	"unicode/utf8"
)

const (
	// TestProductsArtifact is a build-for-testing producer job's required
	// artifact: the deterministic tar of its derived data's
	// Build/Products/Debug-iphonesimulator tree and its single .xctestrun,
	// written by the worker's trusted export step after the job has stopped
	// (nothing the job writes is exported under this name).
	TestProductsArtifact = "test-products.tar"
	// MaxTestProductsBytes caps that tar, below the 5 GiB per-job artifact
	// cap.
	MaxTestProductsBytes int64 = 4 << 30
	// XctestrunSuffix ends the name of the one .xctestrun file a
	// build-for-testing job's products must hold.
	XctestrunSuffix = ".xctestrun"
)

// ValidXctestrun reports whether name may be the .xctestrun file a sealed
// test-products.tar holds at its top level: a single path component of at
// most 255 bytes of valid UTF-8 ending in ".xctestrun", not starting with '.',
// without control characters, slashes or backslashes.
func ValidXctestrun(name string) bool {
	if len(name) <= len(XctestrunSuffix) || len(name) > 255 || !strings.HasSuffix(name, XctestrunSuffix) || name[0] == '.' || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\") {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// buildForTestingRun is the build-for-testing producer's xcodebuild
// arguments after the container: the Debug simulator build of the scheme's
// tests for any iOS simulator, arm64 only (the Studio is Apple silicon),
// unsigned, with no test selection, into ${DERIVED_DATA}.
func buildForTestingRun(scheme string) []string {
	return []string{"-scheme", scheme, "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator", "-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "ARCHS=arm64", "build-for-testing"}
}
