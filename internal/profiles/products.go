package profiles

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jerryfane/macserve/internal/model"
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
	// ProductsDir is a consumer job's workspace directory, ${PRODUCTS},
	// that the worker extracts the verified test products into before any
	// job command runs: the tar's __TESTROOT__.
	ProductsDir = "products"
	// ConsumerXctestrun is the name the worker gives the products' one
	// .xctestrun file in ProductsDir.
	ConsumerXctestrun = "macserve.xctestrun"
)

var producerJobID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// ValidProductsRef reports whether r is well formed: a job ID, a lowercase
// hex SHA-256 and a valid .xctestrun name. Whether the producer sealed those
// products is the controller's admission and the keyholder's check.
func ValidProductsRef(r model.ProductsRef) bool {
	return producerJobID.MatchString(r.ProducerJobID) && configDigest.MatchString(r.SHA256) && ValidXctestrun(r.Xctestrun)
}

func cloneProductsRef(r *model.ProductsRef) *model.ProductsRef {
	if r == nil {
		return nil
	}
	copy := *r
	return &copy
}

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

// testWithoutBuildingRun is a consumer test job's xcodebuild arguments: the
// tests of the imported products' .xctestrun on the job's simulator, limited
// to the shard's selectors. It names no project, workspace or scheme, which
// xcodebuild refuses beside -xctestrun.
func testWithoutBuildingRun(only []string) []string {
	return append([]string{"xcodebuild", "test-without-building", "-xctestrun", "${PRODUCTS}/" + ConsumerXctestrun, "-destination", "id=${SIMULATOR_ID}", "-resultBundlePath", "${RESULT_BUNDLE}"}, only...)
}
