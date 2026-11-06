package worker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// SigningManifestSchema is the signing manifest format version.
const SigningManifestSchema = 1

// Signing manifest bounds.
const (
	maxSigningManifestBytes = 4 << 20
	maxSignableBundles      = 256
	maxEntitlementsBytes    = 64 << 10
)

var (
	bundleIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$`)
	rootAppPattern    = regexp.MustCompile(`^Products/Applications/[^/]+\.app$`)
	bundleNamePattern = regexp.MustCompile(`^[^/\x00-\x1f\x7f]{1,255}$`)
)

// SigningManifest is an ios_archive job's signing manifest
// (signing-manifest.json): the deterministic description of the sealed
// unsigned archive a signer may sign. The worker builds it root-side after
// the job's processes have stopped, from the archive tree alone; the
// receipt binds its SHA-256. Every path is relative to the .xcarchive
// directory, which is the tar's single top-level entry Archive.Root.
//
//   - Bundles lists every signable bundle: exactly one root app
//     Products/Applications/<name>.app and, recursively below a listed
//     bundle, each PlugIns/*.appex, Extensions/*.appex, Frameworks/*.framework
//     and Watch/*.app, sorted by path. Apps and app extensions carry the
//     release's version; frameworks are exempt.
//   - Dylibs lists each loose Mach-O dylib in a listed bundle's Frameworks
//     directory; every other Mach-O file under Products is a listed bundle's
//     executable, or the archive was refused.
//   - Executables lists every regular file the tar stores with mode 0755;
//     every other file is 0644 and every directory 0755.
type SigningManifest struct {
	Schema      int              `json:"schema"`
	BuildName   string           `json:"build_name"`
	BuildNumber string           `json:"build_number"`
	Archive     SealedArchive    `json:"archive"`
	Bundles     []SignableBundle `json:"bundles"`
	Dylibs      []string         `json:"dylibs"`
	Executables []string         `json:"executables"`
}

// SealedArchive identifies the deterministic tar of the archive: its
// artifact name (profiles.ArchiveArtifact), its single top-level directory
// (profiles.ArchivePath), SHA-256, size and tar entry count.
type SealedArchive struct {
	Name      string `json:"name"`
	Root      string `json:"root"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Entries   int    `json:"entries"`
}

// SignableBundle is one bundle of the archive: its path, Info.plist
// CFBundleIdentifier, CFBundleExecutable, CFBundlePackageType (APPL, XPC! or
// FMWK), CFBundleShortVersionString and CFBundleVersion, and the canonical
// JSON of the entitlements its build requested ({} when none), with that
// JSON's SHA-256.
type SignableBundle struct {
	Path               string          `json:"path"`
	BundleID           string          `json:"bundle_id"`
	Executable         string          `json:"executable"`
	PackageType        string          `json:"package_type"`
	ShortVersion       string          `json:"short_version,omitempty"`
	Version            string          `json:"version,omitempty"`
	Entitlements       json.RawMessage `json:"entitlements"`
	EntitlementsSHA256 string          `json:"entitlements_sha256"`
}

// EncodeSigningManifest validates m against release and returns its
// canonical bytes.
func EncodeSigningManifest(m SigningManifest, release model.ReleaseRequest) ([]byte, error) {
	if err := validateSigningManifest(m, release); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// ParseSigningManifest decodes canonical signing manifest bytes and
// validates them against release: the structure SigningManifest documents,
// unique bundle identifiers and paths, and every app and app extension at
// the release's build name and number.
func ParseSigningManifest(raw []byte, release model.ReleaseRequest) (SigningManifest, error) {
	var m SigningManifest
	if len(raw) == 0 || len(raw) > maxSigningManifestBytes {
		return m, errors.New("signing manifest is empty or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return m, fmt.Errorf("signing manifest: %w", err)
	}
	if decoder.More() {
		return m, errors.New("signing manifest has trailing data")
	}
	if err := validateSigningManifest(m, release); err != nil {
		return m, err
	}
	encoded, err := json.Marshal(m)
	if err != nil || !bytes.Equal(encoded, raw) {
		return m, errors.New("signing manifest is not canonical")
	}
	return m, nil
}

// canonicalEntitlements returns the canonical JSON of an entitlements
// object (keys sorted, numbers verbatim) and its SHA-256.
func canonicalEntitlements(raw []byte) (json.RawMessage, string, error) {
	if len(raw) > maxEntitlementsBytes {
		return nil, "", errors.New("entitlements exceed size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil || decoder.More() {
		return nil, "", errors.New("entitlements are not a JSON object")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(digest[:]), nil
}

func validManifestPath(name string) bool {
	return name != "" && len(name) <= 1024 && path.Clean(name) == name && !path.IsAbs(name) && name != "." && name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\x00\\")
}

func validateSigningManifest(m SigningManifest, release model.ReleaseRequest) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("signing manifest: "+format, args...)
	}
	if m.Schema != SigningManifestSchema {
		return invalid("schema %d", m.Schema)
	}
	if m.BuildName != release.BuildName || m.BuildNumber != release.BuildNumber {
		return invalid("version %s (%s) is not the release's %s (%s)", m.BuildName, m.BuildNumber, release.BuildName, release.BuildNumber)
	}
	a := m.Archive
	if a.Name != profiles.ArchiveArtifact || a.Root != profiles.ArchivePath || !sha64.MatchString(a.SHA256) || a.SizeBytes <= 0 || a.Entries <= 0 || a.Entries > maxArchiveEntries {
		return invalid("sealed archive identity")
	}
	if len(m.Bundles) == 0 || len(m.Bundles) > maxSignableBundles {
		return invalid("lists %d bundles", len(m.Bundles))
	}
	if m.Dylibs == nil || m.Executables == nil {
		return invalid("dylibs and executables must be lists")
	}
	if !sortedUnique(m.Executables) || len(m.Executables) > maxArchiveEntries {
		return invalid("executables are not sorted, unique paths")
	}
	for _, name := range m.Executables {
		if !validManifestPath(name) {
			return invalid("executable path %q", name)
		}
	}
	bundles := make(map[string]SignableBundle, len(m.Bundles))
	ids := make(map[string]bool, len(m.Bundles))
	root := ""
	for i, b := range m.Bundles {
		if i > 0 && m.Bundles[i-1].Path >= b.Path {
			return invalid("bundles are not sorted by unique path")
		}
		if !validManifestPath(b.Path) || !strings.HasPrefix(b.Path, "Products/") || !bundleNamePattern.MatchString(path.Base(b.Path)) {
			return invalid("bundle path %q", b.Path)
		}
		if !bundleIDPattern.MatchString(b.BundleID) || ids[b.BundleID] {
			return invalid("bundle %s identifier %q is invalid or duplicate", b.Path, b.BundleID)
		}
		ids[b.BundleID] = true
		if b.Executable == "" || b.Executable == "." || b.Executable == ".." || !bundleNamePattern.MatchString(b.Executable) {
			return invalid("bundle %s executable %q", b.Path, b.Executable)
		}
		want := map[string]string{".app": "APPL", ".appex": "XPC!", ".framework": "FMWK"}[path.Ext(b.Path)]
		if want == "" || b.PackageType != want {
			return invalid("bundle %s package type %q", b.Path, b.PackageType)
		}
		if b.PackageType != "FMWK" {
			if b.ShortVersion != release.BuildName || b.Version != release.BuildNumber {
				return invalid("bundle %s version %s (%s) is not the release's %s (%s)", b.Path, b.ShortVersion, b.Version, release.BuildName, release.BuildNumber)
			}
			if _, found := slices.BinarySearch(m.Executables, path.Join(b.Path, b.Executable)); !found {
				return invalid("bundle %s executable is not mode 0755", b.Path)
			}
		}
		canonical, digest, err := canonicalEntitlements(b.Entitlements)
		if err != nil || !bytes.Equal(canonical, b.Entitlements) || digest != b.EntitlementsSHA256 {
			return invalid("bundle %s entitlements are not canonical or their digest mismatches", b.Path)
		}
		if rootAppPattern.MatchString(b.Path) {
			if root != "" {
				return invalid("archive has more than one application")
			}
			root = b.Path
		}
		bundles[b.Path] = b
	}
	if root == "" {
		return invalid("archive has no application")
	}
	for _, b := range m.Bundles {
		if b.Path == root {
			continue
		}
		container := path.Dir(b.Path)
		parent, ok := bundles[path.Dir(container)]
		if !ok || parent.PackageType == "FMWK" || !strings.HasPrefix(b.Path, root+"/") {
			return invalid("bundle %s is not nested in a listed app or app extension", b.Path)
		}
		ext := path.Ext(b.Path)
		switch path.Base(container) {
		case "PlugIns", "Extensions":
			ok = ext == ".appex"
		case "Frameworks":
			ok = ext == ".framework"
		case "Watch":
			ok = ext == ".app"
		default:
			ok = false
		}
		if !ok {
			return invalid("bundle %s is not in a signable bundle directory", b.Path)
		}
	}
	if !sortedUnique(m.Dylibs) {
		return invalid("dylibs are not sorted, unique paths")
	}
	for _, name := range m.Dylibs {
		container := path.Dir(name)
		parent, ok := bundles[path.Dir(container)]
		if !validManifestPath(name) || !ok || parent.PackageType == "FMWK" || path.Base(container) != "Frameworks" || path.Ext(name) != ".dylib" {
			return invalid("dylib %q is not in a listed bundle's Frameworks directory", name)
		}
	}
	return nil
}

func sortedUnique(names []string) bool {
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			return false
		}
	}
	return true
}
