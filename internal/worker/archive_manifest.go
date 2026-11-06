package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/model"
)

// maxInfoPlistBytes bounds a bundle's Info.plist and a requested
// entitlements (.xcent) plist before decoding.
const maxInfoPlistBytes = 1 << 20

// PlistDecoder converts property list bytes to JSON (see Options.PlistJSON).
type PlistDecoder func(context.Context, []byte) ([]byte, error)

// machOMagics are the leading bytes of thin and fat Mach-O files, both byte
// orders.
var machOMagics = [][]byte{
	{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
	{0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca}, {0xca, 0xfe, 0xba, 0xbf}, {0xbf, 0xba, 0xfe, 0xca},
}

// signableContainers maps a directory of an app or app extension to the
// bundle extension it holds.
var signableContainers = map[string]string{"PlugIns": ".appex", "Extensions": ".appex", "Frameworks": ".framework", "Watch": ".app"}

// requestedEntitlements is the canonical entitlements JSON a bundle's build
// requested, by bundle directory name (see archiveEntitlements).
type requestedEntitlements map[string]json.RawMessage

// isMachO reports whether a scanned regular file starts with a Mach-O magic.
func (t *archiveTree) isMachO(n archiveNode) (bool, error) {
	if n.size < 4 {
		return false, nil
	}
	file, err := t.open(n)
	if err != nil {
		return false, err
	}
	defer file.Close()
	var magic [4]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil {
		return false, err
	}
	return slices.ContainsFunc(machOMagics, func(m []byte) bool { return bytes.Equal(m, magic[:]) }), nil
}

// infoPlist is the part of a bundle's Info.plist the manifest binds.
type infoPlist struct {
	id, executable, packageType string
	shortVersion, version       string
	hasShort, hasVersion        bool
}

func readInfoPlist(ctx context.Context, tree *archiveTree, bundle string, decode PlistDecoder) (infoPlist, error) {
	var info infoPlist
	name := path.Join(bundle, "Info.plist")
	n, ok := tree.node(name)
	if !ok || n.dir {
		return info, archiveRefusal("bundle %s has no Info.plist file", strconv.Quote(bundle))
	}
	raw, err := tree.read(ctx, n, maxInfoPlistBytes)
	if err != nil {
		return info, err
	}
	decoded, err := decode(ctx, raw)
	if err != nil {
		return info, fmt.Errorf("decode %s: %w", strconv.Quote(name), err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &fields); err != nil || fields == nil {
		return info, archiveRefusal("%s is not a dictionary", strconv.Quote(name))
	}
	str := func(key string) (string, bool) {
		var value string
		raw, ok := fields[key]
		return value, ok && json.Unmarshal(raw, &value) == nil
	}
	for key, target := range map[string]*string{"CFBundleIdentifier": &info.id, "CFBundleExecutable": &info.executable, "CFBundlePackageType": &info.packageType} {
		value, ok := str(key)
		if !ok || value == "" {
			return info, archiveRefusal("%s lacks string %s", strconv.Quote(name), key)
		}
		*target = value
	}
	info.shortVersion, info.hasShort = str("CFBundleShortVersionString")
	info.version, info.hasVersion = str("CFBundleVersion")
	return info, nil
}

// buildSigningManifest describes a scanned .xcarchive tree: its one root app
// Products/Applications/<name>.app and, recursively below each app or app
// extension, the bundles signableContainers names; each bundle's Info.plist
// identity and executable (a regular Mach-O file); apps and app extensions
// at release's version; unique bundle identifiers; and every Mach-O file
// under Products either a listed bundle's executable or a .dylib directly in
// a listed app or app extension's Frameworks directory (Dylibs). Archive and
// Executables are the sealer's; every bundle's entitlements are {} until
// archiveManifest adds the requested ones.
func buildSigningManifest(ctx context.Context, tree *archiveTree, release model.ReleaseRequest, decode PlistDecoder) (SigningManifest, error) {
	m := SigningManifest{Schema: SigningManifestSchema, BuildName: release.BuildName, BuildNumber: release.BuildNumber, Dylibs: []string{}, Executables: []string{}}
	applications, ok := tree.node("Products/Applications")
	if !ok || !applications.dir {
		return m, archiveRefusal("no Products/Applications directory")
	}
	apps := tree.children("Products/Applications")
	if len(apps) != 1 || !apps[0].dir || path.Ext(apps[0].rel) != ".app" {
		return m, archiveRefusal("Products/Applications must hold exactly one .app bundle, holds %d entries", len(apps))
	}
	queue := []string{apps[0].rel}
	executables := map[string]bool{}
	ids := map[string]string{}
	codeDirs := map[string]bool{}
	for len(queue) > 0 {
		if len(m.Bundles) == maxSignableBundles {
			return m, archiveRefusal("more than %d bundles", maxSignableBundles)
		}
		bundle := queue[0]
		queue = queue[1:]
		info, err := readInfoPlist(ctx, tree, bundle, decode)
		if err != nil {
			return m, err
		}
		ext := path.Ext(bundle)
		if want := map[string]string{".app": "APPL", ".appex": "XPC!", ".framework": "FMWK"}[ext]; info.packageType != want {
			return m, archiveRefusal("bundle %s package type %q is not %q", strconv.Quote(bundle), info.packageType, want)
		}
		if other, ok := ids[info.id]; ok {
			return m, archiveRefusal("bundles %s and %s share identifier %q", strconv.Quote(other), strconv.Quote(bundle), info.id)
		}
		ids[info.id] = bundle
		if !bundleNamePattern.MatchString(info.executable) || info.executable == "." || info.executable == ".." {
			return m, archiveRefusal("bundle %s executable %q", strconv.Quote(bundle), info.executable)
		}
		executable := path.Join(bundle, info.executable)
		node, ok := tree.node(executable)
		if !ok || node.dir {
			return m, archiveRefusal("bundle %s executable %s is not a regular file", strconv.Quote(bundle), strconv.Quote(info.executable))
		}
		if machO, err := tree.isMachO(node); err != nil || !machO {
			return m, archiveRefusal("bundle %s executable %s is not a Mach-O file", strconv.Quote(bundle), strconv.Quote(info.executable))
		}
		executables[executable] = true
		b := SignableBundle{Path: bundle, BundleID: info.id, Executable: info.executable, PackageType: info.packageType}
		if info.hasShort {
			b.ShortVersion = info.shortVersion
		}
		if info.hasVersion {
			b.Version = info.version
		}
		if ext != ".framework" {
			if !info.hasShort || !info.hasVersion || info.shortVersion != release.BuildName || info.version != release.BuildNumber {
				return m, archiveRefusal("bundle %s version %s (%s) is not the release's %s (%s)", strconv.Quote(bundle), info.shortVersion, info.version, release.BuildName, release.BuildNumber)
			}
			codeDirs[path.Join(bundle, "Frameworks")] = true
			for _, container := range []string{"Extensions", "Frameworks", "PlugIns", "Watch"} {
				for _, child := range tree.children(path.Join(bundle, container)) {
					if child.dir && path.Ext(child.rel) == signableContainers[container] {
						queue = append(queue, child.rel)
					}
				}
			}
		}
		b.Entitlements = json.RawMessage("{}")
		if b.Entitlements, b.EntitlementsSHA256, err = canonicalEntitlements(b.Entitlements); err != nil {
			return m, err
		}
		m.Bundles = append(m.Bundles, b)
	}
	slices.SortFunc(m.Bundles, func(a, b SignableBundle) int { return strings.Compare(a.Path, b.Path) })
	for _, n := range tree.nodes {
		if n.dir || !strings.HasPrefix(n.rel, "Products/") || executables[n.rel] {
			continue
		}
		machO, err := tree.isMachO(n)
		if err != nil {
			return m, err
		}
		if !machO {
			continue
		}
		if path.Ext(n.rel) != ".dylib" || !codeDirs[path.Dir(n.rel)] {
			return m, archiveRefusal("unlisted nested code %s", strconv.Quote(n.rel))
		}
		m.Dylibs = append(m.Dylibs, n.rel)
	}
	return m, nil
}
