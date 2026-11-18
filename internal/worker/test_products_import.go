package worker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/profiles"
)

// importedProductsStaging is where the worker stages a consumer job's
// downloaded test products in the job's protected evidence root, outside
// the evidence it exports, until they are verified and extracted.
const importedProductsStaging = "imported-products.tar"

// maxXctestrunBytes bounds the .xctestrun plist a consumer imports (the
// measured herdrup one is 12 KB).
const maxXctestrunBytes = 1 << 20

// importTestProducts imports a consumer job's test products, root-side,
// before any job command runs. It streams input, the controller's bytes,
// to a root-owned staging file while hashing them and refuses the job
// unless their SHA-256 is the request's, before extracting anything. Then
// it extracts the verified tar into the workspace's products directory
// (${PRODUCTS}) with the export's entry rules: only directories and regular
// files with safe names, at most maxArchiveEntries, the
// Debug-iphonesimulator tree and exactly the one top-level .xctestrun the
// request names, which it writes as macserve.xctestrun after checking its
// plist (checkXctestrun). The workspace pass that follows hands the
// products to the job user. Every error names the step ("test products:
// ...").
func (x *execution) importTestProducts(ctx context.Context, input io.Reader) (returned error) {
	defer func() {
		if returned != nil {
			returned = fmt.Errorf("test products: %w", returned)
		}
	}()
	ref := x.job.Request.Products
	if ref == nil || !profiles.ValidProductsRef(*ref) {
		return errors.New("invalid products reference")
	}
	if input == nil {
		return errors.New("none delivered")
	}
	staged, err := x.evidenceRoot.OpenFile(importedProductsStaging, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() {
		returned = errors.Join(returned, staged.Close(), x.evidenceRoot.Remove(importedProductsStaging))
	}()
	limit := min(profiles.MaxTestProductsBytes, x.engine.options.MaxWorkspaceBytes)
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(staged, h), &contextReader{ctx: ctx, reader: io.LimitReader(input, limit+1)})
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if written > limit {
		return fmt.Errorf("download exceeds %d bytes", limit)
	}
	if digest := hex.EncodeToString(h.Sum(nil)); digest != ref.SHA256 {
		return fmt.Errorf("download SHA-256 %s is not the sealed %s", digest, ref.SHA256)
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := x.root.Mkdir(profiles.ProductsDir, 0700); err != nil {
		return err
	}
	products, err := x.root.OpenRoot(profiles.ProductsDir)
	if err != nil {
		return err
	}
	defer func() { returned = errors.Join(returned, products.Close()) }()
	if err := extractTestProducts(ctx, products, staged, ref.Xctestrun, x.engine.options.MaxWorkspaceBytes); err != nil {
		return err
	}
	x.result.Observation.ImportedProducts = ref.SHA256
	return nil
}

// extractTestProducts extracts a verified test-products.tar into root: the
// Debug-iphonesimulator tree and its one top-level .xctestrun, named
// xctestrun, which it writes as profiles.ConsumerXctestrun. Anything else,
// a symlink, hard link or special file, an unsafe or duplicate name, more
// than maxArchiveEntries entries or more than budget bytes is refused.
func extractTestProducts(ctx context.Context, root *os.Root, input io.Reader, xctestrun string, budget int64) error {
	tr := tar.NewReader(input)
	seen := map[string]bool{}
	var extracted int64
	entries, xctestruns, platform := 0, 0, false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if entries++; entries > maxArchiveEntries {
			return archiveRefusal("more than %d entries", maxArchiveEntries)
		}
		name := strings.TrimSuffix(header.Name, "/")
		if !safeRelative(name) || seen[name] {
			return archiveRefusal("unsafe or duplicate entry %s", strconv.Quote(header.Name))
		}
		seen[name] = true
		dir := header.Typeflag == tar.TypeDir
		if !dir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return archiveRefusal("%s is not a regular file or directory", strconv.Quote(name))
		}
		if header.Size < 0 || dir && header.Size != 0 || header.Size > budget-extracted {
			return archiveRefusal("%s exceeds the workspace budget", strconv.Quote(name))
		}
		extracted += header.Size
		switch {
		case name == testProductsPlatform:
			if !dir {
				return archiveRefusal("%s is not a directory", testProductsPlatform)
			}
			platform = true
			if err := root.Mkdir(name, 0700); err != nil {
				return err
			}
			continue
		case strings.HasPrefix(name, testProductsPlatform+"/"):
			if !seen[path.Dir(name)] {
				return archiveRefusal("%s precedes its directory", strconv.Quote(name))
			}
		case name == xctestrun && !dir:
			if xctestruns++; xctestruns > 1 {
				return archiveRefusal("more than one .xctestrun")
			}
			if header.Size > maxXctestrunBytes {
				return archiveRefusal(".xctestrun exceeds %d bytes", maxXctestrunBytes)
			}
			plist, err := io.ReadAll(&contextReader{ctx: ctx, reader: tr})
			if err != nil {
				return err
			}
			if err := checkXctestrun(plist); err != nil {
				return err
			}
			if err := writeNew(root, profiles.ConsumerXctestrun, bytes.NewReader(plist), 0600); err != nil {
				return err
			}
			continue
		default:
			return archiveRefusal("unexpected entry %s", strconv.Quote(name))
		}
		if dir {
			if err := root.Mkdir(name, 0700); err != nil {
				return err
			}
			continue
		}
		mode := os.FileMode(0600)
		if header.Mode&0111 != 0 {
			mode = 0700
		}
		if err := writeNew(root, name, &contextReader{ctx: ctx, reader: tr}, mode); err != nil {
			return err
		}
	}
	if !platform || xctestruns != 1 {
		return archiveRefusal("the products lack %s or the .xctestrun %s", testProductsPlatform, strconv.Quote(xctestrun))
	}
	return nil
}

// writeNew creates name in root, which must not exist, with content.
func writeNew(root *os.Root, name string, content io.Reader, mode os.FileMode) error {
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(file, content)
	return errors.Join(err, file.Close())
}

// xctestrunBundleKeys are the .xctestrun keys whose values xcodebuild
// resolves to the bundles it installs and runs: each must be inside the
// products (rootedPath under xctestrunProductRoots). XCInjectBundleInto may
// also be "unused".
var xctestrunBundleKeys = map[string]bool{"TestHostPath": true, "TestBundlePath": true, "UITargetAppPath": true, "DependentProductPaths": true, "ProductPaths": true, "XCInjectBundleInto": true}

// xctestrunProductRoots are the placeholders xcodebuild resolves inside the
// imported products: the products directory and a test host inside it.
var xctestrunProductRoots = []string{"__TESTROOT__", "__TESTHOST__"}

// xctestrunToolchainRoots are the placeholders xcodebuild resolves inside
// the pinned Xcode (a UI test's runner and the injected test libraries).
var xctestrunToolchainRoots = []string{"__PLATFORMS__", "__SHAREDFRAMEWORKS__", "__DEVELOPERUSRLIB__"}

// xctestrunSystemRoots are the absolute directories a library path list may
// name: the simulator runtime's system libraries (Xcode itself injects
// /usr/lib/libRPAC.dylib), read-only on the host and in the pinned runtime.
var xctestrunSystemRoots = []string{"/usr/lib/", "/System/Library/"}

// dyldPathVariables are the dyld variables (without DYLD_) whose value is a
// ':'-separated list of paths dyld loads code from or resolves against,
// or a path it reads or writes; each component is confined (pathListKey).
var dyldPathVariables = map[string]bool{"INSERT_LIBRARIES": true, "LIBRARY_PATH": true, "FRAMEWORK_PATH": true, "FALLBACK_LIBRARY_PATH": true, "FALLBACK_FRAMEWORK_PATH": true, "VERSIONED_LIBRARY_PATH": true, "VERSIONED_FRAMEWORK_PATH": true, "ROOT_PATH": true, "SHARED_CACHE_DIR": true, "PRINT_TO_FILE": true}

// dyldFlagVariables are the dyld diagnostic and behaviour flags (without
// DYLD_): dyld tests only whether they are set, so a value is a short
// alphanumeric token such as 1 or YES.
var dyldFlagVariables = map[string]bool{"PRINT_LIBRARIES": true, "PRINT_LIBRARIES_POST_LAUNCH": true, "PRINT_APIS": true, "PRINT_BINDINGS": true, "PRINT_WEAK_BINDINGS": true, "PRINT_REBASINGS": true, "PRINT_INITIALIZERS": true, "PRINT_SEGMENTS": true, "PRINT_STATISTICS": true, "PRINT_STATISTICS_DETAILS": true, "PRINT_ENV": true, "PRINT_OPTS": true, "PRINT_DOFS": true, "PRINT_RPATHS": true, "PRINT_SEARCHING": true, "PRINT_WARNINGS": true, "PRINT_CODE_SIGNATURES": true, "PRINT_INTERPOSING": true, "PRINT_NOTIFICATIONS": true, "BIND_AT_LAUNCH": true, "DISABLE_DOFS": true, "NO_FIX_PREBINDING": true, "FORCE_FLAT_NAMESPACE": true, "PREBIND_DEBUG": true}

var (
	dyldFlagValue   = regexp.MustCompile(`^[A-Za-z0-9]{0,16}$`)
	dyldImageSuffix = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
)

// dyldVariable classifies key when it is a dyld variable (DYLD_*, or as
// launchd passes it to XPC services, __XPC_DYLD_*): its name without the
// prefix, and whether it is one.
func dyldVariable(key string) (string, bool) {
	name, ok := strings.CutPrefix(strings.TrimPrefix(key, "__XPC_"), "DYLD_")
	return name, ok
}

// checkDyldValue checks a dyld variable that is not a path list: a known
// flag holds a short token, DYLD_SHARED_REGION a mode, DYLD_IMAGE_SUFFIX a
// file-name suffix (no '/', so it never leaves a library's directory). Any
// other dyld variable is refused: one dyld might read as a path is never
// accepted as a flag.
func checkDyldValue(key, name, value string) error {
	switch {
	case dyldFlagVariables[name] && dyldFlagValue.MatchString(value),
		name == "SHARED_REGION" && (value == "avoid" || value == "use" || value == "private"),
		name == "IMAGE_SUFFIX" && dyldImageSuffix.MatchString(value):
		return nil
	case dyldFlagVariables[name] || name == "SHARED_REGION" || name == "IMAGE_SUFFIX":
		return archiveRefusal(".xctestrun %s value %s is not a valid setting", key, strconv.Quote(value))
	}
	return archiveRefusal(".xctestrun %s is not a dyld setting the importer knows", key)
}

// pathListKey reports whether key's value is a ':'-separated list of paths
// a process loads code or resources from: a path-valued dyld variable
// (dyldPathVariables, also as __XPC_DYLD_*), and any other key whose name
// says it holds paths. Such a key xcodebuild does not know of is confined
// the same way, never accepted unchecked. (Library-injection variables
// outside dyld's namespace are flags, such as Xcode's
// PERFC_RESET_INSERT_LIBRARIES=1; dyld reads only DYLD_*.)
func pathListKey(key string) bool {
	if name, ok := dyldVariable(key); ok {
		return dyldPathVariables[name]
	}
	for _, suffix := range []string{"_PATH", "_PATHS", "Path", "Paths"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

// checkXctestrun requires an .xctestrun to be an XML property list that is
// relocatable into the imported products and loads code from nowhere else:
//   - every bundle path (xctestrunBundleKeys) is __TESTROOT__ or __TESTHOST__
//     followed by a clean relative path;
//   - every component of a path list (pathListKey: the path-valued DYLD_*
//     and __XPC_DYLD_* variables, *_PATH(S), *Path(s), in any dictionary)
//     is that, a pinned Xcode placeholder followed by a clean relative path,
//     or a clean path in the runtime's system libraries; empty, relative,
//     escaping, other absolute and unknown-placeholder components are
//     refused;
//   - every other dyld variable is a known flag or mode with a valid value
//     (checkDyldValue); an unknown one is refused;
//   - BlueprintProviderRelativePath, the project's name, is a safe relative
//     path.
//
// Any other string (an argument, an ordinary environment value such as a
// URL) is not a path and is left as it is.
func checkXctestrun(plist []byte) error {
	if !bytes.HasPrefix(bytes.TrimLeft(plist, " \t\r\n"), []byte("<?xml")) {
		return archiveRefusal(".xctestrun is not an XML property list")
	}
	decoder := xml.NewDecoder(bytes.NewReader(plist))
	decoder.Strict = true
	// Each open dict or array is a frame; an array's strings belong to the
	// key it is the value of, a dict's string to the <key> before it.
	type frame struct {
		array bool
		key   string
	}
	var frames []frame
	key, inText := "", false
	var text strings.Builder
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return archiveRefusal(".xctestrun plist: %v", err)
		}
		switch t := token.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "dict", "array":
				if len(frames) == 64 {
					return archiveRefusal(".xctestrun plist nests too deeply")
				}
				owner := key
				if owner == "" && len(frames) > 0 && frames[len(frames)-1].array {
					owner = frames[len(frames)-1].key
				}
				frames, key = append(frames, frame{array: t.Name.Local == "array", key: owner}), ""
			case "key", "string":
				inText = true
				text.Reset()
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "dict", "array":
				if len(frames) == 0 {
					return archiveRefusal(".xctestrun plist is malformed")
				}
				frames, key = frames[:len(frames)-1], ""
			case "key":
				inText, key = false, text.String()
			case "string":
				inText = false
				owner := key
				if len(frames) > 0 && frames[len(frames)-1].array {
					owner = frames[len(frames)-1].key
				}
				if err := checkXctestrunString(owner, text.String()); err != nil {
					return err
				}
				key = ""
			default:
				key = ""
			}
		case xml.CharData:
			if inText {
				text.Write(t)
			}
		}
	}
	return nil
}

func checkXctestrunString(key, value string) error {
	switch {
	case xctestrunBundleKeys[key]:
		if !(key == "XCInjectBundleInto" && value == "unused") && !rootedPath(value, xctestrunProductRoots) {
			return archiveRefusal(".xctestrun %s %s is not a path inside the products", key, strconv.Quote(value))
		}
	case key == "BlueprintProviderRelativePath":
		if !safeRelative(value) {
			return archiveRefusal(".xctestrun %s %s is not a safe relative path", key, strconv.Quote(value))
		}
	case pathListKey(key):
		for part := range strings.SplitSeq(value, ":") {
			if !rootedPath(part, xctestrunProductRoots) && !rootedPath(part, xctestrunToolchainRoots) && !rootedPath(part, xctestrunSystemRoots) {
				return archiveRefusal(".xctestrun %s path %s is not inside the products, Xcode or the runtime's system libraries", key, strconv.Quote(part))
			}
		}
	default:
		if name, ok := dyldVariable(key); ok {
			return checkDyldValue(key, name, value)
		}
	}
	return nil
}

// rootedPath reports whether p is one of roots followed by nothing or a
// clean relative path (a root ending in '/' must be followed by one).
func rootedPath(p string, roots []string) bool {
	for _, root := range roots {
		rest, ok := strings.CutPrefix(p, root)
		if !ok {
			continue
		}
		if strings.HasSuffix(root, "/") {
			return rest != "" && safeRelative(strings.TrimSuffix(rest, "/"))
		}
		return cleanBelow(rest)
	}
	return false
}

// cleanBelow reports whether rest, what follows a placeholder, is empty or
// "/" and a safe relative path.
func cleanBelow(rest string) bool {
	if rest == "" {
		return true
	}
	rel, ok := strings.CutPrefix(rest, "/")
	return ok && safeRelative(strings.TrimSuffix(rel, "/"))
}
