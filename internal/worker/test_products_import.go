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

// xctestrunPathKeys are the .xctestrun keys whose values xcodebuild
// resolves to the bundles it installs and runs; each must be a path inside
// the products or the pinned Xcode (placeholderPath).
var xctestrunPathKeys = map[string]bool{"TestHostPath": true, "TestBundlePath": true, "UITargetAppPath": true, "DependentProductPaths": true, "ProductPaths": true}

// xctestrunToolchainRoots are the placeholders xcodebuild resolves inside
// the pinned Xcode (a UI test's runner and the injected test libraries).
var xctestrunToolchainRoots = []string{"__PLATFORMS__", "__SHAREDFRAMEWORKS__", "__DEVELOPERUSRLIB__"}

// checkXctestrun requires an .xctestrun to be an XML property list that is
// relocatable into the imported products: every bundle path
// (xctestrunPathKeys) is a placeholder path, every ':'-separated component
// of any string that is a path is a placeholder path (never absolute), and
// every __TESTROOT__ or __TESTHOST__ path stays below its root. A
// placeholder path is __TESTROOT__ (the products directory), __TESTHOST__
// (a test host inside it) or a pinned Xcode root, followed by a clean
// relative path.
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
	if xctestrunPathKeys[key] && !placeholderPath(value) {
		return archiveRefusal(".xctestrun %s %s is not a path inside the products", key, strconv.Quote(value))
	}
	for part := range strings.SplitSeq(value, ":") {
		if strings.HasPrefix(part, "/") || strings.Contains(part, "__TESTROOT__") || strings.Contains(part, "__TESTHOST__") {
			if !placeholderPath(part) {
				return archiveRefusal(".xctestrun %s path %s is not inside the products or Xcode", key, strconv.Quote(part))
			}
		}
	}
	return nil
}

// placeholderPath reports whether p is a placeholder root followed by
// nothing or a clean relative path.
func placeholderPath(p string) bool {
	for _, root := range append([]string{"__TESTROOT__", "__TESTHOST__"}, xctestrunToolchainRoots...) {
		if rest, ok := strings.CutPrefix(p, root); ok {
			return cleanBelow(rest)
		}
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
