package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/profiles"
	"golang.org/x/sys/unix"
)

// testProductsDir is where xcodebuild build-for-testing, run with
// -derivedDataPath ${DERIVED_DATA}, writes the built products and the
// .xctestrun that names them.
var testProductsDir = []string{"derived-data", "Build", "Products"}

// testProductsPlatform is the one platform directory of a Debug simulator
// build's products.
const testProductsPlatform = "Debug-iphonesimulator"

// keepTestProduct reports whether rel, a slash path below the products
// directory, is exported: the platform directory and everything below it,
// and the top-level *.xctestrun entries. Anything else there is left out.
func keepTestProduct(rel string) bool {
	return rel == testProductsPlatform || strings.HasPrefix(rel, testProductsPlatform+"/") || !strings.Contains(rel, "/") && strings.HasSuffix(rel, profiles.XctestrunSuffix)
}

// testProductsTarName names a scanned products node in test-products.tar:
// its path below the products directory, which is the .xctestrun's
// __TESTROOT__, directories with a slash; the products directory itself is
// left out.
func testProductsTarName(n archiveNode) string {
	switch {
	case n.rel == "":
		return ""
	case n.dir:
		return n.rel + "/"
	}
	return n.rel
}

// exportTestProducts seals a build-for-testing job's test products
// root-side, after the job UID has stopped, into the protected evidence root
// as profiles.TestProductsArtifact, and records the .xctestrun's name in the
// job's observation. The workspace is hostile: its derived data is opened
// descriptor-relative on the workspace device, and nothing the job could
// plant in the workspace is exported. Every error names the step ("test
// products: ...").
func (x *execution) exportTestProducts(ctx context.Context) (returned error) {
	defer func() {
		if returned != nil {
			returned = fmt.Errorf("test products: %w", returned)
		}
	}()
	workspace, err := x.engine.workspaces.OpenFile(x.job.ID, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer workspace.Close()
	maxBytes := min(profiles.MaxTestProductsBytes, x.engine.options.MaxArtifactBytes)
	tree, xctestrun, err := scanTestProducts(ctx, workspace, archiveLimits{entries: maxArchiveEntries, bytes: maxBytes})
	if err != nil {
		return err
	}
	defer tree.root.Close()
	file, err := x.evidenceRoot.OpenFile(profiles.TestProductsArtifact, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if returned != nil {
			returned = errors.Join(returned, x.evidenceRoot.Remove(profiles.TestProductsArtifact))
		}
	}()
	_, err = sealTree(ctx, tree, file, maxBytes, testProductsTarName)
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	x.result.Observation.Xctestrun = xctestrun
	x.productsSealed = true
	return nil
}

// scanTestProducts opens the workspace's derived-data/Build/Products on the
// workspace device and scans the entries keepTestProduct exports within
// limits, refusing what a sealed archive may not hold (see scanTree). The
// products must hold the Debug-iphonesimulator directory and exactly one
// .xctestrun, a regular file with a valid name, which it returns with the
// tree (whose root the caller closes).
func scanTestProducts(ctx context.Context, workspace *os.File, limits archiveLimits) (*archiveTree, string, error) {
	var top unix.Stat_t
	if err := fstatFD(int(workspace.Fd()), &top); err != nil {
		return nil, "", err
	}
	device := uint64(top.Dev)
	root := workspace
	for _, name := range testProductsDir {
		next, err := openDirAt(root, name, device)
		if root != workspace {
			root.Close()
		}
		if err != nil {
			return nil, "", fmt.Errorf("open %s: %w", strings.Join(testProductsDir, "/"), err)
		}
		root = next
	}
	tree, err := scanTree(ctx, root, device, limits, unix.Fstatat, keepTestProduct)
	if err != nil {
		root.Close()
		return nil, "", err
	}
	xctestrun, err := testProductsShape(tree)
	if err != nil {
		root.Close()
		return nil, "", err
	}
	return tree, xctestrun, nil
}

// testProductsShape checks a scanned products tree's top level: the
// platform directory and exactly one .xctestrun regular file, whose name it
// returns.
func testProductsShape(tree *archiveTree) (string, error) {
	if platform, ok := tree.node(testProductsPlatform); !ok || !platform.dir {
		return "", archiveRefusal("no %s directory", testProductsPlatform)
	}
	var xctestruns []string
	for _, n := range tree.children("") {
		if n.rel == testProductsPlatform {
			continue
		}
		if n.dir || !profiles.ValidXctestrun(n.rel) {
			return "", archiveRefusal("%s is not a valid .xctestrun file", strconv.Quote(n.rel))
		}
		xctestruns = append(xctestruns, n.rel)
	}
	if len(xctestruns) != 1 {
		return "", archiveRefusal("%d .xctestrun files, want exactly one", len(xctestruns))
	}
	return xctestruns[0], nil
}
