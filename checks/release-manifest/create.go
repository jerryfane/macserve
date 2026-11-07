package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/checks/boundary"
)

// CarryTrailer is the annotated-tag trailer that makes a tag a
// controller-carry release: "Macserve-Carry-Base: vX.Y.Z".
const CarryTrailer = "Macserve-Carry-Base:"

// carryClasses are the BOUNDARY.json classes (of base_tag's manifest) a
// controller-carry may change. Any B path refuses the carry.
var carryClasses = []string{boundary.ClassK, boundary.ClassC, boundary.ClassG, boundary.ClassT}

// refusal is a manifest CI must not sign.
type refusal struct{ reason string }

func (r *refusal) Error() string { return r.reason }

// refuse builds a refusal whose reason prints on one log line.
func refuse(format string, args ...any) error {
	reason := fmt.Sprintf(format, args...)
	if strings.ContainsFunc(reason, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		q := strconv.Quote(reason)
		reason = q[1 : len(q)-1]
	}
	return &refusal{reason: reason}
}

// carryBase returns the base tag named by tag's annotated-tag message, or
// "" when tag is lightweight or carries no trailer (a full release). More
// than one trailer, or a value that is not vX.Y.Z, is an error.
func carryBase(g gitRepo, tag string) (string, error) {
	if !semver.MatchString(tag) {
		return "", fmt.Errorf("tag %q is not vX.Y.Z", tag)
	}
	ref := "refs/tags/" + tag
	typ, err := g.output("cat-file", "-t", ref)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(typ)) != "tag" {
		return "", nil
	}
	obj, err := g.output("cat-file", "tag", ref)
	if err != nil {
		return "", err
	}
	_, message, _ := strings.Cut(string(obj), "\n\n")
	// A signed tag appends its signature to the message.
	for _, marker := range []string{"-----BEGIN PGP SIGNATURE-----", "-----BEGIN SSH SIGNATURE-----", "-----BEGIN SIGNED MESSAGE-----"} {
		if i := strings.Index(message, "\n"+marker); i >= 0 {
			message = message[:i+1]
		} else if strings.HasPrefix(message, marker) {
			message = ""
		}
	}
	var bases []string
	for _, line := range strings.Split(message, "\n") {
		if value, ok := strings.CutPrefix(line, CarryTrailer); ok {
			bases = append(bases, strings.TrimSpace(value))
		}
	}
	switch {
	case len(bases) == 0:
		return "", nil
	case len(bases) > 1:
		return "", fmt.Errorf("%s has %d %s lines", tag, len(bases), CarryTrailer)
	case !semver.MatchString(bases[0]):
		return "", fmt.Errorf("%s %s %q is not vX.Y.Z", tag, CarryTrailer, bases[0])
	}
	return bases[0], nil
}

// createParams are one `create` run.
type createParams struct {
	gitDir string
	tag    string
	commit string // the commit CI built; must be the tag's commit
	dist   string // holds RootAsset and ControllerAsset as they will publish

	// Carry only. baseSums is base_tag's published SHA256SUMS (attestation
	// verified by the caller); baseManifest, when base_tag published one,
	// its release-manifest.json.
	baseTag, baseSums, baseManifest string

	// binarySchema, when positive, is store_schema_version as printed by
	// the release's own controller binary (`version --json`, run by the
	// macOS rebuild job); the tree's value must equal it.
	binarySchema int

	now     time.Time
	list    packageLister
	schema  schemaReader
	check   func(root string, files []boundary.File) error
	scratch string // parent of the extracted trees; "" = os.TempDir()
}

// create builds the release manifest, or returns a *refusal naming why CI
// must not sign one. Other errors are operational.
func create(ctx context.Context, p createParams) (Manifest, error) {
	m := Manifest{Schema: Schema, Tag: p.tag, Commit: p.commit, Kind: KindFull, BaseTag: p.tag, CreatedAt: canonicalTime(p.now)}
	g := gitRepo{dir: p.gitDir}
	if !semver.MatchString(p.tag) {
		return m, refuse("tag %q is not vX.Y.Z", p.tag)
	}
	tagCommit, err := g.revParse("refs/tags/" + p.tag + "^{commit}")
	if err != nil {
		return m, err
	}
	if tagCommit != p.commit {
		return m, refuse("tag %s is commit %s, not the built commit %s", p.tag, tagCommit, p.commit)
	}
	if m.Binaries.Macserve.SHA256, err = fileDigest(filepath.Join(p.dist, RootAsset)); err != nil {
		return m, err
	}
	if m.Binaries.Controller.SHA256, err = fileDigest(filepath.Join(p.dist, ControllerAsset)); err != nil {
		return m, err
	}
	scratch, err := os.MkdirTemp(p.scratch, "release-manifest-")
	if err != nil {
		return m, err
	}
	defer os.RemoveAll(scratch)
	newTree, err := g.tree(p.commit)
	if err != nil {
		return m, err
	}
	newDir := filepath.Join(scratch, "new")
	if err := g.extract(newTree, newDir); err != nil {
		return m, err
	}
	if m.StoreSchemaVersion, err = p.schema(ctx, newDir); err != nil {
		return m, err
	}
	if p.binarySchema > 0 && p.binarySchema != m.StoreSchemaVersion {
		return m, refuse("%s version --json reports store schema version %d, its source %d", ControllerAsset, p.binarySchema, m.StoreSchemaVersion)
	}
	if p.baseTag == "" {
		return m, m.Validate()
	}

	// controller-carry: the root binary is base_tag's, byte for byte.
	m.Kind, m.BaseTag = KindCarry, p.baseTag
	if !semver.MatchString(p.baseTag) || compareSemver(p.baseTag, p.tag) >= 0 {
		return m, refuse("base tag %q does not precede %s", p.baseTag, p.tag)
	}
	baseCommit, err := g.revParse("refs/tags/" + p.baseTag + "^{commit}")
	if err != nil {
		return m, err
	}
	if baseCommit == p.commit {
		return m, refuse("%s and %s name the same commit", p.baseTag, p.tag)
	}
	sums, err := os.ReadFile(p.baseSums)
	if err != nil {
		return m, err
	}
	baseRoot, err := sumsDigest(sums, RootAsset)
	if err != nil {
		return m, refuse("%s SHA256SUMS: %v", p.baseTag, err)
	}
	if m.Binaries.Macserve.SHA256 != baseRoot {
		return m, refuse("%s in %s is %s, not %s's published %s", RootAsset, p.dist, m.Binaries.Macserve.SHA256, p.baseTag, baseRoot)
	}
	baseSchema := 0
	if p.baseManifest != "" {
		bm, err := checkBaseManifest(p.baseManifest, sums, p.baseTag, baseCommit, baseRoot)
		if err != nil {
			return m, err
		}
		baseSchema = bm.StoreSchemaVersion
	}

	baseTree, err := g.tree(baseCommit)
	if err != nil {
		return m, err
	}
	if err := carryableChanges(g, baseTree, newTree, p.baseTag); err != nil {
		return m, err
	}
	baseDir := filepath.Join(scratch, "base")
	if err := g.extract(baseTree, baseDir); err != nil {
		return m, err
	}

	// The root binary's source closure must be unchanged: same main-module
	// files, same dependency modules, same go.mod and go.sum.
	baseClosure, err := closure(ctx, baseDir, p.list)
	if err != nil {
		return m, err
	}
	newClosure, err := closure(ctx, newDir, p.list)
	if err != nil {
		return m, err
	}
	if diff := closureDiff(baseClosure, newClosure); len(diff) > 0 {
		shown := diff
		if len(shown) > 10 {
			shown = append(shown[:10:10], fmt.Sprintf("... %d more", len(diff)-10))
		}
		return m, refuse("source closure of %s differs between %s (%s) and %s (%s): %s", rootPackage, p.baseTag, closureDigest(baseClosure)[:16], p.tag, closureDigest(newClosure)[:16], strings.Join(shown, ", "))
	}

	// No store migration in a carry.
	treeSchema, err := p.schema(ctx, baseDir)
	if err != nil {
		return m, err
	}
	if baseSchema != 0 && baseSchema != treeSchema {
		return m, refuse("%s release manifest store_schema_version %d differs from its source's %d", p.baseTag, baseSchema, treeSchema)
	}
	if treeSchema != m.StoreSchemaVersion {
		return m, refuse("store schema version %d of %s differs from %d of %s", m.StoreSchemaVersion, p.tag, treeSchema, p.baseTag)
	}

	// The full boundary check (classes, C/G source rules, link graph) on the
	// new tree.
	files := make([]boundary.File, 0, len(newTree))
	for _, path := range sortedKeys(newTree) {
		files = append(files, boundary.File{Path: path, Mode: newTree[path].mode})
	}
	if err := p.check(newDir, files); err != nil {
		return m, err
	}
	return m, m.Validate()
}

// carryableChanges classifies every path changed between the trees by
// base_tag's BOUNDARY.json (which must itself be unchanged) and refuses a
// carry that changes any path outside carryClasses.
func carryableChanges(g gitRepo, baseTree, newTree map[string]entry, baseTag string) error {
	be, ok := baseTree[boundary.ManifestFile]
	if !ok || !regularMode(be.mode) {
		return refuse("%s has no regular %s", baseTag, boundary.ManifestFile)
	}
	if newTree[boundary.ManifestFile] != be {
		return refuse("the release changes %s", boundary.ManifestFile)
	}
	data, err := g.output("cat-file", "blob", be.blob)
	if err != nil {
		return err
	}
	bm, err := boundary.ParseManifest(data)
	if err != nil {
		return refuse("%s %v", baseTag, err)
	}
	var changed []string
	for p, e := range baseTree {
		if newTree[p] != e {
			changed = append(changed, p)
		}
	}
	for p := range newTree {
		if _, ok := baseTree[p]; !ok {
			changed = append(changed, p)
		}
	}
	slices.Sort(changed)
	for _, p := range changed {
		class, err := bm.Classify(p)
		if err != nil {
			return refuse("%v", err)
		}
		if !slices.Contains(carryClasses, class) {
			return refuse("%s is class %s in %s's %s; a controller-carry may change only %s paths", p, class, baseTag, boundary.ManifestFile, strings.Join(carryClasses, ", "))
		}
	}
	return nil
}

// checkBaseManifest binds base_tag's own release-manifest.json to its
// attested SHA256SUMS and requires it to describe a full release of
// baseCommit whose root binary is baseRoot.
func checkBaseManifest(file string, sums []byte, baseTag, baseCommit, baseRoot string) (Manifest, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return Manifest{}, err
	}
	listed, err := sumsDigest(sums, ManifestAsset)
	if err != nil {
		return Manifest{}, refuse("%s SHA256SUMS: %v", baseTag, err)
	}
	if sha256Hex(data) != listed {
		return Manifest{}, refuse("%s %s does not match its SHA256SUMS", baseTag, ManifestAsset)
	}
	bm, err := Parse(data)
	if err != nil {
		return bm, refuse("%s %v", baseTag, err)
	}
	switch {
	case bm.Tag != baseTag || bm.Commit != baseCommit:
		return bm, refuse("%s %s describes %s at %s", baseTag, ManifestAsset, bm.Tag, bm.Commit)
	case bm.Kind != KindFull:
		return bm, refuse("base tag %s is a %s release; a carry's base must be a %s release", baseTag, bm.Kind, KindFull)
	case bm.Binaries.Macserve.SHA256 != baseRoot:
		return bm, refuse("%s %s lists macserve %s, SHA256SUMS %s", baseTag, ManifestAsset, bm.Binaries.Macserve.SHA256, baseRoot)
	}
	return bm, nil
}

// boundaryCheck is the production createParams.check: the repository's
// full boundary check on an extracted tree.
func boundaryCheck(root string, files []boundary.File) error {
	_, problems, err := boundary.Check(root, files)
	if err != nil {
		return refuse("boundary check: %v", err)
	}
	if len(problems) > 0 {
		return refuse("boundary check: %s", strings.Join(problems, "; "))
	}
	return nil
}

func fileDigest(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}
