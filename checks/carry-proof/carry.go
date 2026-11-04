package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/checks/boundary"
	"github.com/jerryfane/macserve/internal/qualification"
)

const (
	// releaseAsset is the binary whose digest SHA256SUMS lists.
	releaseAsset = "macserve-darwin-arm64"
	// ciWorkflow is the workflow whose successful run on the tag commit the
	// proof records.
	ciWorkflow = ".github/workflows/ci.yml"
	// maxProof mirrors internal/setup.MaxCarryProof: macserve upgrade refuses
	// a larger carry-proof.json, so the generator never writes one.
	maxProof = 64 << 10
	// maxDownload bounds every HTTP response; maxSource bounds the
	// decompressed source archive.
	maxDownload = 64 << 20
	maxSource   = 512 << 20
	maxEntries  = 100000
)

var (
	hex64   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	semver  = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	repoRE  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	carryOK = []string{boundary.ClassC, boundary.ClassG, boundary.ClassT}
)

// refusal is a release that cannot carry qualification: the release still
// publishes, without carry-proof.json.
type refusal struct{ reason string }

func (r *refusal) Error() string { return r.reason }

func refuse(format string, args ...any) error {
	return &refusal{reason: fmt.Sprintf(format, args...)}
}

// fetcher performs an HTTP GET and returns the body of a 200 response.
type fetcher func(ctx context.Context, url string, header http.Header) ([]byte, error)

// params are one generator run.
type params struct {
	repo, tag, prev   string
	binary, rebuilt   string
	gitDir, token     string
	get               fetcher
	codeload, release string // base URLs, overridable for tests
	api               string
}

func (p *params) withDefaults() {
	if p.codeload == "" {
		p.codeload = "https://codeload.github.com"
	}
	if p.release == "" {
		p.release = "https://github.com"
	}
	if p.api == "" {
		p.api = "https://api.github.com"
	}
}

// entry is one git tree entry: its mode and object id.
type entry struct{ mode, blob string }

// generate builds the carry proof of p.tag over its predecessor, or returns
// a *refusal naming why the release cannot carry qualification. Any other
// error is operational (git failed).
func generate(ctx context.Context, p params) (qualification.CarryProof, error) {
	p.withDefaults()
	var proof qualification.CarryProof
	if p.binary != p.rebuilt {
		return proof, fmt.Errorf("binary sha256 %s differs from the rebuilt %s", p.binary, p.rebuilt)
	}
	g := gitRepo{dir: p.gitDir}
	if !semver.MatchString(p.tag) {
		return proof, refuse("tag %q is not vX.Y.Z", p.tag)
	}
	if p.prev == "" {
		tags, err := g.lines("tag", "--list", "v*")
		if err != nil {
			return proof, err
		}
		if p.prev = predecessor(tags, p.tag); p.prev == "" {
			return proof, refuse("no vX.Y.Z tag precedes %s", p.tag)
		}
	} else if compareSemver(p.prev, p.tag) >= 0 {
		return proof, refuse("predecessor %s does not precede %s", p.prev, p.tag)
	}
	format, err := g.objectFormat()
	if err != nil {
		return proof, err
	}
	from, err := g.release(p.prev)
	if err != nil {
		return proof, err
	}
	to, err := g.release(p.tag)
	if err != nil {
		return proof, err
	}
	if from.Commit == to.Commit {
		return proof, refuse("%s and %s name the same commit", p.prev, p.tag)
	}
	oldTree, err := g.tree(from.Tree)
	if err != nil {
		return proof, err
	}
	newTree, err := g.tree(to.Tree)
	if err != nil {
		return proof, err
	}

	// The predecessor's own BOUNDARY.json classifies the delta; the release
	// must not change it.
	manifestEntry, ok := oldTree[boundary.ManifestFile]
	if !ok {
		return proof, refuse("%s has no %s", p.prev, boundary.ManifestFile)
	}
	if !regularMode(manifestEntry.mode) {
		return proof, refuse("%s %s is not a regular file", p.prev, boundary.ManifestFile)
	}
	if newTree[boundary.ManifestFile] != manifestEntry {
		return proof, refuse("%s changes %s", p.tag, boundary.ManifestFile)
	}
	manifestData, err := g.output("cat-file", "blob", manifestEntry.blob)
	if err != nil {
		return proof, err
	}
	manifest, err := boundary.ParseManifest(manifestData)
	if err != nil {
		return proof, refuse("%s %v", p.prev, err)
	}
	changed, classes, err := classifyChanges(manifest, oldTree, newTree)
	if err != nil {
		return proof, err
	}

	// The predecessor release's published binary digest.
	sums, err := p.get(ctx, fmt.Sprintf("%s/%s/releases/download/%s/SHA256SUMS", p.release, p.repo, p.prev), nil)
	if err != nil {
		return proof, refuse("%s SHA256SUMS: %v", p.prev, err)
	}
	if from.BinarySHA256, err = releaseDigest(sums); err != nil {
		return proof, refuse("%s SHA256SUMS: %v", p.prev, err)
	}
	to.BinarySHA256 = p.binary
	if from.BinarySHA256 == to.BinarySHA256 {
		return proof, refuse("%s and %s publish the same binary", p.prev, p.tag)
	}

	// The source archive GitHub serves for each tag is exactly its git tree.
	if from.SourceSHA256, _, err = p.source(ctx, p.prev, from.Commit, oldTree, format); err != nil {
		return proof, err
	}
	var tagFiles map[string][]byte
	if to.SourceSHA256, tagFiles, err = p.source(ctx, p.tag, to.Commit, newTree, format); err != nil {
		return proof, err
	}

	ci, err := p.ciRun(ctx, to.Commit)
	if err != nil {
		return proof, err
	}

	// The full BOUNDARY.json check, C/G source rules included, on the tag's
	// verified source.
	if err := sourceCheck(tagFiles, newTree); err != nil {
		return proof, err
	}

	proof = qualification.CarryProof{
		Schema:               1,
		Kind:                 "release-carry-proof",
		ReleaseEffect:        "QualificationCarried",
		From:                 from,
		To:                   to,
		BoundaryManifestBlob: manifestEntry.blob,
		ClassesPresent:       classes,
		Changed:              changed,
		CI:                   ci,
		Provenance:           &qualification.CarryProvenance{RebuiltSHA256: p.rebuilt, AttestationBundleSHA256: ""},
	}
	return proof, nil
}

// encodeProof renders the proof as published and checks it the way macserve
// upgrade and qualify carry will.
func encodeProof(proof qualification.CarryProof) ([]byte, error) {
	data, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > maxProof {
		return nil, refuse("proof is %d bytes, over the %d byte limit", len(data), maxProof)
	}
	if _, err := qualification.ValidateCarryProof(data, proof.From.BinarySHA256, proof.To.BinarySHA256); err != nil {
		return nil, refuse("generated proof rejected: %v", err)
	}
	return data, nil
}

// classifyChanges lists every path whose mode or blob differs between the
// trees, sorted, and refuses any change that is not a carry class.
func classifyChanges(m *boundary.Manifest, oldTree, newTree map[string]entry) ([]qualification.CarryChange, []string, error) {
	var paths []string
	for p, e := range oldTree {
		if newTree[p] != e {
			paths = append(paths, p)
		}
	}
	for p := range newTree {
		if _, ok := oldTree[p]; !ok {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	if len(paths) == 0 {
		return nil, nil, refuse("no path changed")
	}
	var changes []qualification.CarryChange
	var classes []string
	for _, p := range paths {
		change := qualification.CarryChange{Path: p}
		if e, ok := oldTree[p]; ok {
			if !regularMode(e.mode) {
				return nil, nil, refuse("%s: mode %s change is not carryable", p, e.mode)
			}
			change.Old = []string{e.mode, e.blob}
		}
		if e, ok := newTree[p]; ok {
			if !regularMode(e.mode) {
				return nil, nil, refuse("%s: mode %s change is not carryable", p, e.mode)
			}
			change.New = []string{e.mode, e.blob}
		}
		class, err := m.Classify(p)
		if err != nil {
			return nil, nil, refuse("%v", err)
		}
		if !slices.Contains(carryOK, class) {
			return nil, nil, refuse("%s is class %s", p, class)
		}
		change.Class = class
		changes = append(changes, change)
		classes = append(classes, class)
	}
	slices.Sort(classes)
	return changes, slices.Compact(classes), nil
}

func regularMode(mode string) bool { return mode == "100644" || mode == "100755" }

// sourceCheck writes the tag's verified regular files to a scratch
// directory and runs the full boundary check there.
func sourceCheck(files map[string][]byte, tree map[string]entry) error {
	root, err := os.MkdirTemp("", "carry-proof-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	var tracked []boundary.File
	for _, p := range sortedKeys(tree) {
		e := tree[p]
		data, ok := files[p]
		if !regularMode(e.mode) || !ok {
			return refuse("%s: tag tree holds a %s entry", p, e.mode)
		}
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		perm := os.FileMode(0o644)
		if e.mode == "100755" {
			perm = 0o755
		}
		if err := os.WriteFile(full, data, perm); err != nil {
			return err
		}
		tracked = append(tracked, boundary.File{Path: p, Mode: e.mode})
	}
	_, problems, err := boundary.Check(root, tracked)
	if err != nil {
		return refuse("boundary check: %v", err)
	}
	if len(problems) > 0 {
		return refuse("boundary check: %s", strings.Join(problems, "; "))
	}
	return nil
}

// source downloads the codeload archive of tag and requires its files to be
// exactly tree. It returns the archive's sha256 and the regular files.
func (p params) source(ctx context.Context, tag, commit string, tree map[string]entry, format string) (string, map[string][]byte, error) {
	archive, err := p.get(ctx, fmt.Sprintf("%s/%s/tar.gz/refs/tags/%s", p.codeload, p.repo, tag), nil)
	if err != nil {
		return "", nil, refuse("%s source archive: %v", tag, err)
	}
	files, data, err := readArchive(archive, commit, format)
	if err != nil {
		return "", nil, refuse("%s source archive: %v", tag, err)
	}
	for _, path := range sortedKeys(tree) {
		got, ok := files[path]
		if !ok {
			return "", nil, refuse("%s source archive lacks %s", tag, path)
		}
		if got != tree[path] {
			return "", nil, refuse("%s source archive differs from the git tree at %s", tag, path)
		}
	}
	for _, path := range sortedKeys(files) {
		if _, ok := tree[path]; !ok {
			return "", nil, refuse("%s source archive has %s, absent from the git tree", tag, path)
		}
	}
	sum := sha256.Sum256(archive)
	return hex.EncodeToString(sum[:]), data, nil
}

// readArchive reads a git-archive tar.gz: one top-level directory holding
// directories, regular files and symlinks only. Symlinks are recorded as git
// records them (mode 120000, the target as blob) and never followed or
// extracted. A pax comment, when present, must name commit.
func readArchive(archive []byte, commit, format string) (map[string]entry, map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, nil, err
	}
	tr := tar.NewReader(io.LimitReader(zr, maxSource))
	files := map[string]entry{}
	data := map[string][]byte{}
	prefix := ""
	for n := 0; ; n++ {
		if n > maxEntries {
			return nil, nil, errors.New("too many entries")
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			if c, ok := hdr.PAXRecords["comment"]; ok && c != commit {
				return nil, nil, fmt.Errorf("archive of commit %s, not %s", c, commit)
			}
			continue
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if prefix == "" {
			top, _, _ := strings.Cut(name, "/")
			if top == "" || top == "." || top == ".." {
				return nil, nil, fmt.Errorf("entry %q outside a top-level directory", hdr.Name)
			}
			prefix = top
		}
		if name == prefix {
			if hdr.Typeflag != tar.TypeDir {
				return nil, nil, fmt.Errorf("top-level entry %q is not a directory", hdr.Name)
			}
			continue
		}
		rel, ok := strings.CutPrefix(name, prefix+"/")
		if !ok || !validPath(rel) {
			return nil, nil, fmt.Errorf("entry %q outside %s/", hdr.Name, prefix)
		}
		if _, dup := files[rel]; dup {
			return nil, nil, fmt.Errorf("entry %q listed twice", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			content, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, err
			}
			mode := "100644"
			if hdr.Mode&0o111 != 0 {
				mode = "100755"
			}
			files[rel] = entry{mode: mode, blob: blobID(format, content)}
			data[rel] = content
		case tar.TypeSymlink:
			files[rel] = entry{mode: "120000", blob: blobID(format, []byte(hdr.Linkname))}
		default:
			return nil, nil, fmt.Errorf("entry %q has unsupported type %q", hdr.Name, hdr.Typeflag)
		}
	}
	if prefix == "" {
		return nil, nil, errors.New("empty archive")
	}
	return files, data, nil
}

func validPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// blobID is the git object id of a blob with content.
func blobID(format string, content []byte) string {
	var h hash.Hash
	if format == "sha256" {
		h = sha256.New()
	} else {
		h = sha1.New()
	}
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// ciRun finds a successful CI workflow run on commit.
func (p params) ciRun(ctx context.Context, commit string) (*qualification.CarryCI, error) {
	q := url.Values{"head_sha": {commit}, "status": {"success"}, "per_page": {"100"}}
	u := fmt.Sprintf("%s/repos/%s/actions/workflows/%s/runs?%s", p.api, p.repo, path.Base(ciWorkflow), q.Encode())
	header := http.Header{
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {"2022-11-28"},
	}
	if p.token != "" {
		header.Set("Authorization", "Bearer "+p.token)
	}
	body, err := p.get(ctx, u, header)
	if err != nil {
		return nil, refuse("CI runs of %s: %v", commit, err)
	}
	var runs struct {
		WorkflowRuns []struct {
			ID         int64  `json:"id"`
			Path       string `json:"path"`
			HeadSHA    string `json:"head_sha"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		} `json:"workflow_runs"`
	}
	if err := json.Unmarshal(body, &runs); err != nil {
		return nil, refuse("CI runs of %s: %v", commit, err)
	}
	var best *qualification.CarryCI
	for _, r := range runs.WorkflowRuns {
		workflow, _, _ := strings.Cut(r.Path, "@")
		if r.ID <= 0 || workflow != ciWorkflow || r.HeadSHA != commit || r.Status != "completed" || r.Conclusion != "success" || !strings.EqualFold(r.Repository.FullName, p.repo) {
			continue
		}
		if best == nil || r.ID > best.RunID {
			best = &qualification.CarryCI{Workflow: ciWorkflow, RunID: r.ID, HeadSHA: r.HeadSHA, Conclusion: r.Conclusion}
		}
	}
	if best == nil {
		return nil, refuse("no successful %s run on %s", ciWorkflow, commit)
	}
	return best, nil
}

// releaseDigest parses SHA256SUMS strictly ("<64 hex>  <name>" or
// "<64 hex> *<name>" per line) and returns the single macserve-darwin-arm64
// digest.
func releaseDigest(sums []byte) (string, error) {
	var found []string
	for _, line := range strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n") {
		digest, name, ok := strings.Cut(line, "  ")
		if !ok {
			digest, name, ok = strings.Cut(line, " *")
		}
		if !ok || !hex64.MatchString(digest) || name == "" || strings.ContainsAny(name, " \t\r") {
			return "", fmt.Errorf("malformed line %q", line)
		}
		if name == releaseAsset {
			found = append(found, digest)
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("lists %s %d times", releaseAsset, len(found))
	}
	return found[0], nil
}

// predecessor is the highest vX.Y.Z tag below tag, or "".
func predecessor(tags []string, tag string) string {
	best := ""
	for _, t := range tags {
		if semver.MatchString(t) && compareSemver(t, tag) < 0 && (best == "" || compareSemver(t, best) > 0) {
			best = t
		}
	}
	return best
}

// compareSemver orders two vX.Y.Z tags.
func compareSemver(a, b string) int {
	pa, pb := semver.FindStringSubmatch(a), semver.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		x, _ := strconv.ParseUint(pa[i], 10, 64)
		y, _ := strconv.ParseUint(pb[i], 10, 64)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// gitRepo runs git in one repository.
type gitRepo struct{ dir string }

func (g gitRepo) output(args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", g.dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (g gitRepo) lines(args ...string) ([]string, error) {
	out, err := g.output(args...)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

func (g gitRepo) revParse(rev string) (string, error) {
	out, err := g.lines("rev-parse", "--verify", "--end-of-options", rev)
	if err != nil {
		return "", err
	}
	if len(out) != 1 {
		return "", fmt.Errorf("git rev-parse %s: %q", rev, out)
	}
	return out[0], nil
}

func (g gitRepo) objectFormat() (string, error) {
	out, err := g.lines("rev-parse", "--show-object-format")
	if err != nil {
		return "", err
	}
	if len(out) != 1 || (out[0] != "sha1" && out[0] != "sha256") {
		return "", fmt.Errorf("git object format %q", out)
	}
	return out[0], nil
}

// release resolves a tag to its tag object, commit and tree.
func (g gitRepo) release(tag string) (qualification.CarryRelease, error) {
	r := qualification.CarryRelease{Tag: tag}
	ref := "refs/tags/" + tag
	var err error
	if r.TagObject, err = g.revParse(ref); err != nil {
		return r, err
	}
	if r.Commit, err = g.revParse(ref + "^{commit}"); err != nil {
		return r, err
	}
	r.Tree, err = g.revParse(ref + "^{tree}")
	return r, err
}

// tree lists every blob, symlink and submodule entry of a tree recursively.
func (g gitRepo) tree(tree string) (map[string]entry, error) {
	out, err := g.output("ls-tree", "-r", "-z", tree)
	if err != nil {
		return nil, err
	}
	entries := map[string]entry{}
	for _, rec := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if rec == "" {
			continue
		}
		meta, file, ok := strings.Cut(rec, "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 3 || file == "" {
			return nil, fmt.Errorf("git ls-tree: malformed entry %q", rec)
		}
		entries[file] = entry{mode: fields[0], blob: fields[2]}
	}
	return entries, nil
}

// httpGet is the production fetcher.
func httpGet(ctx context.Context, u string, header http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDownload {
		return nil, fmt.Errorf("GET %s: response over %d bytes", u, maxDownload)
	}
	return body, nil
}
