package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// rootPackage is the main package of the root binary whose source closure a
// controller-carry must leave unchanged.
const rootPackage = "./cmd/macserve"

// controllerPackage answers `version --json` with the store schema version.
const controllerPackage = "./cmd/macserve-controller"

// releaseEnv is checks/release-build.sh's pinned build environment: what
// `go list` sees is what the release build compiled. GOWORK=off keeps a
// go.work above an extracted tree out.
var releaseEnv = []string{
	"GOENV=off", "GOFLAGS=", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "GOWORK=off",
	"CGO_ENABLED=0", "GOOS=darwin", "GOARCH=arm64", "GOARM64=v8.0",
}

// hostEnv runs a tree's controller on the CI host.
var hostEnv = []string{
	"GOENV=off", "GOFLAGS=", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "GOWORK=off", "CGO_ENABLED=0",
}

// goEnv is the process environment for a go command run in dir: every
// variable named in pinned replaced by pinned's value, GOOS/GOARCH/GOARM64
// removed unless pinned sets them, and PWD naming dir (the go command
// reports package directories through an inherited $PWD that resolves to
// its working directory).
func goEnv(pinned []string, dir string) []string {
	drop := map[string]bool{"GOOS": true, "GOARCH": true, "GOARM64": true, "PWD": true}
	for _, kv := range pinned {
		k, _, _ := strings.Cut(kv, "=")
		drop[k] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !drop[k] {
			env = append(env, kv)
		}
	}
	return append(append(env, pinned...), "PWD="+dir)
}

// listedPackage is the part of `go list -json` the closure reads.
type listedPackage struct {
	ImportPath string
	Dir        string
	Standard   bool
	Module     *listedModule
	// Every file list go build consumes. CGO is disabled for releases, so
	// CgoFiles and the C-family lists are normally empty; they are hashed
	// anyway so a change in build settings cannot hide a file.
	GoFiles, CgoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles []string
	SwigFiles, SwigCXXFiles, SysoFiles, EmbedFiles                      []string
	Error                                                               *struct{ Err string }
	DepsErrors                                                          []*struct{ Err string }
}

type listedModule struct {
	Path, Version string
	Main          bool
	Replace       *listedModule
}

func (p listedPackage) files() []string {
	var all []string
	for _, list := range [][]string{p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles, p.SFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles, p.EmbedFiles} {
		all = append(all, list...)
	}
	slices.Sort(all)
	return slices.Compact(all)
}

// packageLister lists `go list -deps` of rootPackage in a module tree.
type packageLister func(ctx context.Context, dir string) ([]listedPackage, error)

// goListDeps is the production packageLister.
func goListDeps(ctx context.Context, dir string) ([]listedPackage, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-json", rootPackage)
	cmd.Dir = dir
	cmd.Env = goEnv(releaseEnv, dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -deps %s in %s: %v: %s", rootPackage, dir, err, strings.TrimSpace(stderr.String()))
	}
	var pkgs []listedPackage
	d := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := d.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// closure maps every input of the root binary's build in the module tree
// at root to a digest:
//
//	go.mod, go.sum           sha256 of the file ("absent" for no go.sum)
//	std IMPORTPATH           the standard-library packages linked (the
//	                         toolchain itself is pinned by go.mod)
//	module PATH@VERSION      each dependency module (content pinned by go.sum)
//	package IMPORTPATH       each main-module package, value its directory
//	file DIR/NAME            sha256 of each main-module source/embed file
//
// Two trees whose closures are equal give byte-identical root binaries
// under checks/release-build.sh, up to the version and VCS stamps.
func closure(ctx context.Context, root string, list packageLister) (map[string]string, error) {
	pkgs, err := list(ctx, root)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("go list -deps %s: no packages", rootPackage)
	}
	entries := map[string]string{}
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		switch {
		case errors.Is(err, os.ErrNotExist) && name == "go.sum":
			entries[name] = "absent"
		case err != nil:
			return nil, err
		default:
			entries[name] = sha256Hex(data)
		}
	}
	for _, p := range pkgs {
		if p.Error != nil {
			return nil, fmt.Errorf("go list: %s: %s", p.ImportPath, p.Error.Err)
		}
		for _, e := range p.DepsErrors {
			return nil, fmt.Errorf("go list: %s: %s", p.ImportPath, e.Err)
		}
		switch {
		case p.Standard:
			entries["std "+p.ImportPath] = ""
		case p.Module == nil:
			return nil, fmt.Errorf("go list: %s has no module", p.ImportPath)
		case p.Module.Main:
			rel, err := filepath.Rel(root, p.Dir)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
				return nil, fmt.Errorf("go list: %s directory %s is outside %s", p.ImportPath, p.Dir, root)
			}
			rel = filepath.ToSlash(rel)
			entries["package "+p.ImportPath] = rel
			for _, name := range p.files() {
				file := path.Join(rel, filepath.ToSlash(name))
				data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
				if err != nil {
					return nil, err
				}
				entries["file "+file] = sha256Hex(data)
			}
		default:
			mod := p.Module
			key := "module " + mod.Path + "@" + mod.Version
			if mod.Replace != nil {
				if mod.Replace.Version == "" {
					return nil, fmt.Errorf("go list: %s is replaced by local directory %s", mod.Path, mod.Replace.Path)
				}
				key += " => " + mod.Replace.Path + "@" + mod.Replace.Version
			}
			entries[key] = ""
		}
	}
	return entries, nil
}

// closureDigest is sha256 over the sorted "KEY\tVALUE\n" lines.
func closureDigest(entries map[string]string) string {
	h := sha256.New()
	for _, k := range sortedKeys(entries) {
		fmt.Fprintf(h, "%s\t%s\n", k, entries[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// closureDiff names every closure key that differs between a and b.
func closureDiff(a, b map[string]string) []string {
	var diff []string
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			diff = append(diff, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			diff = append(diff, k)
		}
	}
	slices.Sort(diff)
	return diff
}

// schemaReader returns the store schema version of the module tree at dir.
type schemaReader func(ctx context.Context, dir string) (int, error)

// controllerSchema runs the tree's own `macserve-controller version --json`
// (built for the CI host) and returns its store_schema_version.
func controllerSchema(ctx context.Context, dir string) (int, error) {
	cmd := exec.CommandContext(ctx, "go", "run", "-buildvcs=false", controllerPackage, "version", "--json")
	cmd.Dir = dir
	cmd.Env = goEnv(hostEnv, dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("macserve-controller version --json in %s: %v: %s", dir, err, strings.TrimSpace(stderr.String()))
	}
	return parseVersion(out)
}

// parseVersion reads the carry contract's `version --json` line.
func parseVersion(out []byte) (int, error) {
	var v struct {
		Version            string `json:"version"`
		Commit             string `json:"commit"`
		StoreSchemaVersion *int   `json:"store_schema_version"`
	}
	d := json.NewDecoder(bytes.NewReader(out))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		return 0, fmt.Errorf("version --json: %v", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return 0, errors.New("version --json: trailing data")
	}
	if v.StoreSchemaVersion == nil || *v.StoreSchemaVersion < 1 {
		return 0, fmt.Errorf("version --json: no positive store_schema_version in %q", bytes.TrimSpace(out))
	}
	return *v.StoreSchemaVersion, nil
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

func (g gitRepo) revParse(rev string) (string, error) {
	out, err := g.output("rev-parse", "--verify", "--end-of-options", rev)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(out))
	if strings.ContainsAny(id, " \n") || id == "" {
		return "", fmt.Errorf("git rev-parse %s: %q", rev, out)
	}
	return id, nil
}

// entry is one git tree entry: its mode and object id.
type entry struct{ mode, blob string }

func regularMode(mode string) bool { return mode == "100644" || mode == "100755" }

// tree lists every blob, symlink and submodule entry of a commit's tree.
func (g gitRepo) tree(commit string) (map[string]entry, error) {
	out, err := g.output("ls-tree", "-r", "-z", "--full-tree", commit)
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

// extract writes the tree's regular files under dir (which must be empty)
// from the object database, as git stores them: no checkout filters, no
// export-subst. A symlink or submodule anywhere in the tree is refused.
func (g gitRepo) extract(tree map[string]entry, dir string) error {
	paths := sortedKeys(tree)
	for _, p := range paths {
		e := tree[p]
		if !regularMode(e.mode) {
			return refuse("%s: mode %s is not a regular file", p, e.mode)
		}
		if !validPath(p) {
			return refuse("%q is not a clean relative path", p)
		}
	}
	cmd := exec.Command("git", "-C", g.dir, "cat-file", "--batch")
	var input bytes.Buffer
	for _, p := range paths {
		input.WriteString(tree[p].blob + "\n")
	}
	cmd.Stdin = &input
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	r := bufio.NewReader(stdout)
	readErr := func() error {
		for _, p := range paths {
			header, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("git cat-file: %v", err)
			}
			fields := strings.Fields(header)
			if len(fields) != 3 || fields[0] != tree[p].blob || fields[1] != "blob" {
				return fmt.Errorf("git cat-file: unexpected header %q for %s", header, p)
			}
			size, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil || size < 0 {
				return fmt.Errorf("git cat-file: bad size in %q", header)
			}
			content := make([]byte, size)
			if _, err := io.ReadFull(r, content); err != nil {
				return fmt.Errorf("git cat-file: %s: %v", p, err)
			}
			if b, err := r.ReadByte(); err != nil || b != '\n' {
				return fmt.Errorf("git cat-file: %s: missing record terminator", p)
			}
			target := filepath.Join(dir, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if tree[p].mode == "100755" {
				mode = 0o755
			}
			if err := os.WriteFile(target, content, mode); err != nil {
				return err
			}
		}
		return nil
	}()
	_, _ = io.Copy(io.Discard, r)
	if err := cmd.Wait(); err != nil && readErr == nil {
		readErr = fmt.Errorf("git cat-file: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return readErr
}

func validPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." || seg == ".git" {
			return false
		}
	}
	return true
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
