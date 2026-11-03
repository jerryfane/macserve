// Package readonly proves that `macserve setup --plan` cannot change host
// state. It type-checks the darwin/arm64 release build and walks the call
// graph from every declaration of the read-only package (all of its files,
// so a new file is covered) and from the listed root functions, following
// every function, method and method set referenced into other module
// packages. Every function, method or package-level variable outside the
// module that the graph references must be in Policy.Uses (optionally only
// from one caller, at most N times) or belong to a pure std package. Calls
// from the read-only code into other module packages must be listed seams.
// Imports are resolved by path through go/types, so aliases, dot imports
// and method values cannot hide a call.
package readonly

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Use restricts one std or third-party object: the only function allowed
// to reference it ("" for any) and the maximum number of references (0 for
// any).
type Use struct {
	Caller string
	Max    int
}

// Policy is what the read-only package may reach.
type Policy struct {
	// Package is the read-only package; every declaration in it is a root.
	Package string
	// Roots are further root functions outside Package, by types.Func
	// FullName.
	Roots []string
	// Imports are the module packages Package may import.
	Imports []string
	// Seams are the module functions outside Package and Roots that
	// read-only code may call. Their own call graphs are checked too.
	Seams []string
	// Dispatch maps a module variable outside Package that holds functions
	// (a command table) to the only root allowed to read it. Entries
	// reached through it are not followed; each needs its own proof.
	Dispatch map[string]string
	// PureStd are std packages whose every function, method and variable
	// may be referenced anywhere.
	PureStd []string
	// Uses lists every other non-module object that may be referenced, by
	// types.Func FullName ("os.Lstat", "(*os/exec.Cmd).Run") or
	// "pkgpath.Var".
	Uses map[string]Use
}

type listedPackage struct {
	ImportPath string
	Dir        string
	Export     string
	Standard   bool
	GoFiles    []string
	CgoFiles   []string
	Module     *struct{ Path string }
	Error      *struct{ Err string }
}

// Build is a listed darwin/arm64 build of a module.
type Build struct {
	root, module string
	pkgs         map[string]listedPackage
}

var buildEnv = []string{"GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0", "GOFLAGS=-mod=readonly", "GOWORK=off"}

// List runs go list over patterns (with dependencies and export data) in
// the module at root.
func List(root string, patterns ...string) (*Build, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return nil, err
	}
	tool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(tool); err != nil {
		tool = "go"
	}
	args := append([]string{"list", "-e", "-export", "-deps", "-json=ImportPath,Dir,Export,Standard,GoFiles,CgoFiles,Module,Error"}, patterns...)
	cmd := exec.Command(tool, args...)
	cmd.Dir = root
	cmd.Env = slices.Concat(os.Environ(), buildEnv, []string{"PWD=" + root})
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %v: %s", err, stderr.String())
	}
	b := &Build{root: root, pkgs: map[string]listedPackage{}}
	d := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := d.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if p.Module != nil && b.module == "" && !p.Standard && strings.HasPrefix(p.Dir, root) {
			b.module = p.Module.Path
		}
		b.pkgs[p.ImportPath] = p
	}
	if b.module == "" {
		return nil, errors.New("go list: no module packages")
	}
	return b, nil
}

type source struct {
	pkg   *types.Package
	info  *types.Info
	files []*ast.File
	decls map[string]*ast.FuncDecl
}

type checker struct {
	b        *Build
	policy   Policy
	overlay  map[string][]byte
	fset     *token.FileSet
	imp      types.Importer
	sources  map[string]*source
	visited  map[string]bool
	queue    []string
	counts   map[string]int
	problems []string
}

// Report is the result of Check: the policy violations and every module
// function the walk reached, both sorted, and the reference counts.
type Report struct {
	Problems []string
	Reached  []string
	// Uses counts the references to each Policy.Uses entry.
	Uses map[string]int
}

// Check applies policy to the build. overlay maps absolute file paths to
// replacement contents (nil removes the file; a new path in a package
// directory adds a file); it lets tests check mutated sources.
func (b *Build) Check(policy Policy, overlay map[string][]byte) (Report, error) {
	c := &checker{b: b, policy: policy, overlay: overlay, fset: token.NewFileSet(), sources: map[string]*source{}, visited: map[string]bool{}, counts: map[string]int{}}
	c.imp = importer.ForCompiler(c.fset, "gc", func(path string) (io.ReadCloser, error) {
		p, ok := b.pkgs[path]
		if !ok || p.Export == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(p.Export)
	})
	root, err := c.load(policy.Package)
	if err != nil {
		return Report{}, err
	}
	if len(root.files) == 0 {
		return Report{}, fmt.Errorf("%s has no files", policy.Package)
	}
	for _, f := range root.files {
		c.checkFile(f)
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				// init functions share one name; walk each one directly.
				if d.Recv == nil && d.Name.Name == "init" {
					c.walk(d, root, policy.Package+".init")
					continue
				}
				c.enqueue(root.info.Defs[d.Name].(*types.Func).FullName())
			case *ast.GenDecl:
				c.walk(d, root, policy.Package+".<init>")
			}
		}
	}
	for _, r := range policy.Roots {
		c.enqueue(r)
	}
	for len(c.queue) > 0 {
		key := c.queue[0]
		c.queue = c.queue[1:]
		if err := c.visit(key); err != nil {
			return Report{}, err
		}
	}
	for key, use := range policy.Uses {
		if use.Max > 0 && c.counts[key] > use.Max {
			c.problem("%s referenced %d times, at most %d allowed", key, c.counts[key], use.Max)
		}
	}
	sort.Strings(c.problems)
	return Report{Problems: slices.Compact(c.problems), Reached: slices.Sorted(maps.Keys(c.visited)), Uses: c.counts}, nil
}

func (c *checker) problem(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
}

func (c *checker) module(pkg *types.Package) bool {
	return pkg != nil && (pkg.Path() == c.b.module || strings.HasPrefix(pkg.Path(), c.b.module+"/"))
}

// funcPackage returns the import path a types.Func FullName key belongs to.
func funcPackage(key string) string {
	if strings.HasPrefix(key, "(") {
		key = strings.TrimPrefix(strings.TrimPrefix(key, "("), "*")
		key, _, _ = strings.Cut(key, ")")
	}
	slash := strings.LastIndex(key, "/")
	dot := strings.Index(key[slash+1:], ".")
	if dot < 0 {
		return key
	}
	return key[:slash+1+dot]
}

func (c *checker) enqueue(key string) {
	if !c.visited[key] {
		c.visited[key] = true
		c.queue = append(c.queue, key)
	}
}

func (c *checker) visit(key string) error {
	src, err := c.load(funcPackage(key))
	if err != nil {
		return err
	}
	decl, ok := src.decls[key]
	if !ok {
		c.problem("%s: no source declaration (interface method or assembly); its behaviour cannot be checked", key)
		return nil
	}
	if decl.Body == nil {
		c.problem("%s: function without a Go body", key)
		return nil
	}
	c.walk(decl, src, key)
	return nil
}

// load type-checks one module package from source (with overlay).
func (c *checker) load(path string) (*source, error) {
	if s, ok := c.sources[path]; ok {
		return s, nil
	}
	p, ok := c.b.pkgs[path]
	if !ok || p.Standard || p.Module == nil || p.Module.Path != c.b.module {
		return nil, fmt.Errorf("%s is not a listed module package", path)
	}
	if p.Error != nil {
		return nil, fmt.Errorf("%s: %s", path, p.Error.Err)
	}
	if len(p.CgoFiles) > 0 {
		c.problem("%s: cgo files", path)
	}
	names := map[string]bool{}
	for _, n := range p.GoFiles {
		names[filepath.Join(p.Dir, n)] = true
	}
	for file := range c.overlay {
		if filepath.Dir(file) == p.Dir && strings.HasSuffix(file, ".go") && !strings.HasSuffix(file, "_test.go") {
			names[file] = c.overlay[file] != nil
		}
	}
	var files []*ast.File
	for _, name := range slices.Sorted(maps.Keys(names)) {
		if !names[name] {
			continue
		}
		var src any
		if data, ok := c.overlay[name]; ok {
			src = data
		}
		f, err := parser.ParseFile(c.fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	conf := types.Config{Importer: c.imp, Sizes: types.SizesFor("gc", "arm64")}
	pkg, err := conf.Check(path, c.fset, files, info)
	if err != nil {
		return nil, fmt.Errorf("type-check %s: %w", path, err)
	}
	s := &source{pkg: pkg, info: info, files: files, decls: map[string]*ast.FuncDecl{}}
	for _, f := range files {
		for _, decl := range f.Decls {
			if d, ok := decl.(*ast.FuncDecl); ok {
				if fn, ok := info.Defs[d.Name].(*types.Func); ok {
					s.decls[fn.FullName()] = d
				}
			}
		}
	}
	c.sources[path] = s
	return s, nil
}

// checkFile applies the import rules to a file of the read-only package.
func (c *checker) checkFile(f *ast.File) {
	name := c.fset.Position(f.Pos()).Filename
	for _, spec := range f.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		switch {
		case path == "C" || path == "unsafe":
			c.problem("%s: imports %s", name, path)
		case strings.HasPrefix(path, c.b.module+"/") || path == c.b.module:
			if !slices.Contains(c.policy.Imports, path) {
				c.problem("%s: imports module package %s outside the policy", name, path)
			}
		case !c.b.pkgs[path].Standard:
			c.problem("%s: imports non-std package %s", name, path)
		}
	}
	for _, group := range f.Comments {
		for _, comment := range group.List {
			if strings.HasPrefix(comment.Text, "//go:linkname") || strings.HasPrefix(comment.Text, "//go:cgo") {
				c.problem("%s: %s directive", name, strings.Fields(comment.Text)[0])
			}
		}
	}
}

func (c *checker) rootCode(caller string) bool {
	return funcPackage(caller) == c.policy.Package || slices.Contains(c.policy.Roots, caller)
}

// walk checks every object node references, as code of caller.
func (c *checker) walk(node ast.Node, src *source, caller string) {
	ast.Inspect(node, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			c.use(src.info.Uses[n], caller, n.Pos())
		case ast.Expr:
			if tv, ok := src.info.Types[n]; ok {
				c.methodsOf(tv.Type)
			}
		}
		return true
	})
}

// methodsOf enqueues the methods of a module-defined named type: values of
// it may reach std code that calls them through an interface.
func (c *checker) methodsOf(t types.Type) {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || !c.module(named.Obj().Pkg()) {
		return
	}
	if _, isInterface := named.Underlying().(*types.Interface); isInterface {
		return
	}
	for m := range named.Origin().Methods() {
		c.enqueue(m.FullName())
	}
}

func (c *checker) use(obj types.Object, caller string, pos token.Pos) {
	switch obj := obj.(type) {
	case *types.Func:
		obj = obj.Origin()
		key := obj.FullName()
		if obj.Pkg() == nil {
			return // error.Error
		}
		if c.module(obj.Pkg()) {
			sig := obj.Type().(*types.Signature)
			if recv := sig.Recv(); recv != nil {
				if _, isInterface := recv.Type().Underlying().(*types.Interface); isInterface {
					c.problem("%s: %s calls module interface method %s", c.fset.Position(pos), caller, key)
					return
				}
			}
			if c.rootCode(caller) && obj.Pkg().Path() != c.policy.Package && !slices.Contains(c.policy.Roots, key) && !slices.Contains(c.policy.Seams, key) {
				c.problem("%s: %s calls %s, which is not a listed seam", c.fset.Position(pos), caller, key)
				return
			}
			c.enqueue(key)
			return
		}
		c.external(key, obj.Pkg().Path(), caller, pos)
	case *types.Var:
		if obj.IsField() || obj.Pkg() == nil || obj.Parent() != obj.Pkg().Scope() {
			return
		}
		key := obj.Pkg().Path() + "." + obj.Name()
		if c.module(obj.Pkg()) {
			if obj.Pkg().Path() != c.policy.Package && holdsCode(obj.Type(), 3) && c.policy.Dispatch[key] != caller {
				c.problem("%s: %s reads %s, a module variable that holds functions or interfaces", c.fset.Position(pos), caller, key)
			}
			return
		}
		c.external(key, obj.Pkg().Path(), caller, pos)
	}
}

func (c *checker) external(key, pkg, caller string, pos token.Pos) {
	if slices.Contains(c.policy.PureStd, pkg) && c.b.pkgs[pkg].Standard {
		return
	}
	use, ok := c.policy.Uses[key]
	if !ok {
		c.problem("%s: %s references %s, which is not allowed", c.fset.Position(pos), caller, key)
		return
	}
	if use.Caller != "" && use.Caller != caller {
		c.problem("%s: %s references %s, allowed only in %s", c.fset.Position(pos), caller, key, use.Caller)
	}
	c.counts[key]++
}

// holdsCode reports a type that can carry a function to call: a func,
// interface or channel, directly or inside a pointer, slice, array, map or
// module struct. Std named types count only by their own kind.
func holdsCode(t types.Type, depth int) bool {
	if depth == 0 {
		return true
	}
	if named, ok := types.Unalias(t).(*types.Named); ok && named.Obj().Pkg() != nil && !strings.Contains(named.Obj().Pkg().Path(), ".") {
		switch named.Underlying().(type) {
		case *types.Signature, *types.Interface, *types.Chan:
			return true
		}
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Signature, *types.Interface, *types.Chan:
		return true
	case *types.Pointer:
		return holdsCode(u.Elem(), depth-1)
	case *types.Slice:
		return holdsCode(u.Elem(), depth-1)
	case *types.Array:
		return holdsCode(u.Elem(), depth-1)
	case *types.Map:
		return holdsCode(u.Key(), depth-1) || holdsCode(u.Elem(), depth-1)
	case *types.Struct:
		for f := range u.Fields() {
			if holdsCode(f.Type(), depth-1) {
				return true
			}
		}
	}
	return false
}
