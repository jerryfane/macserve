// Package readonly proves that `macserve setup --plan` cannot change host
// state.
//
// It type-checks the darwin/arm64 release build (CGO disabled) from source
// and walks, as code that runs:
//   - every declaration of the read-only package (every file, so a new file
//     is covered; a file the build excludes is refused);
//   - the listed roots (the command entry points), with the command
//     dispatch switch narrowed to the clause the command word selects;
//   - the init functions and package-level variable initialisers of every
//     module package linked into the binary, which run before main;
//   - every module function, method, method value and method set these
//     reach, across packages.
//
// Within that code:
//   - a std or third-party function, method or variable must belong to a
//     pure std package or be listed in Policy.Uses, with its only caller, a
//     maximum count and optionally its exact arguments;
//   - a method called through an interface (or a type parameter) must be
//     listed, even when the interface is std (io.Writer, net.Conn, ...);
//   - a value may be converted to a non-empty interface other than error
//     only if its dynamic type is a module type (whose methods are walked),
//     a listed safe std type (*bytes.Buffer, ...) or a listed Box; so a
//     dialled connection or a file cannot reach fmt.Fprint or io.Copy;
//   - type assertions to interfaces are refused;
//   - fields of std structs (exec.Cmd.Path, ...) may be set only as listed;
//   - listed declarations are pinned by the sha256 of their source, and
//     listed package variables may be referenced only by listed functions;
//   - calls into other module packages from the read-only package and the
//     roots must be listed seams.
//
// Imports are resolved by path through go/types, so aliases, dot imports
// and method values cannot hide a call. Std and third-party package
// initialisation is trusted: it is pinned by go.mod and go.sum.
package readonly

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/printer"
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
// to reference it ("" for any), the maximum number of references (0 for
// any) and, if set, the exact arguments of every call (types.ExprString of
// each argument; a spread argument ends in "...").
type Use struct {
	Caller string
	Max    int
	Args   []string
}

// Box allows Caller to convert a value of the std type From to the
// interface To ("*os.File" to "io.Writer").
type Box struct {
	Caller, From, To string
}

// Policy is what the read-only package may reach.
type Policy struct {
	// Package is the read-only package; every declaration in it is a root.
	Package string
	// Roots are further root functions outside Package, by types.Func
	// FullName.
	Roots []string
	// Switch maps a root to the command word it is proven for. In that
	// root's body a top-level switch whose cases are all constants runs
	// only the clause the word selects (default when none does), so only
	// that clause is walked.
	Switch map[string]string
	// Imports are the module packages Package may import.
	Imports []string
	// Seams are the module functions outside Package and Roots that
	// read-only code may call. Their own call graphs are checked too.
	Seams []string
	// Dispatch maps a module variable outside Package that holds functions
	// (a command table) to the only functions allowed to read it. Entries
	// reached through it are not followed; each needs its own proof.
	Dispatch map[string][]string
	// PureStd are std packages whose functions, concrete methods and
	// variables may be referenced anywhere.
	PureStd []string
	// Uses lists every other non-module object that may be referenced, by
	// types.Func FullName ("os.Lstat", "(*os/exec.Cmd).Run",
	// "(io.Writer).Write") or "pkgpath.Var".
	Uses map[string]Use
	// SafeBox are std types that may be converted to any interface
	// anywhere (types.TypeString, full package paths).
	SafeBox []string
	// Boxes are the other std conversions to non-empty interfaces.
	Boxes []Box
	// Fields maps a std struct field ("os/exec.Cmd.Env") to the only
	// function allowed to set it.
	Fields map[string]string
	// Pinned maps a declaration of Package ("pkgpath.Name" or
	// "(*pkgpath.T).m") to the sha256 of its printed source.
	Pinned map[string]string
	// Refs maps a package variable of Package to the only functions that
	// may reference it.
	Refs map[string][]string
}

type listedPackage struct {
	ImportPath     string
	Dir            string
	Export         string
	Standard       bool
	GoFiles        []string
	CgoFiles       []string
	IgnoredGoFiles []string
	Module         *struct{ Path string }
	Error          *struct{ Err string }
}

// Build is a listed darwin/arm64 build of a module.
type Build struct {
	root, module string
	pkgs         map[string]listedPackage
	fset         *token.FileSet
	imp          types.Importer
	cache        map[string]*source
}

var buildEnv = []string{"GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0", "GOFLAGS=-mod=readonly", "GOWORK=off"}

// buildContext decides which files the release build compiles.
var buildContext = func() build.Context {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled, ctx.Compiler = "darwin", "arm64", false, "gc"
	ctx.BuildTags = nil
	return ctx
}()

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
	args := append([]string{"list", "-e", "-export", "-deps", "-json=ImportPath,Dir,Export,Standard,GoFiles,CgoFiles,IgnoredGoFiles,Module,Error"}, patterns...)
	cmd := exec.Command(tool, args...)
	cmd.Dir = root
	cmd.Env = slices.Concat(os.Environ(), buildEnv, []string{"PWD=" + root})
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %v: %s", err, stderr.String())
	}
	b := &Build{root: root, pkgs: map[string]listedPackage{}, fset: token.NewFileSet(), cache: map[string]*source{}}
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
	b.imp = importer.ForCompiler(b.fset, "gc", func(path string) (io.ReadCloser, error) {
		p, ok := b.pkgs[path]
		if !ok || p.Export == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(p.Export)
	})
	return b, nil
}

type source struct {
	// problems found while loading; repeated on every cache hit.
	problems []string
	pkg      *types.Package
	info     *types.Info
	files    []*ast.File
	decls    map[string]*ast.FuncDecl
}

type checker struct {
	b        *Build
	policy   Policy
	overlay  map[string][]byte
	sources  map[string]*source
	visited  map[string]bool
	queue    []string
	counts   map[string]int
	problems []string
}

// Report is the result of Check: the policy violations and every module
// function the walk reached, both sorted, and the reference count of each
// Policy.Uses entry.
type Report struct {
	Problems []string
	Reached  []string
	Uses     map[string]int
}

// Check applies policy to the build. overlay maps absolute file paths to
// replacement contents (nil removes the file; a new path in a package
// directory adds a file); it lets tests check mutated sources.
func (b *Build) Check(policy Policy, overlay map[string][]byte) (Report, error) {
	c := &checker{b: b, policy: policy, overlay: overlay, sources: map[string]*source{}, visited: map[string]bool{}, counts: map[string]int{}}
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
	// Package initialisation of every other module package in the binary.
	for _, path := range slices.Sorted(maps.Keys(b.pkgs)) {
		p := b.pkgs[path]
		if path == policy.Package || p.Standard || p.Module == nil || p.Module.Path != b.module {
			continue
		}
		src, err := c.load(path)
		if err != nil {
			return Report{}, err
		}
		for _, f := range src.files {
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.FuncDecl:
					if d.Recv == nil && d.Name.Name == "init" {
						c.walk(d, src, path+".init")
					}
				case *ast.GenDecl:
					if d.Tok == token.VAR {
						for _, spec := range d.Specs {
							for _, v := range spec.(*ast.ValueSpec).Values {
								c.walkInitializer(v, src, path+".<init>")
							}
						}
					}
				}
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
	c.checkPins(root)
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
	if word, ok := c.policy.Switch[key]; ok {
		c.walkDispatch(decl, src, key, word)
		return nil
	}
	c.walk(decl, src, key)
	return nil
}

// load type-checks one module package from source (with overlay). Without
// an overlay for its directory the result is cached in the Build.
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
	overlaid := false
	for file := range c.overlay {
		if filepath.Dir(file) == p.Dir {
			overlaid = true
		}
	}
	if s, ok := c.b.cache[path]; ok && !overlaid {
		c.sources[path] = s
		c.problems = append(c.problems, s.problems...)
		return s, nil
	}
	var problems []string
	if len(p.CgoFiles) > 0 {
		problems = append(problems, path+": cgo files")
	}
	// Candidates: the listed files, the files the build ignores and new
	// overlay files; the darwin/arm64 build context decides.
	names := map[string]bool{}
	for _, n := range slices.Concat(p.GoFiles, p.IgnoredGoFiles) {
		names[filepath.Join(p.Dir, n)] = true
	}
	for file := range c.overlay {
		if filepath.Dir(file) == p.Dir && strings.HasSuffix(file, ".go") {
			names[file] = true
		}
	}
	ctx := buildContext
	ctx.OpenFile = func(name string) (io.ReadCloser, error) {
		if data, ok := c.overlay[name]; ok {
			if data == nil {
				return nil, os.ErrNotExist
			}
			return io.NopCloser(bytes.NewReader(data)), nil
		}
		return os.Open(name)
	}
	var files []*ast.File
	for _, name := range slices.Sorted(maps.Keys(names)) {
		if data, ok := c.overlay[name]; ok && data == nil {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		match, err := ctx.MatchFile(p.Dir, filepath.Base(name))
		if err != nil {
			return nil, err
		}
		if !match {
			if path == c.policy.Package {
				problems = append(problems, name+": file excluded from the darwin/arm64 release build; the read-only package must not have build-constrained files")
			}
			continue
		}
		var src any
		if data, ok := c.overlay[name]; ok {
			src = data
		}
		f, err := parser.ParseFile(c.b.fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Instances: map[*ast.Ident]types.Instance{}}
	conf := types.Config{Importer: c.b.imp, Sizes: types.SizesFor("gc", "arm64")}
	pkg, err := conf.Check(path, c.b.fset, files, info)
	if err != nil {
		return nil, fmt.Errorf("type-check %s: %w", path, err)
	}
	c.problems = append(c.problems, problems...)
	s := &source{problems: problems, pkg: pkg, info: info, files: files, decls: map[string]*ast.FuncDecl{}}
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
	if !overlaid {
		c.b.cache[path] = s
	}
	return s, nil
}

// checkFile applies the import rules to a file of the read-only package.
func (c *checker) checkFile(f *ast.File) {
	name := c.b.fset.Position(f.Pos()).Filename
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

// checkPins compares every pinned declaration of the read-only package.
func (c *checker) checkPins(root *source) {
	found := map[string]ast.Node{}
	for _, f := range root.files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if fn, ok := root.info.Defs[d.Name].(*types.Func); ok {
					cp := *d
					cp.Doc = nil
					found[fn.FullName()] = &cp
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						cp := *vs
						cp.Doc, cp.Comment = nil, nil
						for _, n := range vs.Names {
							found[c.policy.Package+"."+n.Name] = &cp
						}
					}
				}
			}
		}
	}
	for key, want := range c.policy.Pinned {
		node, ok := found[key]
		if !ok {
			c.problem("pinned declaration %s not found", key)
			continue
		}
		var buf bytes.Buffer
		if err := (&printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}).Fprint(&buf, c.b.fset, node); err != nil {
			c.problem("pinned declaration %s: %v", key, err)
			continue
		}
		sum := sha256.Sum256(buf.Bytes())
		got := hex.EncodeToString(sum[:])
		if got != want {
			c.problem("pinned declaration %s changed (sha256 %s); review it and update the policy", key, got)
		}
	}
}

func (c *checker) rootCode(caller string) bool {
	return funcPackage(caller) == c.policy.Package || slices.Contains(c.policy.Roots, caller)
}

// walkDispatch walks a Switch root: every statement, except that in a
// top-level switch with constant cases only the clause word selects runs.
func (c *checker) walkDispatch(decl *ast.FuncDecl, src *source, caller, word string) {
	w := &walker{c: c, src: src, caller: caller}
	w.sigs = append(w.sigs, src.info.Defs[decl.Name].Type().(*types.Signature))
	for _, stmt := range decl.Body.List {
		sw, ok := stmt.(*ast.SwitchStmt)
		if !ok || sw.Init != nil || sw.Tag == nil || !w.constantCases(sw) {
			w.inspect(stmt)
			continue
		}
		w.inspect(sw.Tag)
		var chosen, fallback *ast.CaseClause
		for _, s := range sw.Body.List {
			cc := s.(*ast.CaseClause)
			if cc.List == nil {
				fallback = cc
			}
			for _, e := range cc.List {
				if v := src.info.Types[e].Value; v != nil && v.ExactString() == strconv.Quote(word) && chosen == nil {
					chosen = cc
				}
			}
		}
		if chosen == nil {
			chosen = fallback
		}
		if chosen != nil {
			for _, s := range chosen.Body {
				if br, ok := s.(*ast.BranchStmt); ok && br.Tok == token.FALLTHROUGH {
					c.problem("%s: fallthrough in the dispatch switch", caller)
				}
				w.inspect(s)
			}
		}
	}
}

func (w *walker) constantCases(sw *ast.SwitchStmt) bool {
	for _, s := range sw.Body.List {
		for _, e := range s.(*ast.CaseClause).List {
			if w.src.info.Types[e].Value == nil {
				return false
			}
		}
	}
	return true
}

// walk checks node as code of caller that runs.
func (c *checker) walk(node ast.Node, src *source, caller string) {
	w := &walker{c: c, src: src, caller: caller}
	w.inspect(node)
}

// walkInitializer checks a package-level variable initialiser of another
// module package: it runs at start-up, but function values it only stores
// (the whole value, or an element of a composite literal) do not.
func (c *checker) walkInitializer(v ast.Expr, src *source, caller string) {
	if stored(v, src) {
		return
	}
	if lit, ok := ast.Unparen(v).(*ast.CompositeLit); ok {
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				c.walkInitializer(kv.Key, src, caller)
				e = kv.Value
			}
			c.walkInitializer(e, src, caller)
		}
		return
	}
	w := &walker{c: c, src: src, caller: caller, init: true}
	w.inspect(v)
}

// stored reports a function literal or a reference to a function.
func stored(e ast.Expr, src *source) bool {
	switch e := ast.Unparen(e).(type) {
	case *ast.FuncLit:
		return true
	case *ast.Ident:
		_, ok := src.info.Uses[e].(*types.Func)
		return ok
	case *ast.SelectorExpr:
		_, ok := src.info.Uses[e.Sel].(*types.Func)
		return ok
	}
	return false
}

type walker struct {
	c      *checker
	src    *source
	caller string
	init   bool // a package-level initialiser of another package
	sigs   []*types.Signature
	calls  map[*ast.Ident]*ast.CallExpr
}

func (w *walker) pos(p token.Pos) token.Position { return w.c.b.fset.Position(p) }

func (w *walker) inspect(node ast.Node) {
	if w.calls == nil {
		w.calls = map[*ast.Ident]*ast.CallExpr{}
	}
	var stack []ast.Node
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if _, ok := top.(*ast.FuncDecl); ok {
				w.sigs = w.sigs[:len(w.sigs)-1]
			} else if _, ok := top.(*ast.FuncLit); ok {
				w.sigs = w.sigs[:len(w.sigs)-1]
			}
			return true
		}
		stack = append(stack, n)
		w.node(n)
		return true
	})
}

func (w *walker) node(n ast.Node) {
	info := w.src.info
	switch n := n.(type) {
	case *ast.FuncDecl:
		if obj, ok := info.Defs[n.Name].(*types.Func); ok {
			w.sigs = append(w.sigs, obj.Type().(*types.Signature))
		} else {
			w.sigs = append(w.sigs, nil)
		}
	case *ast.FuncLit:
		sig, _ := info.Types[n].Type.(*types.Signature)
		w.sigs = append(w.sigs, sig)
	case *ast.CallExpr:
		switch fun := ast.Unparen(n.Fun).(type) {
		case *ast.Ident:
			w.calls[fun] = n
		case *ast.SelectorExpr:
			w.calls[fun.Sel] = n
		case *ast.IndexExpr:
			if id := calleeIdent(fun.X); id != nil {
				w.calls[id] = n
			}
		case *ast.IndexListExpr:
			if id := calleeIdent(fun.X); id != nil {
				w.calls[id] = n
			}
		}
		w.call(n)
	case *ast.Ident:
		w.c.use(info.Uses[n], w.caller, n.Pos(), w.calls[n])
	case *ast.TypeAssertExpr:
		if n.Type != nil {
			if t := info.Types[n.Type].Type; t != nil && types.IsInterface(t) {
				w.c.problem("%s: %s asserts to interface %s", w.pos(n.Pos()), w.caller, t)
			}
		}
	case *ast.TypeSwitchStmt:
		for _, s := range n.Body.List {
			for _, e := range s.(*ast.CaseClause).List {
				if t := info.Types[e].Type; t != nil && types.IsInterface(t) {
					w.c.problem("%s: %s switches on interface type %s", w.pos(e.Pos()), w.caller, t)
				}
			}
		}
	case *ast.AssignStmt:
		if n.Tok != token.DEFINE {
			for _, lhs := range n.Lhs {
				w.write(lhs)
			}
		}
		if n.Tok == token.ASSIGN || n.Tok == token.DEFINE {
			var dsts []types.Type
			for _, lhs := range n.Lhs {
				dsts = append(dsts, info.Types[lhs].Type)
			}
			w.assign(n.Rhs, dsts, n.Pos())
		}
	case *ast.IncDecStmt:
		w.write(n.X)
	case *ast.UnaryExpr:
		if n.Op == token.AND {
			w.write(n.X)
		}
	case *ast.ValueSpec:
		if n.Type != nil {
			t := info.Types[n.Type].Type
			var dsts []types.Type
			for range n.Names {
				dsts = append(dsts, t)
			}
			w.assign(n.Values, dsts, n.Pos())
		}
	case *ast.ReturnStmt:
		if len(w.sigs) > 0 && w.sigs[len(w.sigs)-1] != nil && len(n.Results) > 0 {
			res := w.sigs[len(w.sigs)-1].Results()
			var dsts []types.Type
			for v := range res.Variables() {
				dsts = append(dsts, v.Type())
			}
			w.assign(n.Results, dsts, n.Pos())
		}
	case *ast.SendStmt:
		if ch, ok := info.Types[n.Chan].Type.Underlying().(*types.Chan); ok {
			w.convert(n.Value, ch.Elem())
		}
	case *ast.CompositeLit:
		w.composite(n)
	}
	if e, ok := n.(ast.Expr); ok {
		if tv, ok := info.Types[e]; ok && tv.Type != nil {
			w.c.methodsOf(tv.Type, w.caller, e.Pos())
		}
	}
}

// stored reports top-level initialiser code of another package: it builds
// values but runs no statements, so conversions and field settings there
// have no effect until reached code reads the variable (refused for
// variables that hold code).
func (w *walker) stored() bool { return w.init && len(w.sigs) == 0 }

func calleeIdent(e ast.Expr) *ast.Ident {
	switch e := ast.Unparen(e).(type) {
	case *ast.Ident:
		return e
	case *ast.SelectorExpr:
		return e.Sel
	}
	return nil
}

// call checks the conversions of a call's arguments to its parameters,
// and explicit conversions to interfaces.
func (w *walker) call(n *ast.CallExpr) {
	info := w.src.info
	tv := info.Types[n.Fun]
	if tv.IsType() {
		if len(n.Args) == 1 {
			w.convert(n.Args[0], tv.Type)
		}
		return
	}
	sig, ok := tv.Type.(*types.Signature)
	if !ok {
		if t := tv.Type; t != nil {
			sig, ok = t.Underlying().(*types.Signature)
		}
		if !ok {
			return
		}
	}
	params := sig.Params()
	var dsts []types.Type
	for i := range params.Len() {
		dsts = append(dsts, params.At(i).Type())
	}
	if sig.Variadic() && !n.Ellipsis.IsValid() && len(dsts) > 0 {
		elem := dsts[len(dsts)-1].(*types.Slice).Elem()
		dsts = dsts[:len(dsts)-1]
		count := len(n.Args)
		if len(n.Args) == 1 {
			if tuple, ok := info.Types[n.Args[0]].Type.(*types.Tuple); ok {
				count = tuple.Len()
			}
		}
		for len(dsts) < count {
			dsts = append(dsts, elem)
		}
	}
	w.assign(n.Args, dsts, n.Pos())
}

// assign checks values (one per destination, or one tuple) against the
// destination types.
func (w *walker) assign(values []ast.Expr, dsts []types.Type, pos token.Pos) {
	if len(values) == 1 && len(dsts) > 1 {
		if tuple, ok := w.src.info.Types[values[0]].Type.(*types.Tuple); ok {
			for i := range min(tuple.Len(), len(dsts)) {
				w.convertType(tuple.At(i).Type(), dsts[i], pos)
			}
			return
		}
	}
	for i, v := range values {
		if i < len(dsts) {
			w.convert(v, dsts[i])
		}
	}
}

func (w *walker) convert(e ast.Expr, dst types.Type) {
	w.convertType(w.src.info.Types[e].Type, dst, e.Pos())
}

// convertType checks one conversion of a value of type src to dst.
func (w *walker) convertType(src, dst types.Type, pos token.Pos) {
	if w.stored() || src == nil || dst == nil || !types.IsInterface(dst) || types.Identical(src, dst) {
		return
	}
	if b, ok := src.(*types.Basic); ok && (b.Kind() == types.UntypedNil || b.Info()&types.IsUntyped != 0) {
		return
	}
	if _, ok := dst.Underlying().(*types.TypeParam); ok {
		return
	}
	if describes(dst) {
		// any and error receivers only describe values (String, Error,
		// Format); a boxed interface other than error or any could be
		// asserted back by std code, so it is refused.
		if types.IsInterface(src) && !describes(src) {
			w.c.problem("%s: %s converts interface %s to %s", w.pos(pos), w.caller, src, dst)
		}
		return
	}
	if types.IsInterface(src) {
		w.c.problem("%s: %s converts interface %s to %s", w.pos(pos), w.caller, src, dst)
		return
	}
	if w.c.moduleType(src) {
		return
	}
	name := types.TypeString(src, nil)
	if slices.Contains(w.c.policy.SafeBox, name) {
		return
	}
	for _, b := range w.c.policy.Boxes {
		if b.Caller == w.caller && b.From == name && b.To == types.TypeString(dst, nil) {
			return
		}
	}
	w.c.problem("%s: %s converts %s to %s, which is not allowed", w.pos(pos), w.caller, name, types.TypeString(dst, nil))
}

// describes reports an interface whose methods only describe a value:
// any, error, fmt.Stringer.
func describes(t types.Type) bool {
	iface, ok := t.Underlying().(*types.Interface)
	if !ok || !iface.IsMethodSet() {
		return false
	}
	for m := range iface.Methods() {
		if m.Name() != "Error" && m.Name() != "String" {
			return false
		}
	}
	return true
}

func (c *checker) moduleType(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && c.module(named.Obj().Pkg())
}

// write checks an assignment target: setting a field of a std struct is
// allowed only as listed.
func (w *walker) write(lhs ast.Expr) {
	for e := lhs; e != nil; {
		switch x := ast.Unparen(e).(type) {
		case *ast.SelectorExpr:
			if sel := w.src.info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal {
				w.field(sel.Recv(), x.Sel.Name, x.Pos())
			}
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			e = nil
		}
	}
}

func (w *walker) field(recv types.Type, name string, pos token.Pos) {
	if w.stored() {
		return
	}
	if p, ok := recv.Underlying().(*types.Pointer); ok {
		recv = p.Elem()
	}
	named, ok := types.Unalias(recv).(*types.Named)
	if !ok || w.c.module(named.Obj().Pkg()) || named.Obj().Pkg() == nil {
		return
	}
	key := named.Obj().Pkg().Path() + "." + named.Obj().Name() + "." + name
	if caller, ok := w.c.policy.Fields[key]; !ok || caller != w.caller {
		w.c.problem("%s: %s sets %s, which is not allowed", w.pos(pos), w.caller, key)
	}
}

// composite checks element conversions and std struct fields set by a
// composite literal.
func (w *walker) composite(n *ast.CompositeLit) {
	t := w.src.info.Types[n].Type
	if t == nil {
		return
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		named, _ := types.Unalias(t).(*types.Named)
		std := named != nil && named.Obj().Pkg() != nil && !w.c.module(named.Obj().Pkg())
		for i, e := range n.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				fname := kv.Key.(*ast.Ident).Name
				for f := range u.Fields() {
					if f.Name() == fname {
						w.convert(kv.Value, f.Type())
					}
				}
				if std {
					w.field(t, fname, kv.Pos())
				}
				continue
			}
			if std && !w.stored() {
				w.c.problem("%s: %s sets an unkeyed std struct %s", w.pos(e.Pos()), w.caller, t)
			}
			if i < u.NumFields() {
				w.convert(e, u.Field(i).Type())
			}
		}
	case *types.Slice, *types.Array:
		var elem types.Type
		if s, ok := u.(*types.Slice); ok {
			elem = s.Elem()
		} else {
			elem = u.(*types.Array).Elem()
		}
		for _, e := range n.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				e = kv.Value
			}
			w.convert(e, elem)
		}
	case *types.Map:
		for _, e := range n.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				w.convert(kv.Key, u.Key())
				w.convert(kv.Value, u.Elem())
			}
		}
	}
}

// methodsOf enqueues the methods of a module type, including promoted
// ones; a promoted std method is checked like a reference to it.
func (c *checker) methodsOf(t types.Type, caller string, pos token.Pos) {
	if !c.moduleType(t) {
		return
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named := types.Unalias(t).(*types.Named)
	if types.IsInterface(named) {
		return
	}
	for _, mt := range []types.Type{named, types.NewPointer(named)} {
		set := types.NewMethodSet(mt)
		for i := range set.Len() {
			m := set.At(i).Obj().(*types.Func).Origin()
			if c.module(m.Pkg()) {
				c.enqueue(m.FullName())
			} else if m.Pkg() != nil {
				c.use(m, caller, pos, nil)
			}
		}
	}
}

func (c *checker) use(obj types.Object, caller string, pos token.Pos, call *ast.CallExpr) {
	switch obj := obj.(type) {
	case *types.Func:
		obj = obj.Origin()
		key := obj.FullName()
		if obj.Pkg() == nil {
			return // error.Error
		}
		sig := obj.Type().(*types.Signature)
		iface := false
		if recv := sig.Recv(); recv != nil {
			iface = types.IsInterface(recv.Type())
		}
		if c.module(obj.Pkg()) {
			if iface {
				c.problem("%s: %s calls module interface method %s", c.b.fset.Position(pos), caller, key)
				return
			}
			if c.rootCode(caller) && obj.Pkg().Path() != c.policy.Package && !slices.Contains(c.policy.Roots, key) && !slices.Contains(c.policy.Seams, key) {
				c.problem("%s: %s calls %s, which is not a listed seam", c.b.fset.Position(pos), caller, key)
				return
			}
			c.enqueue(key)
			return
		}
		c.external(key, obj.Pkg().Path(), caller, pos, call, iface)
	case *types.Var:
		if obj.IsField() || obj.Pkg() == nil || obj.Parent() != obj.Pkg().Scope() {
			return
		}
		key := obj.Pkg().Path() + "." + obj.Name()
		if c.module(obj.Pkg()) {
			if allowed, ok := c.policy.Refs[key]; ok && !slices.Contains(allowed, caller) {
				c.problem("%s: %s references %s, allowed only in %v", c.b.fset.Position(pos), caller, key, allowed)
			}
			if obj.Pkg().Path() != c.policy.Package && holdsCode(obj.Type(), 3) && !slices.Contains(c.policy.Dispatch[key], caller) {
				c.problem("%s: %s reads %s, a module variable that holds functions or interfaces", c.b.fset.Position(pos), caller, key)
			}
			return
		}
		c.external(key, obj.Pkg().Path(), caller, pos, call, false)
	}
}

func (c *checker) external(key, pkg, caller string, pos token.Pos, call *ast.CallExpr, iface bool) {
	if !iface && slices.Contains(c.policy.PureStd, pkg) && c.b.pkgs[pkg].Standard {
		return
	}
	use, ok := c.policy.Uses[key]
	if !ok {
		c.problem("%s: %s references %s, which is not allowed", c.b.fset.Position(pos), caller, key)
		return
	}
	if use.Caller != "" && use.Caller != caller {
		c.problem("%s: %s references %s, allowed only in %s", c.b.fset.Position(pos), caller, key, use.Caller)
	}
	if use.Args != nil {
		if call == nil {
			c.problem("%s: %s references %s without calling it", c.b.fset.Position(pos), caller, key)
		} else if got := callArgs(call); !slices.Equal(got, use.Args) {
			c.problem("%s: %s calls %s with %q, want %q", c.b.fset.Position(pos), caller, key, got, use.Args)
		}
	}
	c.counts[key]++
}

func callArgs(call *ast.CallExpr) []string {
	var out []string
	for i, a := range call.Args {
		s := types.ExprString(a)
		if i == len(call.Args)-1 && call.Ellipsis.IsValid() {
			s += "..."
		}
		out = append(out, s)
	}
	return out
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
