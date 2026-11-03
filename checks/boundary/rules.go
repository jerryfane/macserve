package boundary

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
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
)

// rootPackages run inside the root worker and maintenance processes; C/G
// files there may call only C/G declarations, listed seams, allowlisted std
// packages and (G only) listed g_calls.
var rootPackages = []string{"internal/worker", "internal/maintenance"}

// pureStd are the std packages whose functions C/G files in root packages
// may call.
var pureStd = []string{"bytes", "context", "encoding/json", "errors", "fmt", "io", "maps", "regexp", "slices", "sort", "strconv", "strings", "time"}

// Imports no C/G file may have; module-internal entries are relative to the
// module path. G files may import syscall and golang.org/x/sys, restricted to
// g_calls identifiers.
var (
	bannedImports  = []string{"unsafe", "os/exec", "os/user", "plugin", "runtime/debug", "github.com/ebitengine/purego"}
	syscallImports = []string{"syscall", "golang.org/x/sys"}
	bannedInternal = []string{"internal/hostguard", "internal/peercred", "internal/pfctl", "internal/deploy", "internal/qualification", "internal/launchctlprint"}
)

// Darwin release target: the rules are checked on exactly the files linked
// into the shipped binary.
var buildEnv = []string{"GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0", "GOFLAGS=-mod=readonly", "GOWORK=off"}

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

// CheckSources applies the C/G source rules to every C/G Go file of the
// module at root, type-checked for the darwin/arm64 release build.
func CheckSources(root string, m *Manifest, classes map[string]string) ([]string, error) {
	// go list reports absolute, resolved directories (macOS: /var ->
	// /private/var), so compare against the same form of root.
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return nil, err
	}
	module, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	pkgs, err := goList(root)
	if err != nil {
		return nil, err
	}
	exports := map[string]string{}
	for _, p := range pkgs {
		if p.Export != "" {
			exports[p.ImportPath] = p.Export
		}
	}
	c := &checker{root: root, module: module, manifest: m, classes: classes, fset: token.NewFileSet()}
	c.imp = importer.ForCompiler(c.fset, "gc", func(importPath string) (io.ReadCloser, error) {
		file, ok := exports[importPath]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", importPath)
		}
		return os.Open(file)
	})
	built := map[string]bool{}
	for _, p := range pkgs {
		if p.Standard || p.Module == nil || p.Module.Path != module {
			continue
		}
		dir, err := c.rel(p.Dir)
		if err != nil {
			return nil, err
		}
		for _, name := range append(slices.Clone(p.GoFiles), p.CgoFiles...) {
			built[path.Join(dir, name)] = true
		}
		if !c.needsTypes(dir, p.GoFiles, p.CgoFiles) {
			continue
		}
		if p.Error != nil {
			return nil, fmt.Errorf("%s: %s", p.ImportPath, p.Error.Err)
		}
		if err := c.checkPackage(dir, p.Dir, p.ImportPath, p.GoFiles); err != nil {
			return nil, err
		}
	}
	for file, class := range classes {
		if (class == ClassC || class == ClassG) && isGoSource(file) && !built[file] {
			c.problem(file, "%s file is not part of the darwin/arm64 build (build tags or cgo); classify it B", class)
		}
	}
	for dir := range m.Seams {
		if !c.seamsChecked[dir] {
			c.problem(dir, "seams listed for a package with no C/G files")
		}
	}
	for dir := range m.GCalls {
		if !c.gCallsChecked[dir] {
			c.problem(dir, "g_calls listed for a package with no G files")
		}
	}
	sort.Strings(c.problems)
	return c.problems, nil
}

func modulePath(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", errors.New("go.mod has no module line")
}

func goTool() string {
	tool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(tool); err == nil {
		return tool
	}
	return "go"
}

func goList(root string) ([]listedPackage, error) {
	cmd := exec.Command(goTool(), "list", "-e", "-export", "-deps", "-json=ImportPath,Dir,Export,Standard,GoFiles,CgoFiles,Module,Error", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), buildEnv...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %v: %s", err, stderr.String())
	}
	var pkgs []listedPackage
	d := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := d.Decode(&p); err == io.EOF {
			return pkgs, nil
		} else if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
}

type checker struct {
	root, module  string
	manifest      *Manifest
	classes       map[string]string
	fset          *token.FileSet
	imp           types.Importer
	problems      []string
	seamsChecked  map[string]bool
	gCallsChecked map[string]bool
}

func (c *checker) problem(file, format string, args ...any) {
	c.problems = append(c.problems, file+": "+fmt.Sprintf(format, args...))
}

func (c *checker) rel(abs string) (string, error) {
	r, err := filepath.Rel(c.root, abs)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the module root", abs)
	}
	return filepath.ToSlash(r), nil
}

// classAt returns the class of the file declaring pos, or "" outside the
// module (std, dependencies, unknown positions).
func (c *checker) classAt(pos token.Pos) string {
	if !pos.IsValid() {
		return ""
	}
	r, err := c.rel(c.fset.Position(pos).Filename)
	if err != nil {
		return ""
	}
	return c.classes[r]
}

func (c *checker) carryAt(pos token.Pos) bool {
	class := c.classAt(pos)
	return class == ClassC || class == ClassG
}

func (c *checker) needsTypes(dir string, files ...[]string) bool {
	for _, list := range files {
		for _, name := range list {
			class := c.classes[path.Join(dir, name)]
			if class == ClassC || class == ClassG {
				return true
			}
		}
	}
	_, seams := c.manifest.Seams[dir]
	_, gcalls := c.manifest.GCalls[dir]
	return seams || gcalls
}

func (c *checker) checkPackage(dir, absDir, importPath string, goFiles []string) error {
	var files []*ast.File
	var names []string
	for _, name := range goFiles {
		f, err := parser.ParseFile(c.fset, filepath.Join(absDir, name), nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files = append(files, f)
		names = append(names, path.Join(dir, name))
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: c.imp, Sizes: types.SizesFor("gc", "arm64")}
	pkg, err := conf.Check(importPath, c.fset, files, info)
	if err != nil {
		return fmt.Errorf("type-check %s: %w", importPath, err)
	}
	if c.seamsChecked == nil {
		c.seamsChecked, c.gCallsChecked = map[string]bool{}, map[string]bool{}
	}
	hasG := false
	for i, f := range files {
		class := c.classes[names[i]]
		if class != ClassC && class != ClassG {
			continue
		}
		hasG = hasG || class == ClassG
		c.seamsChecked[dir] = true
		fc := fileCheck{checker: c, file: names[i], class: class, dir: dir, pkg: pkg, info: info, ast: f}
		fc.run()
	}
	if hasG {
		c.gCallsChecked[dir] = true
	}
	for _, seam := range c.manifest.Seams[dir] {
		if !seamExists(pkg, seam) {
			c.problem(dir, "seam %q does not name a declaration of this package", seam)
		}
	}
	return nil
}

func seamExists(pkg *types.Package, seam string) bool {
	if recv, method, ok := strings.Cut(seam, ")."); ok && strings.HasPrefix(recv, "(*") {
		return hasMethod(pkg, strings.TrimPrefix(recv, "(*"), method, true)
	}
	if recv, method, ok := strings.Cut(seam, "."); ok {
		return hasMethod(pkg, recv, method, false)
	}
	obj := pkg.Scope().Lookup(seam)
	switch obj.(type) {
	case *types.Func, *types.TypeName:
		return true
	}
	return false
}

func hasMethod(pkg *types.Package, typeName, method string, pointer bool) bool {
	tn, ok := pkg.Scope().Lookup(typeName).(*types.TypeName)
	if !ok {
		return false
	}
	named, ok := tn.Type().(*types.Named)
	if !ok {
		return false
	}
	for i := range named.NumMethods() {
		m := named.Method(i)
		if m.Name() == method {
			_, ptr := m.Type().(*types.Signature).Recv().Type().(*types.Pointer)
			return ptr == pointer
		}
	}
	return false
}

type fileCheck struct {
	*checker
	file, class, dir string
	pkg              *types.Package
	info             *types.Info
	ast              *ast.File
}

func (f *fileCheck) run() {
	f.imports()
	f.directives()
	for _, decl := range f.ast.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			f.funcDecl(d)
		case *ast.GenDecl:
			if d.Tok == token.VAR {
				f.packageVars(d)
			}
		}
	}
	f.assignments()
	if slices.Contains(rootPackages, f.dir) {
		f.rootUses()
	}
	if f.class == ClassG {
		f.gCalls()
	}
}

func (f *fileCheck) imports() {
	for _, spec := range f.ast.Imports {
		p := strings.Trim(spec.Path.Value, `"`)
		switch {
		case p == "C":
			f.problem(f.file, "cgo is not allowed")
		case slices.Contains(bannedImports, p):
			f.problem(f.file, "imports %s", p)
		case isSyscallPackage(p) && f.class != ClassG:
			f.problem(f.file, "imports %s", p)
		default:
			for _, internal := range bannedInternal {
				full := f.module + "/" + internal
				if p == full || strings.HasPrefix(p, full+"/") {
					f.problem(f.file, "imports %s", p)
				}
			}
		}
	}
}

func isSyscallPackage(p string) bool {
	for _, s := range syscallImports {
		if p == s || strings.HasPrefix(p, s+"/") {
			return true
		}
	}
	return false
}

func (f *fileCheck) directives() {
	for _, group := range f.ast.Comments {
		for _, comment := range group.List {
			text := comment.Text
			switch {
			case strings.HasPrefix(text, "//go:build "):
			case strings.HasPrefix(text, "//go:"), strings.HasPrefix(text, "//export "), strings.HasPrefix(text, "//line "), strings.HasPrefix(text, "/*line "):
				f.problem(f.file, "compiler directive %q", strings.Fields(text)[0])
			}
		}
	}
}

func (f *fileCheck) funcDecl(d *ast.FuncDecl) {
	if d.Recv == nil {
		if d.Name.Name == "init" {
			f.problem(f.file, "init function")
		}
		return
	}
	fn, ok := f.info.Defs[d.Name].(*types.Func)
	if !ok {
		return
	}
	recv := fn.Type().(*types.Signature).Recv().Type()
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := recv.(*types.Named)
	if !ok || !f.carryAt(named.Obj().Pos()) {
		f.problem(f.file, "method %s declared on %s, which is not declared in a C/G file", d.Name.Name, recv)
	}
}

func (f *fileCheck) packageVars(d *ast.GenDecl) {
	for _, spec := range d.Specs {
		for _, value := range spec.(*ast.ValueSpec).Values {
			if !f.literalInit(value) {
				f.problem(f.file, "package-level var initializer at line %d is not a literal, errors.New or regexp.MustCompile", f.fset.Position(value.Pos()).Line)
			}
		}
	}
}

// literalInit reports whether a package-level initializer runs no code
// beyond constant expressions, composite literals of them, conversions,
// errors.New and regexp.MustCompile.
func (f *fileCheck) literalInit(e ast.Expr) bool {
	if tv, ok := f.info.Types[e]; ok && tv.Value != nil {
		return true
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.ParenExpr:
		return f.literalInit(e.X)
	case *ast.Ident:
		switch f.info.Uses[e].(type) {
		case *types.Const, *types.Nil:
			return true
		}
		return false
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			_, ok := e.X.(*ast.CompositeLit)
			return ok && f.literalInit(e.X)
		}
		return f.literalInit(e.X)
	case *ast.BinaryExpr:
		return f.literalInit(e.X) && f.literalInit(e.Y)
	case *ast.CompositeLit:
		_, isStruct := f.info.Types[e].Type.Underlying().(*types.Struct)
		for _, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if !isStruct && !f.literalInit(kv.Key) {
					return false
				}
				elt = kv.Value
			}
			if !f.literalInit(elt) {
				return false
			}
		}
		return true
	case *ast.CallExpr:
		if tv := f.info.Types[e.Fun]; tv.IsType() {
			return len(e.Args) == 1 && f.literalInit(e.Args[0])
		}
		if fn := f.calledFunc(e.Fun); fn != nil && fn.Pkg() != nil {
			name := fn.Pkg().Path() + "." + fn.Name()
			if (name == "errors.New" || name == "regexp.MustCompile") && len(e.Args) == 1 && f.literalInit(e.Args[0]) {
				return true
			}
		}
	}
	return false
}

func (f *fileCheck) calledFunc(fun ast.Expr) *types.Func {
	switch fun := ast.Unparen(fun).(type) {
	case *ast.Ident:
		fn, _ := f.info.Uses[fun].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		fn, _ := f.info.Uses[fun.Sel].(*types.Func)
		return fn
	}
	return nil
}

// assignments rejects writes to, and addresses of, package-level variables
// that are not declared in a C/G file.
func (f *fileCheck) assignments() {
	check := func(e ast.Expr, what string) {
		v := f.rootVar(e)
		if v != nil && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && !f.carryAt(v.Pos()) {
			f.problem(f.file, "%s package-level variable %s.%s, which is not declared in a C/G file", what, v.Pkg().Name(), v.Name())
		}
	}
	ast.Inspect(f.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok != token.DEFINE {
				for _, lhs := range n.Lhs {
					check(lhs, "assigns")
				}
			}
		case *ast.IncDecStmt:
			check(n.X, "assigns")
		case *ast.RangeStmt:
			if n.Tok == token.ASSIGN {
				for _, e := range []ast.Expr{n.Key, n.Value} {
					if e != nil {
						check(e, "assigns")
					}
				}
			}
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				check(n.X, "takes the address of")
			}
		}
		return true
	})
}

func (f *fileCheck) rootVar(e ast.Expr) *types.Var {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				if _, qualified := f.info.Uses[id].(*types.PkgName); qualified {
					v, _ := f.info.Uses[x.Sel].(*types.Var)
					return v
				}
			}
			e = x.X
		case *ast.Ident:
			v, _ := f.info.Uses[x].(*types.Var)
			return v
		default:
			return nil
		}
	}
}

// rootUses restricts every function and method a root-package C/G file
// refers to, and every call through a function value.
func (f *fileCheck) rootUses() {
	ast.Inspect(f.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			if fn, ok := f.info.Uses[n].(*types.Func); ok && !f.allowedFunc(fn) {
				f.problem(f.file, "line %d uses %s, which is not C/G, a listed seam or allowlisted std", f.fset.Position(n.Pos()).Line, describeFunc(fn))
			}
		case *ast.CallExpr:
			var id *ast.Ident
			switch fun := ast.Unparen(n.Fun).(type) {
			case *ast.Ident:
				id = fun
			case *ast.SelectorExpr:
				id = fun.Sel
			}
			if id == nil {
				return true
			}
			if v, ok := f.info.Uses[id].(*types.Var); ok && !f.carryAt(v.Pos()) {
				f.problem(f.file, "line %d calls function value %s, which is not declared in a C/G file", f.fset.Position(n.Pos()).Line, v.Name())
			}
		}
		return true
	})
}

func (f *fileCheck) allowedFunc(fn *types.Func) bool {
	fn = fn.Origin()
	if fn.Pkg() == nil || slices.Contains(pureStd, fn.Pkg().Path()) || f.carryAt(fn.Pos()) {
		return true
	}
	if f.class == ClassG && isSyscallPackage(fn.Pkg().Path()) && slices.Contains(f.manifest.GCalls[f.dir], fn.Pkg().Name()+"."+fn.Name()) {
		return true
	}
	if fn.Pkg() != f.pkg {
		return false
	}
	seams := f.manifest.Seams[f.dir]
	recv := fn.Type().(*types.Signature).Recv()
	if recv == nil {
		return slices.Contains(seams, fn.Name())
	}
	t := recv.Type()
	ptr := false
	if p, ok := t.(*types.Pointer); ok {
		t, ptr = p.Elem(), true
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	name := named.Obj().Name()
	key := name + "." + fn.Name()
	if ptr {
		key = "(*" + name + ")." + fn.Name()
	}
	return slices.Contains(seams, key) || slices.Contains(seams, name)
}

func describeFunc(fn *types.Func) string {
	if fn.Pkg() == nil {
		return fn.Name()
	}
	return fn.FullName()
}

// gCalls restricts G-file uses of syscall and golang.org/x/sys identifiers to
// the g_calls list of the package.
func (f *fileCheck) gCalls() {
	allowed := f.manifest.GCalls[f.dir]
	for id, obj := range f.info.Uses {
		if id.Pos() < f.ast.FileStart || id.Pos() > f.ast.FileEnd || obj.Pkg() == nil || !isSyscallPackage(obj.Pkg().Path()) || obj.Parent() != obj.Pkg().Scope() {
			continue
		}
		if !slices.Contains(allowed, obj.Pkg().Name()+"."+obj.Name()) {
			f.problem(f.file, "line %d uses %s.%s, which is not listed in g_calls[%q]", f.fset.Position(id.Pos()).Line, obj.Pkg().Name(), obj.Name(), f.dir)
		}
	}
}
