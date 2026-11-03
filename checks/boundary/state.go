package boundary

import (
	"go/ast"
	"go/token"
	"go/types"
)

// Rules that keep C/G code from reaching boundary (B) state.
//
// B code hands C/G code only values and capabilities (functions over std
// types) and writes what C/G returns itself. Therefore a C/G file may not:
//   - declare a function or function literal whose parameters or results can
//     reference B state: a B-declared pointer, slice, map, channel, function
//     or interface type, or a B-declared value type that itself holds a
//     reference, anywhere inside the parameter type; an empty interface,
//     which can carry anything, counts as such;
//   - write through an expression rooted in a B-typed value: assignment,
//     ++/--, address-of, append/copy/delete/clear, channel send, or a
//     pointer-receiver method call or method value, where the target or any
//     selector/index/slice/dereference prefix of it has a B-declared type
//     (after removing pointer, slice, array, map and channel layers);
//   - use a package-level variable declared outside C/G unless its type holds
//     no references (an error variable is allowed);
//   - assert or type-switch to a type that involves a B-declared type.

// declaredB reports whether a named type is declared in a B file of this
// module. Std, dependency and universe types are not B.
func (c *checker) declaredB(named *types.Named) bool {
	return c.classAt(named.Origin().Obj().Pos()) == ClassB
}

// shallowB strips pointer, slice, array, map and channel layers and reports
// whether the element is a B-declared named type.
func (c *checker) shallowB(t types.Type) (*types.Named, bool) {
	for {
		switch u := types.Unalias(t).(type) {
		case *types.Pointer:
			t = u.Elem()
		case *types.Slice:
			t = u.Elem()
		case *types.Array:
			t = u.Elem()
		case *types.Map:
			t = u.Elem()
		case *types.Chan:
			t = u.Elem()
		case *types.Named:
			return u, c.declaredB(u)
		default:
			return nil, false
		}
	}
}

// holdsReference reports whether a value of type t can alias other memory.
func holdsReference(t types.Type, seen map[types.Type]bool) bool {
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.(type) {
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	case *types.Named:
		return holdsReference(u.Underlying(), seen)
	case *types.Array:
		return holdsReference(u.Elem(), seen)
	case *types.Struct:
		for i := range u.NumFields() {
			if holdsReference(u.Field(i).Type(), seen) {
				return true
			}
		}
		return false
	case *types.TypeParam:
		return true
	default: // pointer, slice, map, chan, signature, interface, tuple
		return true
	}
}

// reachesB reports whether a value of type t can reference B state. behind
// is true once a reference layer has been crossed; inMethod is true inside
// the method signatures of a non-B interface, where an empty interface is
// the std's own business (context.Context.Value).
func (c *checker) reachesB(t types.Type, behind, inMethod bool, seen map[types.Type]bool) bool {
	t = types.Unalias(t)
	key := t
	if seen[key] {
		return false
	}
	seen[key] = true
	defer delete(seen, key)
	switch u := t.(type) {
	case *types.Named:
		if c.declaredB(u) {
			return behind || holdsReference(u.Underlying(), map[types.Type]bool{})
		}
		if obj := u.Origin().Obj(); obj.Pkg() == nil || c.classAt(obj.Pos()) == "" {
			// Std and dependency types cannot name module types, except
			// through type arguments and interface methods.
			if args := u.TypeArgs(); args != nil {
				for i := range args.Len() {
					if c.reachesB(args.At(i), true, inMethod, seen) {
						return true
					}
				}
			}
			if iface, ok := u.Underlying().(*types.Interface); ok {
				return c.reachesB(iface, behind, inMethod, seen)
			}
			return false
		}
		return c.reachesB(u.Underlying(), behind, inMethod, seen)
	case *types.Pointer:
		return c.reachesB(u.Elem(), true, inMethod, seen)
	case *types.Slice:
		return c.reachesB(u.Elem(), true, inMethod, seen)
	case *types.Array:
		return c.reachesB(u.Elem(), behind, inMethod, seen)
	case *types.Map:
		return c.reachesB(u.Key(), true, inMethod, seen) || c.reachesB(u.Elem(), true, inMethod, seen)
	case *types.Chan:
		return c.reachesB(u.Elem(), true, inMethod, seen)
	case *types.Struct:
		for i := range u.NumFields() {
			if c.reachesB(u.Field(i).Type(), behind, inMethod, seen) {
				return true
			}
		}
		return false
	case *types.Signature:
		return c.reachesB(u.Params(), true, inMethod, seen) || c.reachesB(u.Results(), true, inMethod, seen)
	case *types.Tuple:
		for i := range u.Len() {
			if c.reachesB(u.At(i).Type(), true, inMethod, seen) {
				return true
			}
		}
		return false
	case *types.Interface:
		if u.NumMethods() == 0 {
			return !inMethod
		}
		for i := range u.NumMethods() {
			if c.reachesB(u.Method(i).Type(), true, true, seen) {
				return true
			}
		}
		return false
	case *types.TypeParam:
		return true
	}
	return false
}

// involvesB reports whether t mentions a B-declared type anywhere.
func (c *checker) involvesB(t types.Type, seen map[types.Type]bool) bool {
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.(type) {
	case *types.Named:
		if c.declaredB(u) {
			return true
		}
		if args := u.TypeArgs(); args != nil {
			for i := range args.Len() {
				if c.involvesB(args.At(i), seen) {
					return true
				}
			}
		}
		if c.classAt(u.Origin().Obj().Pos()) == "" {
			return false
		}
		return c.involvesB(u.Underlying(), seen)
	case *types.Pointer:
		return c.involvesB(u.Elem(), seen)
	case *types.Slice:
		return c.involvesB(u.Elem(), seen)
	case *types.Array:
		return c.involvesB(u.Elem(), seen)
	case *types.Map:
		return c.involvesB(u.Key(), seen) || c.involvesB(u.Elem(), seen)
	case *types.Chan:
		return c.involvesB(u.Elem(), seen)
	case *types.Struct:
		for i := range u.NumFields() {
			if c.involvesB(u.Field(i).Type(), seen) {
				return true
			}
		}
	case *types.Signature:
		return c.involvesB(u.Params(), seen) || c.involvesB(u.Results(), seen)
	case *types.Tuple:
		for i := range u.Len() {
			if c.involvesB(u.At(i).Type(), seen) {
				return true
			}
		}
	case *types.Interface:
		for i := range u.NumMethods() {
			if c.involvesB(u.Method(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func (f *fileCheck) line(n ast.Node) int { return f.fset.Position(n.Pos()).Line }

func (f *fileCheck) typeString(t types.Type) string {
	return types.TypeString(t, types.RelativeTo(f.pkg))
}

// signatures applies the parameter/result rule to every function
// declaration and function literal.
func (f *fileCheck) signatures() {
	check := func(n ast.Node, what string, sig *types.Signature) {
		for _, tuple := range []*types.Tuple{sig.Params(), sig.Results()} {
			for i := range tuple.Len() {
				v := tuple.At(i)
				if f.reachesB(v.Type(), false, false, map[types.Type]bool{}) {
					name := v.Name()
					if name == "" {
						name = "_"
					}
					f.problem(f.file, "line %d: %s %s %s has type %s, which can reference boundary state", f.line(n), what, map[bool]string{true: "parameter", false: "result"}[tuple == sig.Params()], name, f.typeString(v.Type()))
				}
			}
		}
	}
	ast.Inspect(f.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncDecl:
			if fn, ok := f.info.Defs[n.Name].(*types.Func); ok {
				check(n, "func "+n.Name.Name, fn.Type().(*types.Signature))
			}
		case *ast.FuncLit:
			if sig, ok := f.info.Types[n].Type.(*types.Signature); ok {
				check(n, "func literal", sig)
			}
		}
		return true
	})
}

// writes rejects every write whose target is rooted in B state or in a
// package-level variable declared outside C/G.
func (f *fileCheck) writes() {
	ast.Inspect(f.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && n.Tok == token.DEFINE && f.info.Defs[id] != nil {
					continue // a new local
				}
				f.writeTarget(lhs, false, "assigns")
			}
		case *ast.IncDecStmt:
			f.writeTarget(n.X, false, "assigns")
		case *ast.RangeStmt:
			if n.Tok == token.ASSIGN {
				for _, e := range []ast.Expr{n.Key, n.Value} {
					if e != nil {
						f.writeTarget(e, false, "assigns")
					}
				}
			}
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				f.writeTarget(n.X, false, "takes the address of")
			}
		case *ast.SendStmt:
			f.writeTarget(n.Chan, true, "sends on")
		case *ast.CallExpr:
			if id, ok := ast.Unparen(n.Fun).(*ast.Ident); ok && len(n.Args) > 0 {
				if b, ok := f.info.Uses[id].(*types.Builtin); ok {
					switch b.Name() {
					case "append", "copy", "delete", "clear":
						f.writeTarget(n.Args[0], true, b.Name()+" writes")
					}
				}
			}
		case *ast.SelectorExpr:
			// A pointer-receiver method call or method value can write its
			// receiver.
			if sel := f.info.Selections[n]; sel != nil && sel.Kind() == types.MethodVal {
				if _, ptr := sel.Obj().Type().(*types.Signature).Recv().Type().(*types.Pointer); ptr {
					f.writeTarget(n.X, true, "calls pointer method "+n.Sel.Name+" on")
				}
			}
		}
		return true
	})
}

// writeTarget checks one write target. through is set when the operation
// writes the memory the target refers to, not only the target location.
func (f *fileCheck) writeTarget(e ast.Expr, through bool, what string) {
	target := types.ExprString(e)
	if through && f.boundaryPrefix(e, target, what) {
		return
	}
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
			continue
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
					f.packageRoot(x.Sel, what)
					return
				}
			}
			e = x.X
		case *ast.Ident:
			f.packageRoot(x, what)
			return
		default:
			return
		}
		if f.boundaryPrefix(e, target, what) {
			return
		}
	}
}

func (f *fileCheck) boundaryPrefix(e ast.Expr, target, what string) bool {
	tv, ok := f.info.Types[e]
	if !ok || tv.Type == nil {
		return false
	}
	if named, b := f.shallowB(tv.Type); b {
		f.problem(f.file, "line %d %s %s, which is rooted in %s of boundary type %s", f.line(e), what, target, types.ExprString(e), f.typeString(named))
		return true
	}
	return false
}

func (f *fileCheck) packageRoot(id *ast.Ident, what string) {
	v, _ := f.info.Uses[id].(*types.Var)
	if v != nil && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && !f.carryAt(v.Pos()) {
		f.problem(f.file, "%s package-level variable %s.%s, which is not declared in a C/G file", what, v.Pkg().Name(), v.Name())
	}
}

// packageVarUses rejects reads of package-level variables declared outside
// C/G whose type holds references: a copy of such a value aliases the
// owner's memory.
func (f *fileCheck) packageVarUses() {
	errorType := types.Universe.Lookup("error").Type()
	for id, obj := range f.info.Uses {
		v, ok := obj.(*types.Var)
		if !ok || id.Pos() < f.ast.FileStart || id.Pos() > f.ast.FileEnd || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() || f.carryAt(v.Pos()) {
			continue
		}
		if types.Identical(v.Type(), errorType) || !holdsReference(v.Type(), map[types.Type]bool{}) {
			continue
		}
		f.problem(f.file, "line %d uses package-level variable %s.%s of type %s, which is not declared in a C/G file and holds references", f.line(id), v.Pkg().Name(), v.Name(), f.typeString(v.Type()))
	}
}

// typeAssertions rejects assertions and type switches to types that
// involve B-declared types: they would recover boundary values from an
// interface.
func (f *fileCheck) typeAssertions() {
	check := func(e ast.Expr) {
		if e == nil {
			return
		}
		if tv, ok := f.info.Types[e]; ok && tv.Type != nil && f.involvesB(tv.Type, map[types.Type]bool{}) {
			f.problem(f.file, "line %d asserts to %s, which involves a boundary type", f.line(e), f.typeString(tv.Type))
		}
	}
	ast.Inspect(f.ast, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.TypeAssertExpr:
			check(n.Type)
		case *ast.TypeSwitchStmt:
			for _, clause := range n.Body.List {
				for _, e := range clause.(*ast.CaseClause).List {
					check(e)
				}
			}
		}
		return true
	})
}

// moduleCalls restricts C/G files outside the root packages to module
// functions declared in C/G files or listed as seams (root packages get the
// stricter rootUses).
func (f *fileCheck) moduleCalls() {
	for id, obj := range f.info.Uses {
		fn, ok := obj.(*types.Func)
		if !ok || id.Pos() < f.ast.FileStart || id.Pos() > f.ast.FileEnd {
			continue
		}
		fn = fn.Origin()
		if fn.Pkg() == nil || f.classAt(fn.Pos()) != ClassB {
			continue
		}
		if fn.Pkg() == f.pkg && f.allowedFunc(fn) {
			continue
		}
		f.problem(f.file, "line %d uses %s, which is boundary code and not a listed seam", f.line(id), describeFunc(fn))
	}
}
