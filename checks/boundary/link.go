package boundary

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// checkLinks applies the link rules of binaries, k_packages and
// k_allowed_imports to the darwin/arm64 package graph of `go list -deps
// ./...`: no non-K package imports a K package (test imports included), a K
// main package is a binary that links K, a binary without K links no K
// package, a binary with K links only K packages and k_allowed_imports from
// the module, every linked module file has a class its binary lists, and
// every k_allowed_imports entry is linked by a binary with K.
func checkLinks(module string, m *Manifest, classes map[string]string, pkgs []listedPackage) []string {
	var problems []string
	byPath := make(map[string]*listedPackage, len(pkgs))
	for i := range pkgs {
		byPath[pkgs[i].ImportPath] = &pkgs[i]
	}
	// rel is the module-relative directory of a module package, "" otherwise.
	rel := func(p *listedPackage) string {
		if p.Standard || p.Module == nil || p.Module.Path != module {
			return ""
		}
		if p.ImportPath == module {
			return "."
		}
		return strings.TrimPrefix(p.ImportPath, module+"/")
	}
	short := func(importPath string) string {
		if r, ok := strings.CutPrefix(importPath, module+"/"); ok {
			return r
		}
		return importPath
	}
	kPath := map[string]bool{}
	for _, dir := range m.KPackages {
		kPath[module+"/"+dir] = true
	}
	kMains := map[string]bool{}
	for _, b := range m.Binaries {
		if b.linksK() {
			kMains[b.Package] = true
		}
	}
	for i := range pkgs {
		p := &pkgs[i]
		dir := rel(p)
		if kPath[p.ImportPath] {
			if p.Name == "main" && !kMains[dir] {
				problems = append(problems, dir+": K main package is not a binary that links K in BOUNDARY.json binaries")
			}
			continue
		}
		for _, imp := range slices.Concat(p.Imports, p.TestImports, p.XTestImports) {
			if kPath[imp] {
				problems = append(problems, fmt.Sprintf("%s: imports K package %s; only K packages may import K packages", short(p.ImportPath), short(imp)))
			}
		}
	}
	allowed := map[string]bool{}
	for _, dir := range m.KAllowedImports {
		allowed[dir] = false
	}
	names := make([]string, 0, len(m.Binaries))
	for name := range m.Binaries {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		b := m.Binaries[name]
		main := byPath[module+"/"+b.Package]
		if b.Package == "." {
			main = byPath[module]
		}
		if main == nil || main.Name != "main" {
			problems = append(problems, fmt.Sprintf("binaries %s: %s is not a main package of the darwin/arm64 build", name, b.Package))
			continue
		}
		// Breadth-first over imports; parent records the first importer, so
		// a problem names the shortest import chain from the main package.
		parent := map[string]string{main.ImportPath: ""}
		chain := func(importPath string) string {
			var links []string
			for p := importPath; p != ""; p = parent[p] {
				links = append(links, short(p))
			}
			slices.Reverse(links)
			return strings.Join(links, " -> ")
		}
		for queue := []string{main.ImportPath}; len(queue) > 0; queue = queue[1:] {
			p := byPath[queue[0]]
			if p == nil {
				continue
			}
			for _, imp := range p.Imports {
				if _, seen := parent[imp]; !seen {
					parent[imp] = p.ImportPath
					queue = append(queue, imp)
				}
			}
			dir := rel(p)
			if dir == "" {
				continue
			}
			isK := kPath[p.ImportPath]
			switch {
			case isK && !b.linksK():
				problems = append(problems, fmt.Sprintf("binaries %s: links K package %s (imported via %s)", name, dir, chain(p.ImportPath)))
				continue
			case !isK && b.linksK():
				if _, ok := allowed[dir]; !ok {
					problems = append(problems, fmt.Sprintf("binaries %s: links module package %s, which is neither K nor in k_allowed_imports (imported via %s)", name, dir, chain(p.ImportPath)))
				} else {
					allowed[dir] = true
				}
			}
			for _, file := range slices.Concat(p.GoFiles, p.CgoFiles) {
				file = path.Join(dir, file)
				// Untracked files are outside the release tree.
				if class, ok := classes[file]; ok && !slices.Contains(b.Classes, class) {
					problems = append(problems, fmt.Sprintf("binaries %s: links %s of class %s, not one of %v (imported via %s)", name, file, class, b.Classes, chain(p.ImportPath)))
				}
			}
		}
	}
	for _, dir := range m.KAllowedImports {
		if !allowed[dir] {
			problems = append(problems, fmt.Sprintf("k_allowed_imports %s: not linked by any binary that links K", dir))
		}
	}
	return problems
}
