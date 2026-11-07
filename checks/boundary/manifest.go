// Package boundary enforces BOUNDARY.json: the default-deny release
// classification of every tracked file, and the source rules that keep
// carry (C) and gate-tuning (G) code from changing the isolation boundary.
//
// Classes: B (boundary: any change needs full requalification), G (gate
// tuning), C (carry), T (text and tests named for C/G files), K (controller
// only: linked into no binary but the controller). A file that no pattern
// matches is an error, so a new file is boundary until classified.
//
// K is whole-package. k_packages lists the module-relative directories of
// the K packages. A file belongs to the package of its nearest directory,
// itself or an ancestor, that holds Go files the go command sees (testdata,
// "_" and "." directories hold none), and is K exactly when that package is
// listed: its Go source, its tests and its testdata are all K, and a K
// pattern that splits a package or reaches outside one is an error. K test
// files are K (they are not B or T).
//
// Link rules, on the darwin/arm64 release build: binaries names each built
// artifact, its main package and the classes it may link. A binary without
// K links no K package. A binary with K has a K main package and links,
// besides std, other modules and K packages, only the module packages in
// k_allowed_imports, which lists exactly the non-K module packages that the
// K binaries link. No non-K package imports a K package, tests included.
//
// Pattern syntax: a slash-separated path. A segment that is exactly "**"
// matches zero or more whole segments; "*" inside any other segment matches
// any run of characters except "/". No other wildcard is accepted.
//
// Specificity, most specific first: an exact path, then a pattern without
// "**", then a pattern with "**"; within a tier, more literal (non-"*")
// characters win. A path whose most specific matches name two classes is an
// error.
package boundary

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
)

// Classes in BOUNDARY.json.
const (
	ClassB = "B"
	ClassG = "G"
	ClassC = "C"
	ClassT = "T"
	ClassK = "K"
)

var classNames = []string{ClassB, ClassG, ClassC, ClassT, ClassK}

// Manifest is BOUNDARY.json, schema 2.
type Manifest struct {
	Schema  int                 `json:"schema"`
	Classes map[string][]string `json:"classes"`
	// Seams maps a module-relative package directory to the boundary
	// declarations that C/G files in that package may call: "name" for a
	// function or a type (and all of its methods), "(*T).m" or "T.m" for one
	// method.
	Seams map[string][]string `json:"seams"`
	// GCalls maps a module-relative package directory to the syscall and
	// golang.org/x/sys identifiers ("syscall.Lstat", "unix.Statfs") that its G
	// files may use.
	GCalls map[string][]string `json:"g_calls"`
	// KPackages are the module-relative directories of the K packages.
	KPackages []string `json:"k_packages"`
	// KAllowedImports are the module-relative directories of the non-K
	// module packages that binaries linking K may link.
	KAllowedImports []string `json:"k_allowed_imports"`
	// Binaries maps each built artifact to its main package and the classes
	// its linked module files may have.
	Binaries map[string]Binary `json:"binaries"`

	patterns []pattern
}

// Binary is one built artifact: its module-relative main package directory
// and the classes of the module files it may link.
type Binary struct {
	Package string   `json:"package"`
	Classes []string `json:"classes"`
}

// linksK reports whether the binary may link K packages.
func (b Binary) linksK() bool { return slices.Contains(b.Classes, ClassK) }

type pattern struct {
	text, class string
	tier        int // 2 exact, 1 without "**", 0 with "**"
	literals    int
	segments    []string
}

// LoadManifest reads and validates a BOUNDARY.json file.
func LoadManifest(file string) (*Manifest, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return ParseManifest(data)
}

// ParseManifest decodes BOUNDARY.json strictly: unknown fields, trailing
// data, a missing class, a malformed or duplicated pattern are errors.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("BOUNDARY.json: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("BOUNDARY.json: trailing data")
	}
	if m.Schema != 2 {
		return nil, fmt.Errorf("BOUNDARY.json: unsupported schema %d", m.Schema)
	}
	if len(m.Classes) != len(classNames) {
		return nil, fmt.Errorf("BOUNDARY.json: classes must be exactly %v", classNames)
	}
	seen := map[string]string{}
	for _, class := range classNames {
		list, ok := m.Classes[class]
		if !ok {
			return nil, fmt.Errorf("BOUNDARY.json: class %s missing", class)
		}
		for _, text := range list {
			if other, dup := seen[text]; dup {
				return nil, fmt.Errorf("BOUNDARY.json: pattern %q listed in %s and %s", text, other, class)
			}
			seen[text] = class
			p, err := compilePattern(text, class)
			if err != nil {
				return nil, err
			}
			m.patterns = append(m.patterns, p)
		}
	}
	for _, table := range []map[string][]string{m.Seams, m.GCalls} {
		for dir, names := range table {
			if err := validRelPath(dir); err != nil {
				return nil, fmt.Errorf("BOUNDARY.json: package %q: %w", dir, err)
			}
			for _, name := range names {
				if name == "" || strings.ContainsAny(name, " \t\n") {
					return nil, fmt.Errorf("BOUNDARY.json: package %q: malformed entry %q", dir, name)
				}
			}
		}
	}
	for dir, names := range m.GCalls {
		for _, name := range names {
			pkg, ident, ok := strings.Cut(name, ".")
			if !ok || pkg == "" || ident == "" || strings.Contains(ident, ".") {
				return nil, fmt.Errorf("BOUNDARY.json: g_calls %q: entry %q is not pkg.Name", dir, name)
			}
		}
	}
	if err := m.validateK(); err != nil {
		return nil, fmt.Errorf("BOUNDARY.json: %w", err)
	}
	return &m, nil
}

// validateK checks k_packages, k_allowed_imports and binaries on their own;
// ClassifyFiles and the link rules check them against the tree.
func (m *Manifest) validateK() error {
	k := map[string]bool{}
	for _, dir := range m.KPackages {
		if err := validRelPath(dir); err != nil {
			return fmt.Errorf("k_packages %q: %w", dir, err)
		}
		if k[dir] {
			return fmt.Errorf("k_packages %q listed twice", dir)
		}
		k[dir] = true
	}
	allowed := map[string]bool{}
	for _, dir := range m.KAllowedImports {
		if err := validRelPath(dir); err != nil {
			return fmt.Errorf("k_allowed_imports %q: %w", dir, err)
		}
		if allowed[dir] || k[dir] {
			return fmt.Errorf("k_allowed_imports %q listed twice or a K package", dir)
		}
		allowed[dir] = true
	}
	mains := map[string]string{}
	for name, b := range m.Binaries {
		if name == "" || strings.ContainsAny(name, "/ \t\n") {
			return fmt.Errorf("binaries: malformed name %q", name)
		}
		if err := validRelPath(b.Package); err != nil {
			return fmt.Errorf("binaries %s: package %q: %w", name, b.Package, err)
		}
		if other, dup := mains[b.Package]; dup {
			return fmt.Errorf("binaries %s and %s build the same package %q", other, name, b.Package)
		}
		mains[b.Package] = name
		if len(b.Classes) == 0 {
			return fmt.Errorf("binaries %s: no classes", name)
		}
		for i, class := range b.Classes {
			if !slices.Contains(classNames, class) || class == ClassT || slices.Contains(b.Classes[:i], class) {
				return fmt.Errorf("binaries %s: class %q is unknown, T (never linked) or listed twice", name, class)
			}
		}
		if b.linksK() != k[b.Package] {
			return fmt.Errorf("binaries %s: a binary links K exactly when its main package %q is in k_packages", name, b.Package)
		}
	}
	return nil
}

func validRelPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return errors.New("must be a relative slash path")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errors.New("has an empty, . or .. segment")
		}
	}
	return nil
}

func compilePattern(text, class string) (pattern, error) {
	p := pattern{text: text, class: class, tier: 2}
	if err := validRelPath(text); err != nil {
		return p, fmt.Errorf("BOUNDARY.json: pattern %q: %w", text, err)
	}
	if strings.ContainsAny(text, `?[]{}\`) {
		return p, fmt.Errorf("BOUNDARY.json: pattern %q: only * and ** are supported", text)
	}
	p.segments = strings.Split(text, "/")
	for _, seg := range p.segments {
		switch {
		case seg == "**":
			p.tier = 0
		case strings.Contains(seg, "**"):
			return p, fmt.Errorf("BOUNDARY.json: pattern %q: ** must be a whole segment", text)
		case strings.Contains(seg, "*"):
			p.tier = min(p.tier, 1)
			p.literals += len(seg) - strings.Count(seg, "*")
		default:
			p.literals += len(seg)
		}
	}
	p.literals += len(p.segments) - 1 // separators
	return p, nil
}

func (p pattern) match(file string) bool {
	return matchSegments(p.segments, strings.Split(file, "/"))
}

func matchSegments(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if matchSegments(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	return len(segs) > 0 && matchSegment(pat[0], segs[0]) && matchSegments(pat[1:], segs[1:])
}

func matchSegment(pat, seg string) bool {
	parts := strings.Split(pat, "*")
	if len(parts) == 1 {
		return pat == seg
	}
	if !strings.HasPrefix(seg, parts[0]) {
		return false
	}
	seg = seg[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(seg, part)
		if i < 0 {
			return false
		}
		seg = seg[i+len(part):]
	}
	return strings.HasSuffix(seg, last)
}

// Classify returns the class of one module-relative file path.
func (m *Manifest) Classify(file string) (string, error) {
	var best []pattern
	for _, p := range m.patterns {
		if !p.match(file) {
			continue
		}
		switch {
		case len(best) == 0 || p.tier > best[0].tier || (p.tier == best[0].tier && p.literals > best[0].literals):
			best = []pattern{p}
		case p.tier == best[0].tier && p.literals == best[0].literals:
			best = append(best, p)
		}
	}
	if len(best) == 0 {
		return "", fmt.Errorf("%s: not classified in BOUNDARY.json (default-deny)", file)
	}
	for _, p := range best[1:] {
		if p.class != best[0].class {
			return "", fmt.Errorf("%s: patterns %q (%s) and %q (%s) match at the same specificity", file, best[0].text, best[0].class, p.text, p.class)
		}
	}
	return best[0].class, nil
}

// File is one tracked file: its module-relative path and git mode.
type File struct {
	Path string
	Mode string
}

// ClassifyFiles classifies every tracked file exactly once and applies the
// file-level rules: only regular files, C and G hold only non-test Go source,
// test files are B or T outside K packages, a T test file is named for a C or
// G file beside it, T holds no compiled Go source, and a file is K exactly
// when its package is in k_packages.
func (m *Manifest) ClassifyFiles(files []File) (map[string]string, []string) {
	classes := make(map[string]string, len(files))
	var problems []string
	for _, f := range files {
		switch f.Mode {
		case "100644", "100755":
		case "120000":
			problems = append(problems, f.Path+": symlinks are not allowed")
			continue
		case "160000":
			problems = append(problems, f.Path+": submodules are not allowed")
			continue
		default:
			problems = append(problems, fmt.Sprintf("%s: unsupported git mode %s", f.Path, f.Mode))
			continue
		}
		if _, dup := classes[f.Path]; dup {
			problems = append(problems, f.Path+": listed twice")
			continue
		}
		class, err := m.Classify(f.Path)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		classes[f.Path] = class
	}
	stems := map[string][]string{} // dir -> stems of C/G Go files
	for file, class := range classes {
		if (class == ClassC || class == ClassG) && isGoSource(file) {
			dir, name := path.Split(file)
			stems[dir] = append(stems[dir], strings.TrimSuffix(name, ".go"))
		}
	}
	for file, class := range classes {
		dir, name := path.Split(file)
		switch {
		case strings.HasSuffix(name, "_test.go") && (class == ClassC || class == ClassG):
			problems = append(problems, fmt.Sprintf("%s: test files are B or T, not %s", file, class))
		case strings.HasSuffix(name, "_test.go") && class == ClassT:
			if !slices.ContainsFunc(stems[dir], func(stem string) bool {
				return name == stem+"_test.go" || strings.HasPrefix(name, stem+"_")
			}) {
				problems = append(problems, file+": T test file is not named for a C or G file in its directory")
			}
		case (class == ClassC || class == ClassG) && !isGoSource(file):
			problems = append(problems, fmt.Sprintf("%s: only Go source files can be %s (a B file could embed or read it)", file, class))
		case class == ClassT && isGoSource(file):
			problems = append(problems, file+": Go source is linked into the binary and cannot be T")
		}
	}
	problems = append(problems, m.checkKPackages(files, classes)...)
	sort.Strings(problems)
	return classes, problems
}

// checkKPackages applies the whole-package K rule: a file is K exactly when
// the package that owns it (see goPackageOf) is in k_packages, and every
// k_packages entry is a package.
func (m *Manifest) checkKPackages(files []File, classes map[string]string) []string {
	pkgDirs := map[string]bool{}
	for _, f := range files {
		if dir, name := path.Split(f.Path); strings.HasSuffix(name, ".go") && goVisible(f.Path) {
			pkgDirs[path.Clean(dir)] = true
		}
	}
	var problems []string
	for _, dir := range m.KPackages {
		if !pkgDirs[dir] {
			problems = append(problems, dir+": k_packages entry is not a Go package directory")
		}
	}
	for file, class := range classes {
		owner := goPackageOf(file, pkgDirs)
		inK := owner != "" && slices.Contains(m.KPackages, owner)
		switch {
		case class == ClassK && !inK && owner == "":
			problems = append(problems, file+": K file outside any Go package; K is whole-package (k_packages)")
		case class == ClassK && !inK:
			problems = append(problems, fmt.Sprintf("%s: K file in package %s, which is not in k_packages", file, owner))
		case class != ClassK && inK:
			problems = append(problems, fmt.Sprintf("%s: class %s in K package %s; every file of a K package is K", file, class, owner))
		}
	}
	return problems
}

// goVisible reports whether the go command sees a file: no directory or
// file name segment is testdata or starts with "_" or ".".
func goVisible(file string) bool {
	for _, seg := range strings.Split(file, "/") {
		if seg == "testdata" || strings.HasPrefix(seg, "_") || strings.HasPrefix(seg, ".") {
			return false
		}
	}
	return true
}

// goPackageOf returns the package directory that owns file: the nearest of
// its directory and their ancestors that holds Go files, or "" for none.
func goPackageOf(file string, pkgDirs map[string]bool) string {
	for dir := path.Dir(file); ; dir = path.Dir(dir) {
		if pkgDirs[dir] {
			return dir
		}
		if dir == "." {
			return ""
		}
	}
}

func isGoSource(file string) bool {
	return strings.HasSuffix(file, ".go") && !strings.HasSuffix(file, "_test.go")
}
