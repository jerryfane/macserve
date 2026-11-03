// Package boundary enforces BOUNDARY.json: the default-deny release
// classification of every tracked file, and the source rules that keep
// carry (C) and gate-tuning (G) code from changing the isolation boundary.
//
// Classes: B (boundary: any change needs full requalification), G (gate
// tuning), C (carry), T (text and tests named for C/G files). A file that no
// pattern matches is an error, so a new file is boundary until classified.
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
)

var classNames = []string{ClassB, ClassG, ClassC, ClassT}

// Manifest is BOUNDARY.json, schema 1.
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

	patterns []pattern
}

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
	if m.Schema != 1 {
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
	return &m, nil
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
// test files are B or T, a T test file is named for a C or G file beside it,
// and T holds no compiled Go source.
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
	sort.Strings(problems)
	return classes, problems
}

func isGoSource(file string) bool {
	return strings.HasSuffix(file, ".go") && !strings.HasSuffix(file, "_test.go")
}
