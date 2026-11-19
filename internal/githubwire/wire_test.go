package githubwire

import (
	"strings"
	"testing"
)

// Globs match whole repository paths segment by segment: * and ? stay within
// a segment and ** spans zero or more segments; an exclude glob wins.
func TestSkipPathsMatch(t *testing.T) {
	paths := SkipPaths{Include: []string{"docs/**", "LICENSE", "**/*.md"}, Exclude: []string{"App/**"}}
	for name, want := range map[string]string{
		"README.md":                      "**/*.md",
		"Tools/ci/README.md":             "**/*.md",
		"docs/a/b/c.png":                 "docs/**",
		"LICENSE":                        "LICENSE",
		"App/Foo.md":                     "",
		"App/Sub/Foo.md":                 "",
		"LICENSE.txt":                    "",
		"docs":                           "docs/**",
		"Docs/a.md":                      "**/*.md",
		"README.markdown":                "",
		"a.md/b.swift":                   "",
		"project.yml":                    "",
		"Vendor/SwiftTerm/README.md":     "**/*.md",
		".github/ISSUE_TEMPLATE/bug.yml": "",
	} {
		glob, ok := paths.Match(name)
		if glob != want || ok != (want != "") {
			t.Errorf("%s: matched %q %v, want %q", name, glob, ok, want)
		}
	}
	for glob, names := range map[string]map[string]bool{
		"docs/*.md":  {"docs/a.md": true, "docs/x/a.md": false},
		"**":         {"a": true, "a/b/c": true},
		"a/**/b":     {"a/b": true, "a/x/y/b": true, "a/x/c": false},
		"d?cs/[a-c]": {"docs/b": true, "docs/d": false},
	} {
		for name, want := range names {
			if MatchPath(glob, name) != want {
				t.Errorf("MatchPath(%q, %q) != %v", glob, name, want)
			}
		}
	}
}

// A matrix entry's timeout_seconds is positive when set, and its skip_paths
// have the bounds of matrix_skip_paths; both are optional.
func TestCheckMatrixEntryTimeoutAndSkipPaths(t *testing.T) {
	policy := tieredPolicy()
	policy.Matrix[1].TimeoutSeconds = 1800
	policy.Matrix[1].SkipPaths = &SkipPaths{Include: []string{"App/Chat/**"}, Exclude: []string{"App/Chat/Shared/**"}}
	if err := policy.CheckMatrix(); err != nil {
		t.Fatalf("valid entry timeout and skip_paths refused: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*MatrixEntry)
		want   string
	}{
		"negative timeout":       {func(e *MatrixEntry) { e.TimeoutSeconds = -1 }, "mac-evidence/full/ipad timeout_seconds -1"},
		"no include glob":        {func(e *MatrixEntry) { e.SkipPaths = &SkipPaths{Exclude: []string{"docs/**"}} }, "matrix entry mac-evidence/full/ipad skip_paths has 1 to 32 include"},
		"invalid glob":           {func(e *MatrixEntry) { e.SkipPaths = &SkipPaths{Include: []string{"../docs"}} }, `skip_paths glob "../docs" is invalid`},
		"repeated exclude glob":  {func(e *MatrixEntry) { e.SkipPaths = &SkipPaths{Include: []string{"a"}, Exclude: []string{"b", "b"}} }, `skip_paths glob "b" is invalid or repeated`},
		"too many include globs": {func(e *MatrixEntry) { e.SkipPaths = &SkipPaths{Include: strings.Split(strings.Repeat("a,", MaxSkipPaths)+"b", ",")} }, "skip_paths has 1 to 32"},
	} {
		policy := tieredPolicy()
		tc.mutate(&policy.Matrix[1])
		if err := policy.CheckMatrix(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: accepted or wrong error %v, want %q", name, err, tc.want)
		}
	}
}
