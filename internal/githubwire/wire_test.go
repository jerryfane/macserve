package githubwire

import "testing"

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
