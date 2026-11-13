package githubpull

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubwire"
)

// herdrupSkipPaths is herdrup's Tools/ci/ci_scope.py docs rule: docs/,
// .github/ISSUE_TEMPLATE/, LICENSE and Markdown anywhere outside the
// directories the app builds from.
func herdrupSkipPaths() *githubwire.SkipPaths {
	return &githubwire.SkipPaths{
		Include: []string{"docs/**", ".github/ISSUE_TEMPLATE/**", "LICENSE", "**/*.md"},
		Exclude: []string{"App/**", "AskPush/**", "HerdrFontTests/**", "HerdrNotificationService/**", "HerdrShareExtension/**", "HerdrUITests/**", "HerdrWidgets/**", "PrivacyManifests/**", "Shared/**", "Sources/**", "Tests/**", "Vendor/**"},
	}
}

func modified(names ...string) []githubapi.ChangedFile {
	files := make([]githubapi.ChangedFile, len(names))
	for i, name := range names {
		files[i] = githubapi.ChangedFile{Filename: name, Status: "modified"}
	}
	return files
}

// matrix_skip_paths skips a head's matrix only when GitHub's comparison
// lists files, all added or modified, all selected: each matrix entry then
// gets a neutral check and no job, while the build still runs. Any doubt runs
// the matrix.
func TestMatrixSkipPaths(t *testing.T) {
	base := headSHA('b')
	many := make([]string, githubapi.MaxCompareFiles)
	for i := range many {
		many[i] = fmt.Sprintf("docs/page-%d.md", i)
	}
	for name, tc := range map[string]struct {
		files  []githubapi.ChangedFile // nil: the comparison fails
		base   string
		skip   bool
		globs  string
		policy func(*githubwire.Policy)
	}{
		"root README": {files: modified("README.md"), skip: true, globs: "**/*.md"},
		"docs, license, issue template and tool docs": {files: append(modified("docs/guide.md", "LICENSE", ".github/ISSUE_TEMPLATE/bug.yml", "Tools/ci/README.md"), githubapi.ChangedFile{Filename: "docs/new.png", Status: "added"}), skip: true, globs: "docs/**, LICENSE, .github/ISSUE_TEMPLATE/**, **/*.md"},
		"Markdown under App":                          {files: modified("App/Foo.md")},
		"docs and code":                               {files: modified("docs/x.md", "App/a.swift")},
		"project.yml":                                 {files: modified("project.yml")},
		"rename within docs":                          {files: []githubapi.ChangedFile{{Filename: "docs/b.md", PreviousFilename: "docs/a.md", Status: "renamed"}}},
		"copy within docs":                            {files: []githubapi.ChangedFile{{Filename: "docs/b.md", PreviousFilename: "docs/a.md", Status: "copied"}}},
		"removed doc":                                 {files: []githubapi.ChangedFile{{Filename: "docs/a.md", Status: "removed"}}},
		"mode change":                                 {files: []githubapi.ChangedFile{{Filename: "docs/a.md", Status: "changed"}}},
		"empty diff":                                  {files: []githubapi.ChangedFile{}},
		"possibly truncated":                          {files: modified(many...)},
		"comparison fails":                            {},
		"no base commit":                              {files: modified("README.md"), base: "-"},
		"no skip paths":                               {files: modified("README.md"), policy: func(p *githubwire.Policy) { p.MatrixSkipPaths = nil }},
	} {
		t.Run(name, func(t *testing.T) {
			policy := matrixPolicy()
			policy.MatrixSkipPaths = herdrupSkipPaths()
			if tc.policy != nil {
				tc.policy(&policy)
			}
			f := newMatrixFixture(t, policy)
			pull := matrixPull(1, headSHA('1'))
			pull.BaseSHA = base
			if tc.base == "-" {
				pull.BaseSHA = ""
			}
			f.pull(matrixRepo, pull, matrixConfig)
			if tc.files != nil {
				f.remote.changed[matrixRepo+"@"+base+"..."+headSHA('1')] = tc.files
			}
			f.poll(t)
			f.poll(t)
			runs, checks := f.runsByCheck(t, headSHA('1')), f.checksOf(headSHA('1'))
			build := "mac-evidence/" + nativeBuild
			if len(runs) != 5 || len(checks) != 5 || runs[build].JobID == "" || checks[build].Status != "queued" {
				t.Fatalf("runs %v checks %v", runs, checks)
			}
			for _, entry := range policy.Matrix {
				name := githubwire.CheckName(entry.Profile, entry.Shard)
				run, check := runs[name], checks[name]
				if !tc.skip {
					if run.JobID == "" || run.Skipped != "" || check.Status != "queued" {
						t.Fatalf("%s should run: run %+v check %+v", name, run, check)
					}
					continue
				}
				want := fmt.Sprintf("all %d changed files match the policy's matrix_skip_paths (%s)", len(tc.files), tc.globs)
				if run.JobID != "" || !strings.Contains(run.Skipped, want) || check.Status != "completed" || check.Conclusion != "neutral" || check.Output.Title != "Not run: docs/version-only change" || check.Output.Summary != run.Skipped {
					t.Fatalf("%s should be skipped (%q): run %+v check %+v", name, want, run, check)
				}
			}
			f.remote.mu.Lock()
			compares := f.remote.compares
			f.remote.mu.Unlock()
			if want := map[bool]int{true: 1, false: 0}[policy.MatrixSkipPaths != nil && pull.BaseSHA != ""]; compares != want {
				t.Fatalf("%d comparisons for two polls of one head, want %d", compares, want)
			}
		})
	}
}

// The decision is per head: a later push that touches code runs the matrix,
// and the docs-only head's skipped runs retire with it.
func TestMatrixSkipPathsReevaluatesEachHead(t *testing.T) {
	policy := matrixPolicy()
	policy.MatrixSkipPaths = herdrupSkipPaths()
	f := newMatrixFixture(t, policy)
	pull := matrixPull(1, headSHA('1'))
	pull.BaseSHA = headSHA('b')
	f.pull(matrixRepo, pull, matrixConfig)
	f.remote.changed[matrixRepo+"@"+headSHA('b')+"..."+headSHA('1')] = modified("README.md")
	f.remote.changed[matrixRepo+"@"+headSHA('b')+"..."+headSHA('2')] = modified("README.md", "App/a.swift")
	f.poll(t)
	ipad := "mac-evidence/org-ios-sim-uitest-v1/ipad"
	if run := f.runsByCheck(t, headSHA('1'))[ipad]; run.JobID != "" || run.Skipped == "" {
		t.Fatalf("docs-only head: %+v", run)
	}
	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.HeadSHA = headSHA('2') })
	f.remote.mu.Lock()
	f.remote.files[matrixRepo+"@"+headSHA('2')] = matrixConfig
	f.remote.mu.Unlock()
	f.poll(t)
	runs := f.runsByCheck(t, headSHA('2'))
	for _, entry := range policy.Matrix {
		if run := runs[githubwire.CheckName(entry.Profile, entry.Shard)]; run.JobID == "" || run.Skipped != "" {
			t.Fatalf("code head %s: %+v", entry.Shard, run)
		}
	}
	if active := f.active(t, matrixRepoID); len(active) != 5 {
		t.Fatalf("active runs %v", active)
	}
}
