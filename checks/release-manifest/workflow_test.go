package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	// stepStart is the first line of a workflow step: a list item whose
	// first key is a step key.
	stepStart = regexp.MustCompile(`^\s+- (name|uses|run|id|if|env|with|shell|working-directory|continue-on-error|timeout-minutes):`)
	workDir   = regexp.MustCompile(`^\s+working-directory:\s*(.*)$`)
	// goModuleCommand is a go command that needs the module root as its
	// working directory (no -C).
	goModuleCommand = regexp.MustCompile("(^|[\\s;&|(`])go\\s+(run|build|test|vet|list|generate|install|mod|tool)\\b")
)

// outsideModuleGoSteps names every step whose working-directory is outside
// the checkout (runner.temp, $RUNNER_TEMP or an absolute path) and that
// runs a module-relative go command: go then finds no go.mod.
func outsideModuleGoSteps(workflow string) []string {
	var bad []string
	var step []string
	flush := func() {
		if len(step) == 0 {
			return
		}
		dir := ""
		for _, line := range step {
			if m := workDir.FindStringSubmatch(line); m != nil {
				dir = strings.TrimSpace(m[1])
			}
		}
		outside := strings.Contains(dir, "runner.temp") || strings.Contains(dir, "RUNNER_TEMP") || strings.HasPrefix(strings.Trim(dir, `"'`), "/")
		if outside {
			for _, line := range step {
				if !strings.HasPrefix(strings.TrimSpace(line), "#") && goModuleCommand.MatchString(line) {
					bad = append(bad, strings.TrimSpace(step[0])+": "+strings.TrimSpace(line))
				}
			}
		}
		step = nil
	}
	for _, line := range strings.Split(workflow, "\n") {
		if stepStart.MatchString(line) {
			flush()
		}
		if step != nil || stepStart.MatchString(line) {
			step = append(step, line)
		}
	}
	flush()
	return bad
}

func TestWorkflowsRunGoInsideModule(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("workflows: %v %v", files, err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range outsideModuleGoSteps(string(data)) {
			t.Errorf("%s: go command in a step whose working-directory is outside the module (build in the checkout, run the binary): %s", filepath.Base(file), bad)
		}
	}
}

func TestOutsideModuleGoStepsDetects(t *testing.T) {
	bad := `
      - name: Verify
        working-directory: ${{ runner.temp }}/dist
        run: |
          go run "$GITHUB_WORKSPACE/checks/release-manifest" verify
      - name: Fine
        run: go run ./checks/release-manifest verify
      - name: Also fine
        working-directory: ${{ runner.temp }}/dist
        run: |
          "$RUNNER_TEMP/release-manifest" verify
          go -C "$GITHUB_WORKSPACE" run ./checks/release-manifest verify
`
	got := outsideModuleGoSteps(bad)
	if len(got) != 1 || !strings.Contains(got[0], "- name: Verify") {
		t.Fatalf("outsideModuleGoSteps = %q", got)
	}
}
