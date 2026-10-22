package qualification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

// v0.1.13 field failure: tool-evidence.json said only "exit 1"; the failing
// xcodegen command and its stderr were in an export the run removed.
func TestToolRunRecordsFailingCommandAndBoundedStderrTail(t *testing.T) {
	log := filepath.Join(t.TempDir(), "stderr")
	stderr := strings.Repeat("x", 2*stderrTailBytes) + "Couldn't find current username\n"
	if err := os.WriteFile(log, []byte(stderr), 0600); err != nil {
		t.Fatal(err)
	}
	result := worker.Result{
		State: model.Failed,
		Commands: []worker.ExecutedCommand{
			{Executable: "/usr/bin/xcodebuild", Args: []string{"-version"}},
			{Executable: "/Library/macserve/tools/xcodegen", Args: []string{"generate", "--spec", "project.yml"}, ExitCode: 1},
		},
		Artifacts: []evidence.Artifact{{ID: "out", Name: "evidence/stdout.log"}, {ID: "err", Name: "evidence/stderr.log"}},
	}
	var asked string
	f := recipeFailure(result, func(id string) (string, error) {
		asked = id
		return fileTail(log, stderrTailBytes)
	})
	if f == nil || f.CommandIndex != 1 || f.Executable != "/Library/macserve/tools/xcodegen" || f.ExitCode != 1 || asked != "err" {
		t.Fatalf("failure %+v from artifact %q", f, asked)
	}
	if len(f.StderrTail) != stderrTailBytes || !strings.HasSuffix(f.StderrTail, "Couldn't find current username\n") {
		t.Fatalf("stderr tail of %d bytes: %q", len(f.StderrTail), f.StderrTail[max(len(f.StderrTail)-40, 0):])
	}
	b, err := json.Marshal(ToolRun{Profile: "p", Result: result, Failure: f})
	if err != nil || !strings.Contains(string(b), `"failure":{"command_index":1,`) {
		t.Fatalf("tool evidence lacks the failure: %s %v", b, err)
	}
	if !strings.Contains(f.String(), "Couldn't find current username") {
		t.Fatalf("refusal message lacks the stderr tail: %s", f)
	}
	if recipeFailure(worker.Result{Commands: result.Commands[:1]}, nil) != nil {
		t.Fatal("failure reported without a failed command")
	}
}
