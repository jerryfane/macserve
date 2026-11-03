package plan

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const toctouChildEnv = "MACSERVE_TEST_ARGV_TOCTOU_CHILD"

// TestCommandUsesItsOwnArgv: the process command builds does not share
// memory with the caller's slice.
func TestCommandUsesItsOwnArgv(t *testing.T) {
	argv := []string{"/usr/bin/sw_vers", "-productVersion"}
	cmd, _, err := command(context.Background(), argv)
	if err != nil {
		t.Fatal(err)
	}
	argv[0], argv[1] = "/usr/bin/touch", "/tmp/x"
	if cmd.Path != "/usr/bin/sw_vers" || !slices.Equal(cmd.Args, []string{"/usr/bin/sw_vers", "-productVersion"}) {
		t.Fatalf("command follows the caller's slice: %q %q", cmd.Path, cmd.Args)
	}
}

// TestCommandArgvTOCTOU: a goroutine flips the caller's argv between an
// allowed and a refused command while command is called in a loop; every
// process built must be an allowed command. The flipping is a data race by
// design, so it runs in a child test process; this process only reads the
// child's verdict line and stays race-free under -race. Nothing is
// executed.
func TestCommandArgvTOCTOU(t *testing.T) {
	if os.Getenv(toctouChildEnv) == "1" {
		toctouChild()
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestCommandArgvTOCTOU$", "-test.count=1")
	child.Env = append(os.Environ(), toctouChildEnv+"=1", "GORACE=halt_on_error=0 log_path=/dev/null")
	// Under -race the child fails on the race it provokes; only its
	// verdict line counts.
	out, _ := child.CombinedOutput()
	var built, bad int
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, "TOCTOU "); ok {
			fields := strings.Fields(rest)
			if len(fields) == 2 {
				built, _ = strconv.Atoi(fields[0])
				bad, _ = strconv.Atoi(fields[1])
			}
		}
	}
	if built == 0 {
		t.Fatalf("child gave no verdict:\n%s", out)
	}
	if bad != 0 {
		t.Fatalf("%d of %d built commands were not the validated command", bad, built)
	}
}

func toctouChild() {
	allowed := []string{"/usr/bin/sw_vers", "-productVersion"}
	refused := []string{"/usr/bin/touch", "/tmp/macserve-toctou"}
	argv := slices.Clone(allowed)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for flip := false; ; flip = !flip {
			select {
			case <-stop:
				return
			default:
			}
			src := allowed
			if flip {
				src = refused
			}
			argv[0], argv[1] = src[0], src[1]
		}
	}()
	built, bad := 0, 0
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		cmd, _, err := command(context.Background(), argv)
		if err != nil {
			continue
		}
		built++
		if !AllowedCommand(cmd.Args) || cmd.Path != cmd.Args[0] {
			bad++
		}
	}
	close(stop)
	<-done
	os.Stdout.WriteString("TOCTOU " + strconv.Itoa(built) + " " + strconv.Itoa(bad) + "\n")
}
