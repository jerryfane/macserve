//go:build linux

package worker

import (
	"os"
	"strconv"
	"strings"
)

// describeProcess reads pid's executable path and, when wantArgs, its
// NUL-joined arguments from /proc (development hosts only).
func describeProcess(pid int, wantArgs bool) (processDescription, error) {
	dir := "/proc/" + strconv.Itoa(pid)
	executable, err := os.Readlink(dir + "/exe")
	if err != nil {
		return processDescription{}, err
	}
	d := processDescription{executable: executable}
	if wantArgs {
		raw, err := os.ReadFile(dir + "/cmdline")
		if err != nil {
			return processDescription{}, err
		}
		d.args = strings.TrimRight(string(raw), "\x00")
	}
	return d, nil
}
