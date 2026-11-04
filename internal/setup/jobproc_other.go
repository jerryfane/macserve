//go:build !darwin

package setup

import "errors"

// jobProcesses needs the macOS kernel process facts.
func jobProcesses(uint32) ([]JobProcess, error) {
	return nil, errors.New("the build account's processes are read on macOS only")
}
