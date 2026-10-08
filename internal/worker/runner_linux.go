//go:build linux

package worker

import "syscall"

func backgroundCommand(executable string, args []string) (string, []string) {
	wrapped := make([]string, 0, 3+len(args))
	wrapped = append(wrapped, "-n", "10", executable)
	wrapped = append(wrapped, args...)
	return "/usr/bin/nice", wrapped
}

func peakRSSKiB(usage syscall.Rusage) int64 {
	return usage.Maxrss
}
