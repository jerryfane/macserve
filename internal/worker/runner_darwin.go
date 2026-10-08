//go:build darwin

package worker

import "syscall"

func backgroundCommand(executable string, args []string) (string, []string) {
	wrapped := make([]string, 0, 8+len(args))
	wrapped = append(wrapped, "-b", "-c", "background", "/usr/bin/nice", "-n", "10", executable)
	wrapped = append(wrapped, args...)
	return "/usr/sbin/taskpolicy", wrapped
}

func peakRSSKiB(usage syscall.Rusage) int64 {
	kib := usage.Maxrss / 1024
	if usage.Maxrss%1024 != 0 {
		kib++
	}
	return kib
}
