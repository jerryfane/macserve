//go:build darwin

package worker

import "context"

func backgroundCommand(executable string, args []string) (string, []string) {
	wrapped := make([]string, 0, 8+len(args))
	wrapped = append(wrapped, "-b", "-c", "background", "/usr/bin/nice", "-n", "10", executable)
	wrapped = append(wrapped, args...)
	return "/usr/sbin/taskpolicy", wrapped
}

// inspectProcesses lists processes from the kernel in-process, so cleanup
// confirmation never waits on a /bin/ps subprocess under simulator load.
func inspectProcesses(ctx context.Context) ([]processSample, error) {
	return identityProcesses(ctx)
}
