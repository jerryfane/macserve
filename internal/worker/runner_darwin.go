//go:build darwin

package worker

func backgroundCommand(executable string, args []string) (string, []string) {
	wrapped := make([]string, 0, 8+len(args))
	wrapped = append(wrapped, "-b", "-c", "background", "/usr/bin/nice", "-n", "10", executable)
	wrapped = append(wrapped, args...)
	return "/usr/sbin/taskpolicy", wrapped
}
