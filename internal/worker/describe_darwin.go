//go:build darwin

package worker

import "golang.org/x/sys/unix"

// describeProcess reads pid's executable path from the kernel and, when
// wantArgs, its launch arguments (KERN_PROCARGS2 argv, NUL-joined). It never
// reads the environment.
func describeProcess(pid int, wantArgs bool) (processDescription, error) {
	facts, err := nativeAgents{}.kernel(pid)
	if err != nil {
		return processDescription{}, err
	}
	d := processDescription{executable: facts.executable}
	if wantArgs {
		raw, err := unix.SysctlRaw("kern.procargs2", pid)
		if err != nil {
			return processDescription{}, err
		}
		launch, err := launchIdentity(raw)
		if err != nil {
			return processDescription{}, err
		}
		d.args = launch.argv
	}
	return d, nil
}
