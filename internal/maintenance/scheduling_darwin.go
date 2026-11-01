//go:build darwin

package maintenance

import "golang.org/x/sys/unix"

// <sys/resource.h>: setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG) puts the
// whole task in the Darwin background band; 0 takes it out. x/sys does not
// export these names.
const (
	prioDarwinProcess = 4
	prioDarwinBG      = 0x1000
)

// leaveBackgroundScheduling takes the observer out of the Darwin background band
// that launchd applies for ProcessType=Background. In that band disk I/O is
// throttled behind foreground work, so while a build writes into the job home
// the census of that home could not finish inside the 8 s probe deadline
// (observed: "mutable census /Users/macservejob: context deadline exceeded",
// versus at most 2 s unthrottled). Every missed probe publishes invalid health
// and the controller then cancels the running job. Nice is left as configured.
func leaveBackgroundScheduling() error {
	return unix.Setpriority(prioDarwinProcess, 0, 0)
}
