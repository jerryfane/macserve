package setup

import "time"

// CheckFDA is `sudo macserve doctor --live`'s Full Disk Access check: the
// same transient launchd job owner-actions runs (checkFDA), against the
// installed binary, outside any setup step. It needs root.
func CheckFDA() (bool, string, error) {
	h := &Helper{Root: InstallRoot, Store: SystemStore(), Probe: quietCommand, FDAWait: 30 * time.Second}
	return h.checkFDA()
}
