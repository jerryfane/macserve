//go:build darwin

package worker

import (
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// PROC_PIDUNIQIDENTIFIERINFO: struct proc_uniqidentifierinfo (56 bytes):
// p_uuid[16], p_uniqueid, p_puniqueid, p_idversion, p_orig_ppidversion,
// p_reserve2, p_orig_ppid, p_reserve4.
const procPIDUniqIdentifierInfo = 17

// processLineage reads pid's kernel unique ID and its parent's unique ID at
// fork (p_puniqueid), which, unlike the PPID, survives reparenting to
// launchd. Unique IDs are never reused within a boot. The instance is
// confirmed by its start time after the read, so a reused PID never answers
// for start.
func processLineage(pid int, start string) (uint64, uint64, error) {
	var info [56]byte
	if _, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoPIDInfo, uintptr(pid), procPIDUniqIdentifierInfo, 0, uintptr(unsafe.Pointer(&info[0])), uintptr(len(info))); errno != 0 {
		return 0, 0, errno
	}
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(k.Proc.P_pid) != pid || startToken(&k.Proc) != start {
		return 0, 0, errors.Join(err, errors.New("process changed during lineage read"))
	}
	unique, parent := binary.LittleEndian.Uint64(info[16:24]), binary.LittleEndian.Uint64(info[24:32])
	if unique == 0 {
		return 0, 0, errors.New("process unique ID unavailable")
	}
	return unique, parent, nil
}
