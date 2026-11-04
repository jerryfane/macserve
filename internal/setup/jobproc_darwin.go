//go:build darwin

package setup

import (
	"bytes"
	"errors"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	procInfoPIDInfo = 2
	procPIDPathInfo = 11
)

// jobProcesses reads the kernel facts the baseline rule uses, as the
// worker reads them (internal/worker identity_darwin.go and
// respawn_darwin.go): every process whose effective UID is jobUID, its
// start time, its PROC_PIDPATHINFO executable and whether that file is
// SIP-restricted, root-owned and not group or other writable.
func jobProcesses(jobUID uint32) ([]JobProcess, error) {
	rows, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	var procs []JobProcess
	for _, row := range rows {
		if row.Eproc.Ucred.Uid != jobUID {
			continue
		}
		p := row.Proc
		jp := JobProcess{PID: int(p.P_pid), Start: strconv.FormatInt(p.P_starttime.Sec, 10) + ":" + strconv.FormatInt(int64(p.P_starttime.Usec), 10), Zombie: p.P_stat == 5}
		if !jp.Zombie {
			jp.Executable = processPath(jp.PID)
			jp.Restricted = sipRestricted(jp.Executable)
		}
		procs = append(procs, jp)
	}
	return procs, nil
}

func processPath(pid int) string {
	path := make([]byte, 4096)
	if _, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoPIDInfo, uintptr(pid), procPIDPathInfo, 0, uintptr(unsafe.Pointer(&path[0])), uintptr(len(path))); errno != 0 {
		return ""
	}
	end := bytes.IndexByte(path, 0)
	if end <= 0 {
		return ""
	}
	return string(path[:end])
}

// sipRestricted is the baseline executable rule: a regular file (never a
// symlink) with SF_RESTRICTED, owned by root, not group or other writable.
func sipRestricted(path string) error {
	if path == "" {
		return errors.New("executable unavailable")
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("not a regular file")
	}
	if st.Flags&unix.SF_RESTRICTED == 0 {
		return errors.New("not SIP-restricted (SF_RESTRICTED unset)")
	}
	if st.Uid != 0 || st.Mode&0o022 != 0 {
		return errors.New("not root-owned or writable by group/other")
	}
	return nil
}
