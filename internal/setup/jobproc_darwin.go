//go:build darwin

package setup

import (
	"bytes"
	"errors"
	"strconv"

	"golang.org/x/sys/unix"
)

// jobProcesses reads the kernel facts the baseline proposal checks: every
// process whose effective UID is jobUID, its start time, its executable
// and whether that file is SIP-restricted, root-owned and not group or
// other writable.
//
// The executable is the exec path the kernel records in KERN_PROCARGS2,
// read through x/sys's safe sysctl wrapper: setup may not import unsafe
// (checks/readonly), and PROC_PIDPATHINFO needs it. This is a pre-check
// only, so a refused process is reported before any reset. The binding
// check stays worker.CheckBaselinePolicy (PROC_PIDPATHINFO) on the reset
// baseline, which round-begin runs, and which qualify begin, collect and
// approve enforce again.
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

// processPath is the exec path of pid's KERN_PROCARGS2 (argc, then the
// NUL-terminated path), or "" when it is unavailable or not absolute.
func processPath(pid int) string {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(raw) < 4 {
		return ""
	}
	path, _, ok := bytes.Cut(raw[4:], []byte{0})
	if !ok || len(path) == 0 || path[0] != '/' {
		return ""
	}
	return string(path)
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

// systemProcesses lists every process with its effective UID and the
// exec path of KERN_PROCARGS2 ("" when unavailable, or for a zombie).
func systemProcesses() ([]Process, error) {
	rows, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	procs := make([]Process, 0, len(rows))
	for _, row := range rows {
		p := Process{PID: int(row.Proc.P_pid), UID: row.Eproc.Ucred.Uid}
		if row.Proc.P_stat != 5 {
			p.Executable = processPath(p.PID)
		}
		procs = append(procs, p)
	}
	return procs, nil
}
