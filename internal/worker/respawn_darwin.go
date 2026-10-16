//go:build darwin

package worker

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"unsafe"

	"github.com/jerryfane/macserve/internal/launchctlprint"
	"golang.org/x/sys/unix"
)

const (
	csValid          = 0x00000001
	csPlatformBinary = 0x04000000
	procPIDPathInfo  = 11
	procInfoPIDInfo  = 2
)

// nativeAgents reads kernel facts and launchd's own service records as root.
// It never signals, starts or modifies a service.
type nativeAgents struct{}

func (nativeAgents) process(pid int) (agentProcess, error) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || int(k.Proc.P_pid) != pid {
		return agentProcess{}, errors.Join(err, errors.New("process unavailable"))
	}
	facts := agentProcess{
		start: startToken(&k.Proc),
		uid:   int(k.Eproc.Ucred.Uid),
		ppid:  int(k.Eproc.Ppid),
	}
	// The kernel's code-signing status of the running process, not of a file:
	// a valid platform binary is Apple-signed OS code.
	var flags uint32
	if _, _, errno := unix.Syscall6(unix.SYS_CSOPS, uintptr(pid), 0, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), 0, 0); errno != 0 {
		return agentProcess{}, errno
	}
	facts.platform = flags&csValid != 0 && flags&csPlatformBinary != 0
	path := make([]byte, 4096)
	n, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoPIDInfo, uintptr(pid), procPIDPathInfo, 0, uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)))
	if errno != 0 || n == 0 {
		return agentProcess{}, errors.Join(errno, errors.New("process executable unavailable"))
	}
	end := bytes.IndexByte(path, 0)
	if end < 0 {
		end = int(n)
	}
	facts.executable = string(path[:end])
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return agentProcess{}, err
	}
	if facts.label, facts.launch, err = launchIdentity(raw); err != nil {
		return agentProcess{}, err
	}
	return facts, nil
}

func (nativeAgents) service(ctx context.Context, target string) (launchctlprint.Snapshot, error) {
	out, _, err := inspectCommand(ctx, nil, "/bin/launchctl", "print", target)
	if err != nil {
		return launchctlprint.Snapshot{}, err
	}
	return launchctlprint.Parse(out)
}

// responsible is only a hint naming which audited pid domain to query;
// authority comes from launchctl print of that domain's exact service.
func (nativeAgents) responsible(ctx context.Context, pid int) (int, error) {
	out, _, err := inspectCommand(ctx, nil, "/bin/launchctl", "procinfo", strconv.Itoa(pid))
	if err != nil {
		return 0, err
	}
	return responsiblePID(out)
}

func responsiblePID(out string) (int, error) {
	found := 0
	for line := range strings.Lines(out) {
		value, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "responsible pid = ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(value)
		if err != nil || pid <= 1 || found != 0 {
			return 0, errors.New("ambiguous responsible process")
		}
		found = pid
	}
	if found == 0 {
		return 0, errors.New("responsible process unavailable")
	}
	return found, nil
}
