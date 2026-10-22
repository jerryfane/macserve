//go:build darwin

package worker

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
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

// kernel reads kinfo_proc (start, effective UID, parent), the csops status and
// the PROC_PIDPATHINFO executable path. It does not read KERN_PROCARGS2, whose
// environment the kernel withholds from every caller, root included, for a
// CS_RESTRICT process while SIP is enabled.
func (nativeAgents) kernel(pid int) (agentProcess, error) {
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
	// The raw PROC_PIDPATHINFO call returns 0 on success; the path is the
	// NUL-terminated prefix of the buffer.
	path := make([]byte, 4096)
	if _, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoPIDInfo, uintptr(pid), procPIDPathInfo, 0, uintptr(unsafe.Pointer(&path[0])), uintptr(len(path))); errno != 0 {
		return agentProcess{}, errno
	}
	end := bytes.IndexByte(path, 0)
	if end <= 0 {
		return agentProcess{}, errors.New("process executable unavailable")
	}
	facts.executable = string(path[:end])
	return facts, nil
}

func (a nativeAgents) process(pid int) (agentProcess, error) {
	facts, err := a.kernel(pid)
	if err != nil {
		return agentProcess{}, err
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return agentProcess{}, err
	}
	launch, err := launchIdentity(raw)
	if err != nil {
		return agentProcess{}, err
	}
	facts.launch, facts.program, facts.argv = launch.digest, launch.program, launch.argv
	return facts, nil
}

func (nativeAgents) service(ctx context.Context, target string) (launchctlprint.Snapshot, error) {
	out, _, err := inspectCommand(ctx, nil, "/bin/launchctl", "print", target)
	if err != nil {
		return launchctlprint.Snapshot{}, err
	}
	return launchctlprint.Parse(out)
}

func (nativeAgents) domain(ctx context.Context, target string) (launchctlprint.Domain, error) {
	out, _, err := inspectCommand(ctx, nil, "/bin/launchctl", "print", target)
	if err != nil {
		return launchctlprint.Domain{}, err
	}
	return launchctlprint.ParseDomain(out)
}

func (nativeAgents) restricted(path string) error {
	return sipRestrictedExecutable(path)
}

func (nativeAgents) resolve(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

// plist returns a SIP-restricted launchd plist as XML converted by the
// SIP-protected plutil (read-only, under inspectCommand's output bound and
// deadline). It is Apple's own plist parser: a quarter of
// /System/Library/LaunchAgents is binary on macOS 27.0, and some XML ones
// (com.apple.familycircled) carry unquoted attributes that only
// CoreFoundation accepts. Any failure refuses.
func (nativeAgents) plist(ctx context.Context, path string) ([]byte, error) {
	if err := sipRestrictedExecutable(path); err != nil {
		return nil, err
	}
	out, _, err := inspectCommand(ctx, nil, "/usr/bin/plutil", "-convert", "xml1", "-o", "-", path)
	if err != nil {
		return nil, err
	}
	if len(out) > maxLaunchdPlistBytes {
		return nil, errors.New("launchd plist too large")
	}
	return []byte(out), nil
}
