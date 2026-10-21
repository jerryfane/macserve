//go:build darwin

package qualification

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// auditinfoAddr is struct auditinfo_addr from <bsm/audit.h> (48 bytes on
// arm64/amd64): auid, mask{success,failure}, termid{port,type,addr[4]},
// asid, flags.
type auditinfoAddr struct {
	AUID  uint32
	Mask  [2]uint32
	Port  uint32
	Type  uint32
	Addr  [4]uint32
	ASID  int32
	Flags uint64
}

const (
	sysAuditon      = 351 // SYS_auditon, <sys/syscall.h>
	sysGetauditAddr = 357 // SYS_getaudit_addr
	aGetpinfoAddr   = 28  // A_GETPINFO_ADDR, <bsm/audit.h>
)

// auditpinfoAddr is struct auditpinfo_addr from <bsm/audit.h> (56 bytes).
type auditpinfoAddr struct {
	PID   int32
	AUID  uint32
	Mask  [2]uint32
	Port  uint32
	Type  uint32
	Addr  [4]uint32
	ASID  int32
	Flags uint64
}

// processAuditOf returns another process's audit user and session through
// auditon(A_GETPINFO_ADDR), which XNU serves from the target's credential
// (bsd/security/audit/audit_syscalls.c). It needs root and can be refused by
// MAC policy or a kernel without audit support; callers treat any error as
// "unavailable", never as a match.
func processAuditOf(pid int) (uint32, int32, error) {
	info := auditpinfoAddr{PID: int32(pid)}
	_, _, errno := syscall.Syscall(sysAuditon, aGetpinfoAddr, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if errno != 0 {
		return 0, 0, errno
	}
	return info.AUID, info.ASID, nil
}

// processAudit returns the audit user ID and audit session ID of this process.
// launchctl asuser joins the target user's audit session; sudo and a root SSH
// login keep the caller's.
func processAudit() (uint32, int32, error) {
	var info auditinfoAddr
	_, _, errno := syscall.Syscall(sysGetauditAddr, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 0)
	if errno != 0 {
		return 0, 0, errno
	}
	return info.AUID, info.ASID, nil
}

// bootSession returns kern.bootsessionuuid, which changes on every boot.
func bootSession() (string, error) {
	value, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil {
		return "", err
	}
	if len(value) != 36 {
		return "", errors.New("unexpected kern.bootsessionuuid")
	}
	return value, nil
}
