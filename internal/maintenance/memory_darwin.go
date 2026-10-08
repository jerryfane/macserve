//go:build darwin

package maintenance

import (
	"errors"
	"golang.org/x/sys/unix"
)

// XNU kern_memorystatus_notify.c converts this read-only sysctl to dispatch
// NOTE_MEMORYSTATUS_PRESSURE_NORMAL/WARN/CRITICAL (1/2/4).
func memoryPressure() (bool, error) {
	level, err := unix.SysctlUint32("kern.memorystatus_vm_pressure_level")
	if err != nil {
		return true, err
	}
	switch level {
	case 1:
		return false, nil
	case 2, 4:
		return true, nil
	default:
		return true, errors.New("unsupported kernel memory pressure level")
	}
}
