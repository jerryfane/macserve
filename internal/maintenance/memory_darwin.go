//go:build darwin

package maintenance

import "golang.org/x/sys/unix"

// XNU kern_memorystatus_notify.c converts this read-only sysctl to dispatch
// NOTE_MEMORYSTATUS_PRESSURE_NORMAL/WARN/CRITICAL (1/2/4).
var readPressureLevel = func() (uint32, error) {
	return unix.SysctlUint32("kern.memorystatus_vm_pressure_level")
}

// memoryPressure reports CRITICAL kernel memory pressure; a sysctl error fails
// closed.
func memoryPressure() (bool, error) {
	level, err := readPressureLevel()
	if err != nil {
		return true, err
	}
	return pressureFromLevel(level)
}
