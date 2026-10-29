package maintenance

import "errors"

// pressureFromLevel maps an XNU kern.memorystatus_vm_pressure_level value
// (NOTE_MEMORYSTATUS_PRESSURE_NORMAL/WARN/CRITICAL = 1/2/4) to the health
// memory_pressure flag that blocks admission. Since v0.1.17 only CRITICAL
// blocks: WARN is routine on a large host running other memory-heavy
// services and still leaves the kernel room to reclaim. Unknown values fail
// closed.
func pressureFromLevel(level uint32) (bool, error) {
	switch level {
	case 1, 2:
		return false, nil
	case 4:
		return true, nil
	default:
		return true, errors.New("unsupported kernel memory pressure level")
	}
}
