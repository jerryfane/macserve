//go:build !darwin

package worker

// processLineage has no kernel unique IDs off darwin; lineage then follows
// the PPID alone.
var processLineage func(pid int, start string) (uint64, uint64, error)
