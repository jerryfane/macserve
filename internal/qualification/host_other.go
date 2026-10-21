//go:build !darwin

package qualification

import "errors"

func processAudit() (uint32, int32, error) {
	return 0, 0, errors.New("audit session requires macOS")
}

func bootSession() (string, error) {
	return "", errors.New("kern.bootsessionuuid requires macOS")
}

func processAuditOf(int) (uint32, int32, error) {
	return 0, 0, errors.New("audit session requires macOS")
}
