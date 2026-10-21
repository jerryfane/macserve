//go:build !darwin

package worker

import "errors"

func sipRestrictedExecutable(string) error {
	return errors.New("SIP-restricted executable check requires macOS")
}
