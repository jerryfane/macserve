//go:build !darwin

package setup

import "errors"

// SystemBoot requires macOS.
func SystemBoot() (Boot, error) {
	return Boot{}, errors.New("boot identity requires macOS")
}
