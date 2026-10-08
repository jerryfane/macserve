//go:build linux

package maintenance

import "errors"

func memoryPressure() (bool, error) {
	return true, errors.New("native memory observation requires macOS")
}
