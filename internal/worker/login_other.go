//go:build !darwin

package worker

import "errors"

func LegacyLoginItemCount() (int64, error) {
	return 0, errors.New("legacy login census requires macOS CoreServices")
}
