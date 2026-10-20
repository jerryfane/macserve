//go:build !darwin

package maintenance

import "errors"

// The maintenance service is macOS-only; elsewhere no nested mount is recognized.
func mountTable() ([]mountEntry, error) {
	return nil, errors.New("mount table unsupported")
}
