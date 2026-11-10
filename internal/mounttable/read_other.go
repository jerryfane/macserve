//go:build !darwin

package mounttable

import "errors"

// Read is macOS-only; elsewhere no nested mount is recognized.
func Read() ([]Entry, error) {
	return nil, errors.New("mount table unsupported")
}
