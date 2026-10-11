//go:build darwin

package worker

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/ebitengine/purego"
)

// LegacyLoginItemCount observes the calling non-root user's SessionLoginItems.
// This deprecated CoreServices API does not send AppleEvents. It is deliberately
// census-only: no removal symbols are bound, and a missing API is never empty.
func LegacyLoginItemCount() (int64, error) {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return 0, errors.New("legacy census requires the actual non-root account")
	}
	library, err := purego.Dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return 0, fmt.Errorf("CoreServices unavailable: %w", err)
	}
	defer purego.Dlclose(library)
	bind := func(name string, target any) error {
		address, err := purego.Dlsym(library, name)
		if err != nil || address == 0 {
			return fmt.Errorf("legacy census symbol unavailable: %s", name)
		}
		purego.RegisterFunc(target, address)
		return nil
	}
	var create func(uintptr, uintptr, uintptr) uintptr
	var snapshot func(uintptr, *uint32) uintptr
	var count func(uintptr) int64
	var release func(uintptr)
	for _, symbol := range []struct {
		name   string
		target any
	}{
		{"LSSharedFileListCreate", &create},
		{"LSSharedFileListCopySnapshot", &snapshot},
		{"CFArrayGetCount", &count},
		{"CFRelease", &release},
	} {
		if err := bind(symbol.name, symbol.target); err != nil {
			return 0, err
		}
	}
	address, err := purego.Dlsym(library, "kLSSharedFileListSessionLoginItems")
	if err != nil || address == 0 {
		return 0, errors.New("session login list type unavailable")
	}
	// Dlsym returns the address of an exported CFStringRef variable. Read the
	// pointer bits through the address variable, then dereference that foreign
	// pointer once; do not convert an integer value to unsafe.Pointer.
	kind := **(**uintptr)(unsafe.Pointer(&address))
	if kind == 0 {
		return 0, errors.New("session login list type is null")
	}
	list := create(0, kind, 0)
	if list == 0 {
		return 0, errors.New("legacy login list creation failed")
	}
	defer release(list)
	var seed uint32
	items := snapshot(list, &seed)
	if items == 0 {
		return 0, errors.New("legacy login snapshot unavailable")
	}
	defer release(items)
	n := count(items)
	if n < 0 || n > 1<<20 {
		return 0, errors.New("legacy login count unsupported")
	}
	return n, nil
}
