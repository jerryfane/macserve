//go:build darwin

package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/sys/unix"
)

// SystemBoot identifies this boot: the sha256 of the raw kern.boottime and
// kern.bootsessionuuid. A new boot changes both.
func SystemBoot() (Boot, error) {
	raw, err := unix.SysctlRaw("kern.boottime")
	if err != nil {
		return Boot{}, err
	}
	session, err := unix.Sysctl("kern.bootsessionuuid")
	if err != nil {
		return Boot{}, err
	}
	if len(session) != 36 {
		return Boot{}, errors.New("unexpected kern.bootsessionuuid")
	}
	digest := sha256.Sum256(raw)
	return Boot{Time: hex.EncodeToString(digest[:]), SessionUUID: session}, nil
}
