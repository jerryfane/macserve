package upgrade

import (
	"os"
	"path/filepath"

	"github.com/jerryfane/macserve/internal/doctor"
	"github.com/jerryfane/macserve/internal/setup"
)

// SystemProbe reads the running host through doctor's read-only probe.
func SystemProbe() Probe {
	d := doctor.SystemProbe()
	return Probe{
		Run: d.Run, ReadFile: d.ReadFile, Self: executable, Version: setup.ReleaseVersion,
		Exists: func(path string) (bool, error) {
			info, err := d.Lstat(path)
			return info.Exists, err
		},
	}
}

// executable is the path of the running binary, links resolved.
func executable() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(self)
}
