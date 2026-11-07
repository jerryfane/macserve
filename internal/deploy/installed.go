package deploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/jerryfane/macserve/internal/hostguard"
)

// InstalledBinariesPath is written by the root installer/dispatcher
// (macserve-admin) when it installs Developer ID signed binaries. The signed
// bytes on disk differ from the release assets, so it maps each installed
// digest back to the release digest it was signed from.
const InstalledBinariesPath = Prefix + "/config/installed-binaries.json"

const installedBinariesSchema = "macserve-installed-binaries/1"

// InstalledBinary is one binary's entry in installed-binaries.json.
type InstalledBinary struct {
	ReleaseSHA256         string `json:"release_sha256"`
	InstalledSHA256       string `json:"installed_sha256"`
	Identifier            string `json:"identifier"`
	DesignatedRequirement string `json:"designated_requirement"`
}

// InstalledBinaries is installed-binaries.json, keyed by binary name
// ("macserve", "macserve-controller").
type InstalledBinaries struct {
	Schema   string                     `json:"schema"`
	Binaries map[string]InstalledBinary `json:"binaries"`
}

// ParseInstalledBinaries decodes installed-binaries.json strictly.
func ParseInstalledBinaries(data []byte) (*InstalledBinaries, error) {
	var b InstalledBinaries
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		return nil, fmt.Errorf("installed-binaries.json: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("installed-binaries.json: trailing data")
	}
	if b.Schema != installedBinariesSchema || len(b.Binaries) == 0 {
		return nil, errors.New("installed-binaries.json: unsupported schema")
	}
	for name, e := range b.Binaries {
		if name != "macserve" && name != "macserve-controller" || !validDigest(e.ReleaseSHA256) || !validDigest(e.InstalledSHA256) {
			return nil, fmt.Errorf("installed-binaries.json: invalid entry %q", name)
		}
	}
	return &b, nil
}

// LoadInstalledBinaries reads the protected installed-binaries.json. An
// absent file returns nil, nil: binaries are installed unsigned, so the
// installed and release digests are equal.
func LoadInstalledBinaries() (*InstalledBinaries, error) {
	if _, err := os.Lstat(InstalledBinariesPath); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err := hostguard.CheckProtectedPath(InstalledBinariesPath, false); err != nil {
		return nil, err
	}
	data, err := readRegular(InstalledBinariesPath, 1<<16)
	if err != nil {
		return nil, err
	}
	return ParseInstalledBinaries(data)
}

// ReleaseDigest maps the on-disk digest of binary name to its release
// digest. With no file (b == nil) they are the same. With a file, the
// on-disk digest must be the recorded installed_sha256.
func (b *InstalledBinaries) ReleaseDigest(name, onDisk string) (string, error) {
	if b == nil {
		return onDisk, nil
	}
	e, ok := b.Binaries[name]
	if !ok {
		return "", fmt.Errorf("installed-binaries.json has no %s entry", name)
	}
	if e.InstalledSHA256 != onDisk {
		return "", fmt.Errorf("installed %s (SHA-256 %s) is not the one installed-binaries.json records (%s)", name, onDisk, e.InstalledSHA256)
	}
	return e.ReleaseSHA256, nil
}
