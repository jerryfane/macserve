package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// templateRecipe reads the extracted checkout's .macserve.json for a template
// job, derives its recipe and preflights a Flutter job's lockfiles. It runs
// before any toolchain or recipe command.
func templateRecipe(checkout *os.Root, snapshot model.Profile) (model.Profile, *model.RepoRecipe, error) {
	data, err := readRepoConfig(checkout)
	if err != nil {
		return model.Profile{}, nil, err
	}
	config, err := profiles.ParseRepoConfig(data)
	if err != nil {
		return model.Profile{}, nil, err
	}
	derived, err := profiles.Derive(snapshot, config)
	if err != nil {
		return model.Profile{}, nil, err
	}
	if pin := flutterPin(derived); pin != nil {
		if err := flutterPreflight(checkout, *config.Flutter, *pin); err != nil {
			return model.Profile{}, nil, err
		}
	}
	sum := sha256.Sum256(data)
	return derived, &model.RepoRecipe{ConfigSHA256: hex.EncodeToString(sum[:]), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run, Shard: derived.Shard, RequiredTests: derived.RequiredTests}, nil
}

func readRepoConfig(checkout *os.Root) ([]byte, error) {
	name := profiles.RepoConfigFile
	info, err := checkout.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: file is missing at the repository root", profiles.ErrRepoConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", profiles.ErrRepoConfig, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: must be a regular file, not a symlink or directory", profiles.ErrRepoConfig)
	}
	if info.Size() > profiles.MaxRepoConfigBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", profiles.ErrRepoConfig, profiles.MaxRepoConfigBytes)
	}
	f, err := checkout.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", profiles.ErrRepoConfig, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%w: file changed while opening", profiles.ErrRepoConfig)
	}
	data, err := io.ReadAll(io.LimitReader(f, profiles.MaxRepoConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", profiles.ErrRepoConfig, err)
	}
	if len(data) > profiles.MaxRepoConfigBytes {
		return nil, fmt.Errorf("%w: file exceeds %d bytes", profiles.ErrRepoConfig, profiles.MaxRepoConfigBytes)
	}
	return data, nil
}
