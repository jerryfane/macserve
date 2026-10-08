package hostguard

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

type toolchainInfo struct {
	mode     os.FileMode
	uid, gid uint32
}

func (i toolchainInfo) Name() string       { return "toolchain" }
func (i toolchainInfo) Size() int64        { return 0 }
func (i toolchainInfo) Mode() os.FileMode  { return i.mode }
func (i toolchainInfo) ModTime() time.Time { return time.Time{} }
func (i toolchainInfo) IsDir() bool        { return i.mode.IsDir() }
func (i toolchainInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid, Gid: i.gid} }

func TestToolchainAdministratorManagedPaths(t *testing.T) {
	const developer = "/Applications/Xcode.app/Contents/Developer"
	const executable = developer + "/usr/bin/xcresulttool"
	for _, tc := range []struct {
		name        string
		path        string
		directory   bool
		changedPath string
		mode        os.FileMode
		uid, gid    uint32
		groups      map[string]bool
		wantError   bool
	}{
		{name: "normal Applications", path: developer, directory: true},
		{name: "normal executable", path: executable},
		{name: "world writable ancestor", path: developer, directory: true, changedPath: "/Applications", mode: os.ModeDir | 0777, gid: 80, wantError: true},
		{name: "job group writable ancestor", path: developer, directory: true, changedPath: "/Applications", mode: os.ModeDir | 0775, gid: 502, wantError: true},
		{name: "unrelated group writable ancestor", path: developer, directory: true, changedPath: "/Applications", mode: os.ModeDir | 0775, gid: 20, wantError: true},
		{name: "job owned ancestor", path: developer, directory: true, changedPath: "/Applications/Xcode.app", mode: os.ModeDir | 0755, uid: 502, gid: 80, wantError: true},
		{name: "symlink ancestor", path: developer, directory: true, changedPath: "/Applications/Xcode.app", mode: os.ModeSymlink | 0777, gid: 80, wantError: true},
		{name: "symlink executable", path: executable, changedPath: executable, mode: os.ModeSymlink | 0777, gid: 80, wantError: true},
		{name: "world writable executable", path: executable, changedPath: executable, mode: 0777, gid: 80, wantError: true},
		{name: "admin group writable executable", path: executable, changedPath: executable, mode: 0775, gid: 80, wantError: true},
		{name: "job group writable executable", path: executable, changedPath: executable, mode: 0775, gid: 502, wantError: true},
		{name: "non executable", path: executable, changedPath: executable, mode: 0644, gid: 80, wantError: true},
		{name: "job administrator membership", path: developer, directory: true, groups: map[string]bool{"502": true, "80": true}, wantError: true},
		{name: "relative path", path: "Applications/Xcode.app", directory: true, wantError: true},
		{name: "unclean path", path: "/Applications/../Applications/Xcode.app", directory: true, wantError: true},
		{name: "missing path", path: "/missing", directory: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := map[string]toolchainInfo{
				"/":                                {mode: os.ModeDir | 0755},
				"/Applications":                    {mode: os.ModeDir | 0775, gid: 80},
				"/Applications/Xcode.app":          {mode: os.ModeDir | 0755, gid: 80},
				"/Applications/Xcode.app/Contents": {mode: os.ModeDir | 0755, gid: 80},
				developer:                          {mode: os.ModeDir | 0755, gid: 80},
				developer + "/usr":                 {mode: os.ModeDir | 0755, gid: 80},
				developer + "/usr/bin":             {mode: os.ModeDir | 0755, gid: 80},
				executable:                         {mode: 0755, gid: 80},
			}
			if tc.changedPath != "" {
				metadata[tc.changedPath] = toolchainInfo{mode: tc.mode, uid: tc.uid, gid: tc.gid}
			}
			groups := tc.groups
			if groups == nil {
				groups = map[string]bool{"502": true, "20": true}
			}
			err := protectedToolchainPath(tc.path, tc.directory, 502, "80", groups, func(path string) (os.FileInfo, error) {
				info, ok := metadata[path]
				if !ok {
					return nil, errors.New("missing metadata")
				}
				return info, nil
			})
			if (err != nil) != tc.wantError {
				t.Fatalf("guard error = %v, wantError = %v", err, tc.wantError)
			}
		})
	}
}
