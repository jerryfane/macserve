package maintenance

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// accountBytes uses descriptor-relative, no-follow traversal. Symlinks count as
// links, never as their targets; regular files use max(logical, allocated) bytes.
// Hardlinks and nested roots are counted once. Concurrent directory mutation,
// mount crossings, special nodes (except local sockets), and traversal limits
// invalidate the entire census. Local sockets have metadata but no file payload.
func accountBytes(ctx context.Context, roots []string) (int64, error) {
	type inode struct {
		dev uint64
		ino uint64
	}
	seen := map[inode]bool{}
	var total int64
	entries := 0
	var walk func(int, string, uint64, int) error
	walk = func(parent int, name string, device uint64, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > 1000000 || depth > 128 {
			return errors.New("mutable census bound exceeded")
		}
		var st unix.Stat_t
		if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if uint64(st.Dev) != device {
			return errors.New("mutable mount crossing")
		}
		key := inode{uint64(st.Dev), uint64(st.Ino)}
		if seen[key] {
			return nil
		}
		seen[key] = true
		size := st.Size
		if st.Blocks < 0 || st.Blocks > math.MaxInt64/512 || size < 0 {
			return errors.New("invalid mutable size")
		}
		if allocated := st.Blocks * 512; allocated > size {
			size = allocated
		}
		if total > math.MaxInt64-size {
			return errors.New("mutable size overflow")
		}
		total += size
		kind := st.Mode & unix.S_IFMT
		if kind == unix.S_IFREG || kind == unix.S_IFLNK || kind == unix.S_IFSOCK {
			return nil
		}
		if kind != unix.S_IFDIR {
			return errors.New("unsupported mutable special file")
		}
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()
		var opened unix.Stat_t
		if err = unix.Fstat(fd, &opened); err != nil {
			return err
		}
		if opened.Dev != st.Dev || opened.Ino != st.Ino {
			return errors.New("mutable directory replaced")
		}
		for {
			names, err := f.Readdirnames(128)
			if err != nil && err != io.EOF {
				return err
			}
			for _, child := range names {
				if err := walk(fd, child, device, depth+1); err != nil {
					return err
				}
			}
			if err == io.EOF {
				break
			}
		}
		var after unix.Stat_t
		if err = unix.Fstat(fd, &after); err != nil {
			return err
		}
		if after.Mtim != opened.Mtim || after.Ctim != opened.Ctim {
			return errors.New("mutable directory changed during census")
		}
		return nil
	}
	for _, root := range roots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
			return -1, errors.New("invalid mutable root")
		}
		// Open every ancestor without following a link, not just the final component.
		fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err
		}
		parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
		for _, part := range parts[:len(parts)-1] {
			next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			unix.Close(fd)
			if e != nil {
				return -1, e
			}
			fd = next
		}
		var st unix.Stat_t
		err = unix.Fstatat(fd, parts[len(parts)-1], &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			err = errors.New("mutable root is not directory")
		}
		if err == nil {
			err = walk(fd, parts[len(parts)-1], uint64(st.Dev), 0)
		}
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
	}
	return total, ctx.Err()
}
