package controller

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/store"
	"golang.org/x/sys/unix"
)

const maxArtifactPoolBytes int64 = 15 << 30

type retainedExport struct {
	id       string
	bytes    int64
	finished time.Time
}

// trimPool is called with evidenceMu held. It counts each content-addressed byte
// file once regardless of manifest aliases, and never evicts an active job.
func (c *Controller) trimPool(ctx context.Context, reservation, limit int64) error {
	if c.poolKnown && c.poolBytes <= limit-reservation {
		return nil
	}
	c.poolKnown = false
	directory, err := c.root.OpenFile("artifacts", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer directory.Close()
	var total int64
	var terminal []retainedExport
	for {
		names, readErr := directory.Readdirnames(128)
		for _, id := range names {
			if !safeID(id) {
				continue
			}
			fd, err := unix.Openat(int(directory.Fd()), id, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			export := os.NewFile(uintptr(fd), id)
			size, err := exportBytes(export)
			export.Close()
			if err != nil {
				return err
			}
			total += size
			job, err := c.options.Store.Get(ctx, id)
			if errors.Is(err, store.ErrNotFound) {
				terminal = append(terminal, retainedExport{id: id, bytes: size})
			} else if err != nil {
				return err
			} else if job.State.Terminal() && job.FinishedAt != nil {
				terminal = append(terminal, retainedExport{id: id, bytes: size, finished: *job.FinishedAt})
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	c.poolBytes = total
	c.poolKnown = true
	sort.Slice(terminal, func(i, j int) bool {
		if terminal[i].finished.Equal(terminal[j].finished) {
			return terminal[i].id < terminal[j].id
		}
		return terminal[i].finished.Before(terminal[j].finished)
	})
	for _, old := range terminal {
		if total <= limit-reservation {
			return nil
		}
		if err := c.root.RemoveAll("artifacts/" + old.id); err != nil {
			return err
		}
		total -= old.bytes
		c.poolBytes = total
	}
	if total > limit-reservation {
		return evidence.ErrArtifactLimit
	}
	return nil
}

func exportBytes(directory *os.File) (int64, error) {
	var total int64
	for {
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			if !hexDigest(name, 64) {
				continue
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return 0, err
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 {
				return 0, evidence.ErrArtifact
			}
			total += stat.Size
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return 0, readErr
		}
	}
}
