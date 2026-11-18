package controller

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"golang.org/x/sys/unix"
)

// The products pool holds build-for-testing jobs' test-products.tar bytes,
// content-addressed as products/<sha256>.tar under the controller root, with
// its own budget apart from the evidence pool (maxArtifactPoolBytes), so
// test products never evict test evidence. Bytes unused for maxProductAge
// are evicted; beyond the budget the least recently used go first. The
// store's products ledger records every retained digest and, after an
// eviction, its proof.
const (
	productsDir                = "products"
	maxProductsPoolBytes int64 = 16 << 30
	maxProductAge              = 7 * 24 * time.Hour
)

// productsArtifact reports whether a is job's test products: the
// test-products.tar of a build-for-testing job, stored in the products pool
// rather than the job's export directory.
func productsArtifact(job model.Job, a evidence.Artifact) bool {
	return job.Request.BuildForTesting && a.Name == profiles.TestProductsArtifact
}

func productFile(digest string) string { return digest + ".tar" }

// openProduct opens the pool's bytes of digest without following a symlink,
// as a private regular file.
func (c *Controller) openProduct(digest string) (*os.File, error) {
	parent, err := c.root.OpenFile(productsDir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), productFile(digest), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), productFile(digest))
	if _, err := privateRegular(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// openJobArtifact opens the stored bytes of job's artifact a: test products
// from the products pool, anything else from the job's export directory.
func (c *Controller) openJobArtifact(job model.Job, a evidence.Artifact) (*os.File, error) {
	if productsArtifact(job, a) {
		return c.openProduct(a.SHA256)
	}
	return c.openArtifact(job.ID, a.ID)
}

// productFiles lists the pool's <sha256>.tar files and their sizes. Any
// other name is not a product and is ignored.
func (c *Controller) productFiles() (map[string]int64, error) {
	directory, err := c.root.OpenFile(productsDir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	files := map[string]int64{}
	for {
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			digest, ok := strings.CutSuffix(name, ".tar")
			if !ok || !hexDigest(digest, 64) {
				continue
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return nil, err
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 {
				return nil, evidence.ErrArtifact
			}
			files[digest] = stat.Size
		}
		if errors.Is(readErr, io.EOF) {
			return files, nil
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

// trimProducts is called with evidenceMu held. It makes room for
// reservation bytes in the products pool: it records the eviction of every
// ledger digest whose bytes are gone, removes bytes the ledger does not
// record and bytes unused for maxProductAge, then the least recently used
// until the pool fits limit (maxProductsPoolBytes in production). It never
// evicts the bytes of a producer job that is not terminal: its completion
// still verifies them.
func (c *Controller) trimProducts(ctx context.Context, reservation, limit int64) error {
	now := c.options.Now()
	files, err := c.productFiles()
	if err != nil {
		return err
	}
	records, err := c.options.Store.RetainedProducts(ctx)
	if err != nil {
		return err
	}
	type candidate struct {
		digest  string
		bytes   int64
		used    time.Time
		ledger  bool
		expired bool
	}
	var total int64
	var candidates []candidate
	recorded := make(map[string]store.Product, len(records))
	for _, r := range records {
		recorded[r.SHA256] = r
		if _, ok := files[r.SHA256]; !ok {
			if err := c.options.Store.EvictProduct(ctx, r.SHA256, now); err != nil {
				return err
			}
		}
	}
	for digest, size := range files {
		total += size
		r, ok := recorded[digest]
		if !ok {
			candidates = append(candidates, candidate{digest: digest, bytes: size, expired: true})
			continue
		}
		job, err := c.options.Store.Get(ctx, r.JobID)
		if err == nil && !job.State.Terminal() {
			continue
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		candidates = append(candidates, candidate{digest: digest, bytes: size, used: r.UsedAt, ledger: true, expired: !now.Before(r.UsedAt.Add(maxProductAge))})
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.expired != b.expired {
			return a.expired
		}
		if !a.used.Equal(b.used) {
			return a.used.Before(b.used)
		}
		return a.digest < b.digest
	})
	for _, old := range candidates {
		if !old.expired && total <= limit-reservation {
			break
		}
		if err := c.root.Remove(productsDir + "/" + productFile(old.digest)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		total -= old.bytes
		if old.ledger {
			if err := c.options.Store.EvictProduct(ctx, old.digest, now); err != nil {
				return err
			}
		}
	}
	if total > limit-reservation {
		return evidence.ErrArtifactLimit
	}
	return nil
}
