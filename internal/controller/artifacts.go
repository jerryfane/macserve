package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"os"
	"path"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/source"
	"github.com/jerryfane/macserve/internal/store"
	"golang.org/x/sys/unix"
)

const maxArtifactBytes int64 = 5 << 30
const maxArtifacts = 10000

func hexDigest(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func validateSource(ctx context.Context, descriptor source.Descriptor, commit string) error {
	value := descriptor.Source
	if value.Commit != commit || !hexDigest(value.Tree, 40) || !hexDigest(value.SHA256, 64) || value.SizeBytes < 0 || value.SizeBytes > 30<<30 {
		return errors.New("invalid prepared source descriptor")
	}
	file, err := os.OpenFile(descriptor.Path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := privateRegular(file)
	if err != nil {
		return err
	}
	if info.Size() != value.SizeBytes {
		return errors.New("prepared source length mismatch")
	}
	return verifyBytes(contextReader{ctx: ctx, reader: file}, value.SizeBytes, value.SHA256)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

func verifyBytes(reader io.Reader, size int64, digest string) error {
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(reader, size+1))
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return evidence.ErrArtifact
	}
	return nil
}

func validArtifact(a evidence.Artifact) bool {
	if !hexDigest(a.ID, 64) || a.SHA256 != a.ID || a.SizeBytes < 0 || a.SizeBytes > maxArtifactBytes || a.Name == "" || len(a.Name) > 4096 || path.IsAbs(a.Name) || strings.ContainsAny(a.Name, "\\\x00\r\n") || a.ExpiresAt.IsZero() {
		return false
	}
	for _, part := range strings.Split(a.Name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	_, _, err := mime.ParseMediaType(a.MediaType)
	return err == nil && len(a.MediaType) <= 256
}

func (c *Controller) openArtifact(id, artifact string) (*os.File, error) {
	// Root confinement plus no-follow directory opens prevent both final and
	// intermediate symlink substitution, even within the private export root.
	parent, err := c.root.OpenFile("artifacts", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), id, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), id)
	defer dir.Close()
	fd, err = unix.Openat(int(dir.Fd()), artifact, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), artifact)
	if _, err := privateRegular(file); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func (c *Controller) uploaded(id string) ([]evidence.Artifact, error) {
	file, err := c.openArtifact(id, "uploads.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var manifest []evidence.Artifact
	if err := decodeJSON(file, 8<<20, &manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func randomName() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return ".pending-" + hex.EncodeToString(bytes[:]), nil
}

func (c *Controller) durable(name string, data []byte) error {
	temporary, err := randomName()
	if err != nil {
		return err
	}
	temporary = path.Join(path.Dir(name), temporary)
	file, err := c.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer c.root.Remove(temporary)
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	if err := c.root.Rename(temporary, name); err != nil {
		return err
	}
	dir, err := c.root.Open(path.Dir(name))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (c *Controller) putArtifact(ctx context.Context, job model.Job, a evidence.Artifact, body io.Reader) error {
	if !validArtifact(a) {
		return evidence.ErrArtifact
	}
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	current, err := c.options.Store.Get(ctx, job.ID)
	if err != nil {
		return err
	}
	if current.WorkerEpoch != job.WorkerEpoch || current.LeaseToken != job.LeaseToken {
		return store.ErrLease
	}
	if current.State.Terminal() && len(current.Result) == 0 {
		return store.ErrLease
	}
	if !c.options.Now().Before(a.ExpiresAt) {
		return ErrExpired
	}
	directory := "artifacts/" + job.ID
	if err := c.root.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := c.root.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return evidence.ErrArtifact
	}
	manifest, err := c.uploaded(job.ID)
	if err != nil {
		return err
	}
	duplicate := false
	var total int64
	for _, existing := range manifest {
		total += existing.SizeBytes
		if existing == a {
			duplicate = true
		}
		if existing.Name == a.Name && existing != a {
			return store.ErrConflict
		}
	}
	if !duplicate && current.State.Terminal() {
		return store.ErrConflict
	}
	if !duplicate && (len(manifest) >= maxArtifacts || a.SizeBytes > maxArtifactBytes-total) {
		return evidence.ErrArtifactLimit
	}
	temporary, err := randomName()
	if err != nil {
		return err
	}
	temporary = directory + "/" + temporary
	file, err := c.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer c.root.Remove(temporary)
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(body, a.SizeBytes+1))
	if copyErr == nil && (count != a.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != a.SHA256) {
		copyErr = evidence.ErrArtifact
	}
	if copyErr == nil {
		copyErr = file.Sync()
	}
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	existing, err := c.openArtifact(job.ID, a.ID)
	if err == nil {
		verifyErr := verifyBytes(existing, a.SizeBytes, a.SHA256)
		existing.Close()
		if verifyErr != nil {
			return verifyErr
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if duplicate {
			return ErrExpired
		}
		if err := c.trimPool(ctx, a.SizeBytes, maxArtifactPoolBytes); err != nil {
			return err
		}
		if err := c.root.Rename(temporary, directory+"/"+a.ID); err != nil {
			return err
		}
		c.poolBytes += a.SizeBytes
	} else {
		return err
	}
	if duplicate {
		return nil
	}
	manifest = append(manifest, a)
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return c.durable(directory+"/uploads.json", data)
}

// Artifact must be called only after the API has authorized this job's repository.
// IDs are resolved through the sealed completion manifest, never as arbitrary paths.
func (c *Controller) Artifact(ctx context.Context, id, artifactID string) (*os.File, evidence.Artifact, error) {
	if !safeID(id) || !hexDigest(artifactID, 64) {
		return nil, evidence.Artifact{}, store.ErrNotFound
	}
	job, err := c.options.Store.Get(ctx, id)
	if err != nil {
		return nil, evidence.Artifact{}, err
	}
	if !job.State.Terminal() || len(job.Result) == 0 {
		return nil, evidence.Artifact{}, ErrNotReady
	}
	var completion Completion
	if err := json.Unmarshal(job.Result, &completion); err != nil {
		return nil, evidence.Artifact{}, err
	}
	for _, artifact := range completion.Result.Artifacts {
		if artifact.ID != artifactID {
			continue
		}
		if !c.options.Now().Before(artifact.ExpiresAt) {
			return nil, artifact, ErrExpired
		}
		file, err := c.openArtifact(id, artifactID)
		if errors.Is(err, os.ErrNotExist) {
			err = ErrExpired
		}
		if err != nil {
			return nil, artifact, err
		}
		info, err := file.Stat()
		if err != nil || info.Size() != artifact.SizeBytes {
			file.Close()
			return nil, artifact, evidence.ErrArtifact
		}
		return file, artifact, nil
	}
	return nil, evidence.Artifact{}, store.ErrNotFound
}

func artifactExpiry(a evidence.Artifact, now time.Time) evidence.Artifact {
	latest := now.Add(7 * 24 * time.Hour)
	if a.ExpiresAt.After(latest) {
		a.ExpiresAt = latest
	}
	return a
}
