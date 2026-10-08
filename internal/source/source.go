// Package source exports admitted Git commits without exposing controller credentials.
package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

type Descriptor struct {
	Source worker.Source `json:"source"`
	Path   string        `json:"path"`
}

type Options struct {
	Root     string
	Token    func(context.Context, string) (string, error)
	MaxBytes int64
}

type Exporter struct {
	options Options
	root    *os.Root
	lock    *os.File
	mu      sync.Mutex
	closed  bool
}

var (
	jobIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	repoPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,99}/[A-Za-z0-9_.-]{1,100}$`)
	shaPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type ownership struct {
	JobID  string `json:"job_id"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func privateDir(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && info.Mode().Perm() == 0700 && stat.Uid == uint32(os.Geteuid())
}

func New(options Options) (*Exporter, error) {
	if options.Root == "" || options.MaxBytes < 0 {
		return nil, errors.New("invalid source options")
	}
	if options.MaxBytes == 0 {
		options.MaxBytes = 2 << 30
	}
	absolute, err := filepath.Abs(options.Root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if !privateDir(info) {
		return nil, errors.New("source root must be a service-owned private directory")
	}
	options.Root, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(options.Root)
	if err != nil {
		return nil, err
	}
	lock, err := root.OpenFile("source.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		root.Close()
		return nil, err
	}
	fail := func(err error) (*Exporter, error) { lock.Close(); root.Close(); return nil, err }
	lockInfo, err := lock.Stat()
	if err != nil {
		return fail(err)
	}
	stat, ok := lockInfo.Sys().(*syscall.Stat_t)
	if !ok || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return fail(errors.New("unsafe source lock"))
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(errors.New("source root already in use"))
	}
	for _, name := range []string{"jobs", "records"} {
		if err := root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return fail(err)
		}
		info, err := root.Lstat(name)
		if err != nil {
			return fail(err)
		}
		if !privateDir(info) {
			return fail(errors.New("unsafe source directory"))
		}
	}
	return &Exporter{options: options, root: root, lock: lock}, nil
}

func (e *Exporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	return errors.Join(e.root.Close(), e.lock.Close())
}

func syncDir(root *os.Root, name string) error {
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func (e *Exporter) record(jobID string) (resultErr error) {
	info, err := e.root.Lstat("jobs/" + jobID)
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	data, err := json.Marshal(ownership{JobID: jobID, Device: uint64(stat.Dev), Inode: uint64(stat.Ino)})
	if err != nil {
		return err
	}
	file, err := e.root.OpenFile("records/"+jobID+".json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, e.root.Remove("records/"+jobID+".json"))
		}
	}()
	_, writeErr := file.Write(data)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	return errors.Join(syncDir(e.root, "records"), syncDir(e.root, "jobs"))
}

// Remove never traverses an arbitrary caller-supplied path. Durable ownership
// records survive restart; an unrecorded or replaced subtree is left untouched.
func (e *Exporter) Remove(jobID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return os.ErrClosed
	}
	return e.remove(jobID)
}

func (e *Exporter) remove(jobID string) error {
	if !jobIDPattern.MatchString(jobID) {
		return errors.New("invalid source job ID")
	}
	name := "records/" + jobID + ".json"
	file, err := e.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	info, statErr := file.Stat()
	err = errors.Join(readErr, statErr, file.Close())
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || len(data) > 4096 {
		return errors.New("unsafe source ownership record")
	}
	var record ownership
	if err := json.Unmarshal(data, &record); err != nil || record.JobID != jobID {
		return errors.New("invalid source ownership record")
	}
	dir := "jobs/" + jobID
	info, err = e.root.Lstat(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !privateDir(info) || uint64(stat.Dev) != record.Device || uint64(stat.Ino) != record.Inode {
			return errors.New("source ownership changed")
		}
		if err := e.root.RemoveAll(dir); err != nil {
			return err
		}
		if err := syncDir(e.root, "jobs"); err != nil {
			return err
		}
	}
	if err := e.root.Remove(name); err != nil {
		return err
	}
	return syncDir(e.root, "records")
}

func validJob(job model.Job) bool {
	_, name, _ := strings.Cut(job.Request.Repo, "/")
	return jobIDPattern.MatchString(job.ID) && repoPattern.MatchString(job.Request.Repo) && name != "." && name != ".." && job.Profile.Repo == job.Request.Repo && shaPattern.MatchString(job.Request.SHA)
}

func (e *Exporter) Prepare(ctx context.Context, job model.Job) (descriptor Descriptor, resultErr error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return Descriptor{}, os.ErrClosed
	}
	if !validJob(job) {
		return Descriptor{}, errors.New("invalid admitted source identity")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Descriptor{}, err
	}
	jobDir := "jobs/" + job.ID
	if err := e.root.Mkdir(jobDir, 0700); err != nil {
		return Descriptor{}, err
	}
	if err := e.record(job.ID); err != nil {
		// Nothing has been placed in this newly created directory yet. Do not
		// delete a pre-existing ownership record if exclusive creation failed.
		return Descriptor{}, errors.Join(err, e.root.Remove(jobDir))
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, e.remove(job.ID))
		}
	}()
	stage, err := e.root.OpenRoot(jobDir)
	if err != nil {
		return Descriptor{}, err
	}
	defer stage.Close()
	dir := filepath.Join(e.options.Root, jobDir)
	if err := runGit(ctx, dir, nil, "init", "--bare", "--template=", "--object-format=sha1", "repo.git"); err != nil {
		return Descriptor{}, err
	}
	token := ""
	if e.options.Token != nil {
		token, err = e.options.Token(ctx, job.Request.Repo)
		if err != nil {
			return Descriptor{}, errors.New("source credential unavailable")
		}
		if strings.ContainsAny(token, "\x00\r\n") {
			return Descriptor{}, errors.New("invalid source credential")
		}
	}
	if err := fetch(ctx, dir, job.Request.Repo, job.Request.SHA, token, e.options.MaxBytes); err != nil {
		return Descriptor{}, err
	}
	token = ""
	descriptor.Source, err = exportTree(ctx, dir, stage, job.Request.SHA, e.options.MaxBytes)
	if err != nil {
		return Descriptor{}, err
	}
	if err := stage.RemoveAll("repo.git"); err != nil {
		return Descriptor{}, err
	}
	if err := syncDir(stage, "."); err != nil {
		return Descriptor{}, err
	}
	descriptor.Path = filepath.Join(dir, "source.tar")
	return descriptor, nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
	written   int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("source export exceeds byte limit")
	}
	n, err := w.writer.Write(data)
	w.remaining -= int64(n)
	w.written += int64(n)
	return n, err
}

func archiveFile(stage *os.Root, limit int64) (*os.File, *boundedWriter, interface{ Sum([]byte) []byte }, error) {
	file, err := stage.OpenFile("source.tar", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, nil, err
	}
	hash := sha256.New()
	return file, &boundedWriter{writer: io.MultiWriter(file, hash), remaining: limit}, hash, nil
}

func sourceIdentity(commit, tree string, size int64, digest []byte) worker.Source {
	return worker.Source{Commit: commit, Tree: tree, SizeBytes: size, SHA256: hex.EncodeToString(digest)}
}

func sourceError(operation string, err error) error {
	if err == nil {
		return nil
	}
	// Never forward Git output, arguments, or credential callback errors.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("source %s failed", operation)
}
