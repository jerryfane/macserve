package worker

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
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

var (
	ErrBusy     = errors.New("worker is busy")
	ErrClosed   = errors.New("worker is closed")
	ErrRecovery = errors.New("worker requires recovery")
	identifier  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	sha40       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	udidPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
)

type Engine struct {
	mu         sync.Mutex
	options    Options
	root       *os.Root
	exports    *os.Root
	workspaces *os.Root
	lock       *os.File
	closed     bool
}

type manifest struct {
	JobID            string `json:"job_id"`
	DeveloperDir     string `json:"developer_dir"`
	DeviceUDID       string `json:"device_udid,omitempty"`
	Active           bool   `json:"active"`
	ProcessUncertain bool   `json:"process_uncertain,omitempty"`
}

type exportManifest struct {
	Artifacts []evidence.Artifact `json:"artifacts"`
}

func New(options Options) (*Engine, error) {
	if options.Root == "" || options.ExportRoot == "" || options.WorkspaceRoot == "" {
		return nil, errors.New("control, export and workspace roots are required")
	}
	if options.CleanupTimeout < 0 || options.CleanupTimeout > 2*time.Minute || options.MaxWorkspaceBytes < 0 || options.MaxArtifactBytes < 0 {
		return nil, errors.New("invalid worker limits")
	}
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = 2 * time.Minute
	}
	if options.MaxWorkspaceBytes == 0 {
		options.MaxWorkspaceBytes = 30 << 30
	}
	if options.MaxArtifactBytes == 0 {
		options.MaxArtifactBytes = 5 << 30
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	var err error
	if options.Runner == nil {
		options.Runner, err = NewNativeRunner(options)
		if err != nil {
			return nil, err
		}
	}
	for _, target := range []*string{&options.Root, &options.ExportRoot, &options.WorkspaceRoot} {
		*target, err = filepath.Abs(*target)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(*target, 0700); err != nil {
			return nil, err
		}
		*target, err = filepath.EvalSymlinks(*target)
		if err != nil {
			return nil, err
		}
	}
	roots := []string{options.Root, options.ExportRoot, options.WorkspaceRoot}
	for i, a := range roots {
		for _, b := range roots[i+1:] {
			if within(a, b) || within(b, a) {
				return nil, errors.New("control, export and workspace roots must not overlap")
			}
		}
	}
	if _, native := options.Runner.(*nativeRunner); native {
		for _, target := range []string{options.Root, options.ExportRoot} {
			info, err := os.Stat(target)
			if err != nil {
				return nil, err
			}
			if info.Mode().Perm()&0077 != 0 {
				return nil, errors.New("control and export roots must be root-private")
			}
		}
	}
	root, err := os.OpenRoot(options.Root)
	if err != nil {
		return nil, err
	}
	lock, err := root.OpenFile("worker.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		root.Close()
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		root.Close()
		return nil, fmt.Errorf("exclusive worker lock: %w", err)
	}
	fail := func(err error) (*Engine, error) { lock.Close(); root.Close(); return nil, err }
	if err := root.MkdirAll("manifests", 0700); err != nil {
		return fail(err)
	}
	info, err := root.Lstat("manifests")
	if err != nil || !info.IsDir() {
		return fail(errors.New("worker manifest directory is not a real directory"))
	}
	exports, err := os.OpenRoot(options.ExportRoot)
	if err != nil {
		return fail(err)
	}
	workspaces, err := os.OpenRoot(options.WorkspaceRoot)
	if err != nil {
		exports.Close()
		return fail(err)
	}
	return &Engine{options: options, root: root, exports: exports, workspaces: workspaces, lock: lock}, nil
}

func within(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (e *Engine) Close() error {
	if !e.mu.TryLock() {
		return ErrBusy
	}
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	return errors.Join(e.workspaces.Close(), e.exports.Close(), e.root.Close(), e.lock.Close())
}

func (e *Engine) saveManifest(m manifest) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return durableFile(e.root, "manifests/"+m.JobID+".json", data)
}

func durableFile(root *os.Root, name string, data []byte) error {
	file, err := root.OpenFile(name+".new", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := root.Rename(name+".new", name); err != nil {
		return err
	}
	dir, err := root.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readJSON(root *os.Root, name string, value any) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return errors.New("invalid worker registry file")
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	dec := json.NewDecoder(io.LimitReader(file, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("trailing registry data")
	}
	return nil
}

func (e *Engine) registryNames() ([]string, error) {
	dir, err := e.root.Open("manifests")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.Readdirnames(-1)
}

// Recover acts only on durable worker-owned records. A process whose termination
// was not observed remains quarantined: recovery never guesses from a reused PID.
func (e *Engine) Recover(ctx context.Context) error {
	if !e.mu.TryLock() {
		return ErrBusy
	}
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	quietCtx, cancel := context.WithTimeout(ctx, e.options.CleanupTimeout)
	defer cancel()
	if err := e.options.Runner.Quiesce(quietCtx); err != nil {
		return errors.Join(ErrRecovery, err)
	}
	names, err := e.registryNames()
	if err != nil {
		return err
	}
	var failures []error
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		var m manifest
		if err := readJSON(e.root, "manifests/"+name, &m); err != nil {
			failures = append(failures, err)
			continue
		}
		if !identifier.MatchString(m.JobID) || name != m.JobID+".json" || !filepath.IsAbs(m.DeveloperDir) || (m.DeviceUDID != "" && !udidPattern.MatchString(m.DeviceUDID)) {
			failures = append(failures, ErrRecovery)
			continue
		}
		if m.Active || m.ProcessUncertain {
			failures = append(failures, fmt.Errorf("%w: unresolved recorded work %s", ErrRecovery, m.JobID))
			continue
		}
		if m.DeviceUDID != "" {
			if err := e.reconcileDevice(ctx, &m); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		if err := e.stopWriters(ctx, &m); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := e.cleanup(ctx, &m); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func validateJob(job model.Job, source Source) (model.Job, error) {
	if !identifier.MatchString(job.ID) || !identifier.MatchString(job.LeaseToken) || !identifier.MatchString(job.WorkerEpoch) || job.State != model.Preparing {
		return job, errors.New("invalid job identity, lease, epoch or state")
	}
	if !sha40.MatchString(source.Commit) || !sha40.MatchString(source.Tree) || !sha64.MatchString(source.SHA256) || source.Commit != job.Request.SHA || source.SizeBytes <= 0 {
		return job, errors.New("invalid immutable source identity")
	}
	registry, err := profiles.New([]model.Profile{job.Profile})
	if err != nil {
		return job, err
	}
	admission, err := registry.Resolve(job.Request)
	if err != nil {
		return job, err
	}
	data, err := json.Marshal(admission.Request)
	if err != nil {
		return job, err
	}
	digest := sha256.Sum256(data)
	if !reflect.DeepEqual(job.Profile, admission.Profile) || !reflect.DeepEqual(job.Request, admission.Request) || job.ProfileDigest != admission.ProfileDigest || job.RequestDigest != hex.EncodeToString(digest[:]) {
		return job, errors.New("job snapshot is not normalized or its digest mismatches")
	}
	if job.Deadline != nil && (job.Deadline.IsZero() || job.Deadline.Year() < 1970 || job.Deadline.Year() > 9999) {
		return job, errors.New("invalid job deadline")
	}
	// Registry returns independent copies, avoiding retaining mutable caller slices.
	job.Profile = admission.Profile
	job.Request = admission.Request
	return job, nil
}

func (e *Engine) ArtifactPath(jobID, artifactID string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return "", ErrClosed
	}
	if !identifier.MatchString(jobID) || !sha64.MatchString(artifactID) {
		return "", errors.New("invalid export identity")
	}
	var m exportManifest
	if err := readJSON(e.exports, jobID+"/manifest.json", &m); err != nil {
		return "", err
	}
	for _, artifact := range m.Artifacts {
		if artifact.ID == artifactID {
			name := jobID + "/" + artifactID
			info, err := e.exports.Lstat(name)
			if err != nil {
				return "", err
			}
			if !info.Mode().IsRegular() || info.Size() != artifact.SizeBytes {
				return "", errors.New("export changed after sealing")
			}
			file, err := e.exports.Open(name)
			if err != nil {
				return "", err
			}
			hash := sha256.New()
			_, copyErr := io.Copy(hash, file)
			closeErr := file.Close()
			if err := errors.Join(copyErr, closeErr); err != nil {
				return "", err
			}
			if hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
				return "", errors.New("export digest mismatch")
			}
			return filepath.Join(e.options.ExportRoot, jobID, artifactID), nil
		}
	}
	return "", os.ErrNotExist
}

func (e *Engine) RemoveExport(jobID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	if !identifier.MatchString(jobID) {
		return errors.New("invalid export job identity")
	}
	return e.exports.RemoveAll(jobID)
}
