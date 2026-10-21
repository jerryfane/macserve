package workerclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/worker"
)

type Config struct {
	Socket                string `json:"socket"`
	ControllerUID         uint32 `json:"controller_uid"`
	Root                  string `json:"root"`
	ExportRoot            string `json:"export_root"`
	WorkspaceRoot         string `json:"workspace_root"`
	JobUID                uint32 `json:"job_uid"`
	JobGID                uint32 `json:"job_gid"`
	OwnerUID              uint32 `json:"owner_uid"`
	HelperPath            string `json:"helper_path"`
	BaselinePath          string `json:"baseline_path"`
	PersistencePath       string `json:"persistence_path"`
	PollSeconds           int    `json:"poll_seconds"`
	HeartbeatSeconds      int    `json:"heartbeat_seconds"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
}

// EngineOptions maps the protected broker configuration to native worker
// options; the broker, worker-reset, persistence review and qualification tool
// evidence all use this one mapping.
func (c Config) EngineOptions() worker.Options {
	return worker.Options{Root: c.Root, ExportRoot: c.ExportRoot, WorkspaceRoot: c.WorkspaceRoot, JobUID: c.JobUID, JobGID: c.JobGID, OwnerUID: c.OwnerUID, ControllerUID: c.ControllerUID, HelperPath: c.HelperPath, BaselinePath: c.BaselinePath, PersistencePath: c.PersistencePath}
}

func LoadConfig(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return cfg, err
	}
	if len(data) > 64<<10 {
		return cfg, errors.New("worker configuration exceeds 64 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("trailing worker configuration")
	}
	return normalize(cfg)
}

func normalize(cfg Config) (Config, error) {
	for _, path := range []string{cfg.Socket, cfg.Root, cfg.ExportRoot, cfg.WorkspaceRoot, cfg.HelperPath, cfg.BaselinePath, cfg.PersistencePath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return cfg, fmt.Errorf("worker paths must be explicit clean absolute paths")
		}
	}
	inside := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	roots := []string{cfg.Root, cfg.ExportRoot, cfg.WorkspaceRoot}
	for i, a := range roots {
		for _, b := range roots[i+1:] {
			if inside(a, b) || inside(b, a) {
				return cfg, errors.New("worker control, export and workspace roots must not overlap")
			}
		}
	}
	for _, path := range []string{cfg.Socket, cfg.HelperPath, cfg.BaselinePath, cfg.PersistencePath} {
		if inside(cfg.WorkspaceRoot, path) {
			return cfg, errors.New("broker control path must not be inside workspace storage")
		}
	}
	for _, path := range []string{cfg.Socket, cfg.Root, cfg.ExportRoot, cfg.WorkspaceRoot, cfg.HelperPath, cfg.BaselinePath} {
		if path == cfg.PersistencePath {
			return cfg, errors.New("persistence authority must be a separate protected file")
		}
	}
	if err := hostguard.DistinctJobIdentity(cfg.JobUID, cfg.JobGID, cfg.ControllerUID, cfg.OwnerUID); err != nil {
		return cfg, err
	}
	if cfg.PollSeconds == 0 {
		cfg.PollSeconds = 2
	}
	if cfg.HeartbeatSeconds == 0 {
		cfg.HeartbeatSeconds = 5
	}
	if cfg.RequestTimeoutSeconds == 0 {
		cfg.RequestTimeoutSeconds = 10
	}
	if cfg.PollSeconds < 1 || cfg.PollSeconds > 30 || cfg.HeartbeatSeconds < 1 || cfg.HeartbeatSeconds > 5 || cfg.RequestTimeoutSeconds < 1 || cfg.RequestTimeoutSeconds > 10 {
		return cfg, errors.New("worker polling or heartbeat bounds exceeded")
	}
	return cfg, nil
}
