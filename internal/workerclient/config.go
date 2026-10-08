package workerclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Config struct {
	Socket                string `json:"socket"`
	ControllerUID         uint32 `json:"controller_uid"`
	Root                  string `json:"root"`
	ExportRoot            string `json:"export_root"`
	PollSeconds           int    `json:"poll_seconds"`
	HeartbeatSeconds      int    `json:"heartbeat_seconds"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
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
	for _, path := range []string{cfg.Socket, cfg.Root, cfg.ExportRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return cfg, fmt.Errorf("worker paths must be explicit clean absolute paths")
		}
	}
	if cfg.Root == cfg.ExportRoot {
		return cfg, errors.New("worker and export roots must differ")
	}
	if cfg.ControllerUID == 0 {
		return cfg, errors.New("controller must use a non-root UID")
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
