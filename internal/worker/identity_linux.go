//go:build linux

package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func bootIdentity() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(data)), err
}

func identityProcesses(ctx context.Context) ([]processSample, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var samples []processSample
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		path := filepath.Join("/proc", entry.Name(), "stat")
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		info, statErr := file.Stat()
		data := make([]byte, 8192)
		n, readErr := file.Read(data)
		file.Close()
		if statErr != nil || readErr != nil {
			continue
		} // exited during the snapshot
		stat, ok := info.Sys().(*syscall.Stat_t)
		end := strings.LastIndexByte(string(data[:n]), ')')
		if !ok || end < 0 {
			return nil, errors.New("invalid kernel process stat")
		}
		fields := strings.Fields(string(data[end+1 : n]))
		if len(fields) < 20 {
			return nil, errors.New("short kernel process stat")
		}
		group, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, err
		}
		samples = append(samples, processSample{pid: pid, group: group, uid: int(stat.Uid), zombie: fields[0] == "Z", start: fields[19]})
	}
	return samples, nil
}
