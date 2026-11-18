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
		p, _, ok, err := readStat(pid)
		if err != nil {
			return nil, err
		}
		if ok {
			samples = append(samples, p)
		}
	}
	return samples, nil
}

// processCommand is pid's kernel command name (comm: its executable's name,
// at most 15 bytes; never an argument or the environment) while pid still
// names the process started at start.
func processCommand(pid int, start string) (string, bool) {
	p, command, ok, err := readStat(pid)
	if err != nil || !ok || p.start != start {
		return "", false
	}
	return command, true
}

// readStat reads pid's /proc stat record and its command name; ok is false
// for a process that exited during the read.
func readStat(pid int) (p processSample, command string, ok bool, err error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if os.IsNotExist(err) {
		return p, "", false, nil
	}
	if err != nil {
		return p, "", false, err
	}
	info, statErr := file.Stat()
	data := make([]byte, 8192)
	n, readErr := file.Read(data)
	file.Close()
	if statErr != nil || readErr != nil {
		return p, "", false, nil // exited during the read
	}
	text := string(data[:n])
	stat, isStat := info.Sys().(*syscall.Stat_t)
	begin, end := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if !isStat || begin < 0 || end < begin {
		return p, "", false, errors.New("invalid kernel process stat")
	}
	fields := strings.Fields(text[end+1:])
	if len(fields) < 20 {
		return p, "", false, errors.New("short kernel process stat")
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return p, "", false, err
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil {
		return p, "", false, err
	}
	return processSample{pid: pid, parent: parent, group: group, uid: int(stat.Uid), zombie: fields[0] == "Z", start: fields[19]}, text[begin+1 : end], true, nil
}
