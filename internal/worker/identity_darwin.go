//go:build darwin

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

func bootIdentity() (string, error) {
	raw, err := unix.SysctlRaw("kern.boottime")
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func identityProcesses(ctx context.Context) ([]processSample, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	samples := make([]processSample, 0, len(rows))
	for _, row := range rows {
		p := row.Proc
		samples = append(samples, processSample{pid: int(p.P_pid), parent: int(row.Eproc.Ppid), group: int(row.Eproc.Pgid), uid: int(row.Eproc.Ucred.Uid), zombie: p.P_stat == 5, start: startToken(&p)})
	}
	return samples, ctx.Err()
}

// memoryProcesses reads the live processes of uid and charges each its
// phys_footprint, with the resident size alongside for diagnostics. Both come
// from the kernel in-process, so a sample never waits on a subprocess, however
// many processes a booting simulator has started. A process that exits
// between the table read and its memory read is omitted.
func memoryProcesses(ctx context.Context, uid int) ([]processSample, error) {
	rows, err := identityProcesses(ctx)
	if err != nil {
		return nil, err
	}
	samples := rows[:0]
	for _, p := range rows {
		if p.uid != uid || p.zombie {
			continue
		}
		resident, footprint, err := processMemory(p.pid)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read process %d memory: %w", p.pid, err)
		}
		p.rssKiB, p.footprintKiB = bytesToKiB(resident), bytesToKiB(footprint)
		samples = append(samples, p)
	}
	return samples, ctx.Err()
}

func bytesToKiB(n uint64) int64 {
	kib := n / 1024
	if n%1024 != 0 {
		kib++
	}
	return int64(kib)
}

// startToken is the kernel start time: with the PID it names one process.
func startToken(p *unix.ExternProc) string {
	return strconv.FormatInt(p.P_starttime.Sec, 10) + ":" + strconv.FormatInt(int64(p.P_starttime.Usec), 10)
}
