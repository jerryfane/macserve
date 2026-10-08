//go:build darwin

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		samples = append(samples, processSample{pid: int(p.P_pid), group: int(row.Eproc.Pgid), uid: int(row.Eproc.Ucred.Uid), zombie: p.P_stat == 5, start: strconv.FormatInt(p.P_starttime.Sec, 10) + ":" + strconv.FormatInt(int64(p.P_starttime.Usec), 10)})
	}
	return samples, ctx.Err()
}
