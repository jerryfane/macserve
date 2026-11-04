package plan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// SystemProbe reads the running host.
func SystemProbe() Probe {
	return Probe{
		GOOS: runtime.GOOS,
		UID:  os.Getuid(), EUID: os.Geteuid(),
		GID: os.Getgid(), EGID: os.Getegid(),
		Environ:   os.Environ(),
		Run:       runReadOnly,
		Addrs:     interfaceAddrs,
		Lstat:     lstat,
		Owner:     invokingAccount,
		AdminGID:  adminGID,
		PortInUse: portInUse,
	}
}

func interfaceAddrs() ([]netip.Addr, error) {
	list, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range list {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

func lstat(path string) (FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return FileInfo{}, nil
	}
	if err != nil {
		return FileInfo{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileInfo{}, fmt.Errorf("%s: no ownership information", path)
	}
	return FileInfo{Exists: true, Mode: info.Mode(), UID: st.Uid, GID: st.Gid, Nlink: uint64(st.Nlink)}, nil
}

func invokingAccount() (Account, error) {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return Account{}, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return Account{}, err
	}
	a := Account{Name: u.Username, UID: uint32(uid), Home: u.HomeDir}
	gids, err := u.GroupIds()
	if err != nil {
		return Account{}, err
	}
	for _, g := range gids {
		n, err := strconv.ParseInt(g, 10, 64)
		if err != nil {
			return Account{}, fmt.Errorf("group id %q: %w", g, err)
		}
		// Directory services may report negative IDs (nobody, -2); no
		// such group can be admin or matter for the ID choice.
		if n >= 0 && n <= 1<<32-1 {
			a.GIDs = append(a.GIDs, uint32(n))
		}
	}
	return a, nil
}

func adminGID() (uint32, error) {
	g, err := user.LookupGroup("admin")
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(g.Gid, 10, 32)
	return uint32(n), err
}

// portInUse dials ap once. Only a refused connection proves the port free.
func portInUse(ctx context.Context, ap netip.AddrPort) bool {
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "tcp", ap.String())
	if err == nil {
		conn.Close()
		return true
	}
	return !errors.Is(err, syscall.ECONNREFUSED)
}
