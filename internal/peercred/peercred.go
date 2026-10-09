// Package peercred authenticates Unix socket peers using kernel credentials.
package peercred

import (
	"errors"
	"net"
)

func UID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("peer credentials require a Unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credentialErr error
	if err := raw.Control(func(fd uintptr) { uid, credentialErr = socketUID(int(fd)) }); err != nil {
		return 0, err
	}
	return uid, credentialErr
}
