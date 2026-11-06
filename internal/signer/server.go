package signer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/peercred"
)

// signingEngine is the Engine surface the server needs.
type signingEngine interface {
	Sign(context.Context, Request) (*Signed, error)
}

// Server serves signing requests on a Unix socket to exactly one peer UID,
// the controller's.
type Server struct {
	Engine        signingEngine
	ControllerUID uint32
	Logger        *log.Logger
	// PeerUID returns a connection's kernel peer UID; nil uses peercred.
	PeerUID func(net.Conn) (uint32, error)
}

// Listen binds socket as the current (signer) user, removing only a stale
// socket this user owns, and grants the RPC group read/write (0660). The
// directory is the access boundary: owned by the signer and the RPC group,
// 0750, so no other account can reach the socket.
func Listen(socket string, rpcGID uint32) (net.Listener, error) {
	if info, err := os.Lstat(socket); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if info.Mode()&os.ModeSocket == 0 || !ok || stat.Uid != uint32(os.Getuid()) {
			return nil, fmt.Errorf("%s exists and is not this account's socket", socket)
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := errors.Join(os.Chown(socket, -1, int(rpcGID)), os.Chmod(socket, 0o660)); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// Serve accepts connections until ctx ends. Each connection must come from
// ControllerUID, else it is closed unread.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	peer := s.PeerUID
	if peer == nil {
		peer = peercred.UID
	}
	uid, err := peer(conn)
	if err != nil || uid != s.ControllerUID {
		s.logf("signer: refused connection from peer UID %d: %v", uid, err)
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := readLine(bufio.NewReaderSize(conn, 64<<10), maxRequestBytes)
	if err != nil {
		s.logf("signer: request: %v", err)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	var req Request
	if err := strictJSON(line, &req); err != nil {
		writeResponse(conn, response{Error: "malformed request"})
		return
	}
	signed, err := s.Engine.Sign(ctx, req)
	if err != nil {
		s.logf("signer: job %s: %v", req.JobID, err)
		reason := "signer failure: " + err.Error()
		var refused *RefusalError
		if errors.As(err, &refused) {
			reason = refused.Reason
		}
		writeResponse(conn, response{Error: reason})
		return
	}
	defer signed.Close()
	if err := writeResponse(conn, response{OK: true, Receipt: signed.Receipt, IPASHA256: signed.IPASHA256, IPASize: signed.IPASize}); err != nil {
		return
	}
	if _, err := io.Copy(conn, io.LimitReader(signed.IPA, signed.IPASize)); err != nil {
		s.logf("signer: job %s: send ipa: %v", req.JobID, err)
		return
	}
	s.logf("signer: job %s signed, ipa %s", req.JobID, signed.IPASHA256)
}

func writeResponse(w io.Writer, resp response) error {
	line, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}
