package signer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// recordingEngine counts requests and signs with a real world's engine.
type recordingEngine struct {
	calls atomic.Int32
	inner signingEngine
}

func (r *recordingEngine) Sign(ctx context.Context, req Request) (*Signed, error) {
	r.calls.Add(1)
	return r.inner.Sign(ctx, req)
}

func serve(t *testing.T, controllerUID uint32, engine signingEngine) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	listener, err := Listen(socket, uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", info, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	server := &Server{Engine: engine, ControllerUID: controllerUID}
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return socket
}

// The controller's connection is served end to end; the ipa arrives
// verified against the signer's header.
func TestSocketServesControllerPeer(t *testing.T) {
	w := newWorld(t)
	engine := &recordingEngine{inner: w.engine}
	socket := serve(t, uint32(os.Getuid()), engine)
	client := &Client{Socket: socket, SignerUID: uint32(os.Getuid()), Timeout: time.Minute}
	var ipa bytes.Buffer
	result, err := client.Sign(t.Context(), w.request(), &ipa)
	if err != nil {
		t.Fatal(err)
	}
	if engine.calls.Load() != 1 || int64(ipa.Len()) != result.IPASize || digestHex(ipa.Bytes()) != result.IPASHA256 || len(result.Receipt) == 0 {
		t.Fatalf("result %+v, %d bytes", result, ipa.Len())
	}
	// A refusal comes back as a RefusalError with its reason.
	req := w.request()
	req.JobID = "job-2"
	_, err = client.Sign(t.Context(), req, &ipa)
	var refused *RefusalError
	if !errors.As(err, &refused) || refused.Reason == "" {
		t.Fatalf("refusal = %v", err)
	}
}

// Any peer other than the controller UID is disconnected before its
// request is read; the engine never runs.
func TestSocketRefusesOtherPeerUID(t *testing.T) {
	w := newWorld(t)
	engine := &recordingEngine{inner: w.engine}
	socket := serve(t, uint32(os.Getuid())+1, engine)
	client := &Client{Socket: socket, SignerUID: uint32(os.Getuid()), Timeout: 10 * time.Second}
	var ipa bytes.Buffer
	if _, err := client.Sign(t.Context(), w.request(), &ipa); err == nil {
		t.Fatal("non-controller peer was served")
	}
	if engine.calls.Load() != 0 || ipa.Len() != 0 {
		t.Fatalf("engine ran %d times for a refused peer", engine.calls.Load())
	}
}

// The client refuses a socket served by any account but the signer's,
// before sending the receipt.
func TestClientRefusesNonSignerSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "sg")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "s.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan int, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- -1
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 1024)
		n, _ := conn.Read(buffer)
		received <- n
	}()
	client := &Client{Socket: socket, SignerUID: uint32(os.Getuid()) + 1, Timeout: 5 * time.Second}
	if _, err := client.Sign(t.Context(), Request{JobID: "job-1", Receipt: []byte("secret receipt")}, &bytes.Buffer{}); err == nil {
		t.Fatal("client trusted a non-signer socket")
	}
	if n := <-received; n > 0 {
		t.Fatalf("client sent %d bytes to a non-signer socket", n)
	}
}

// Listen refuses to replace a path that is not this account's socket.
func TestListenRefusesNonSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "sg")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s.sock")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, uint32(os.Getgid())); err == nil {
		t.Fatal("replaced a regular file")
	}
}
