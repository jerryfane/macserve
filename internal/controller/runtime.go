package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/peercred"
	"github.com/jerryfane/macserve/internal/source"
	"github.com/jerryfane/macserve/internal/store"
	"golang.org/x/sys/unix"
)

type execution struct {
	job             model.Job
	source          source.Descriptor
	ready           bool
	offered         bool
	heartbeat       time.Time
	cancellingSince time.Time
	finalizingSince time.Time
	cancel          context.CancelFunc
}

type Controller struct {
	options        Options
	mu             sync.Mutex
	evidenceMu     sync.Mutex
	poolBytes      int64 // protected by evidenceMu
	poolKnown      bool
	root           *os.Root
	lock           *os.File
	ctx            context.Context
	cancel         context.CancelFunc
	prep           sync.WaitGroup
	background     sync.WaitGroup
	active         *execution
	epoch          string
	workerIdle     bool
	lastSeen       time.Time
	maintaining    bool
	closed         bool
	running        bool
	server         *http.Server
	requestTimeout time.Duration
	closeOnce      sync.Once
	closeErr       error
}

func New(options Options) (*Controller, error) {
	if options.Root == "" || options.Socket == "" || options.Store == nil || options.Source == nil || options.Gate == nil || options.HeartbeatTimeout < 0 || options.CleanupTimeout < 0 || options.DeliveryTimeout < 0 || options.SourceTimeout < 0 {
		return nil, errors.New("controller requires private root, socket, authenticated broker peer UID, store, source and readiness gate")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.HeartbeatTimeout == 0 {
		options.HeartbeatTimeout = 30 * time.Second
	}
	// These match the worker's independent cleanup, evidence-delivery and source
	// read budgets. HeartbeatTimeout also provides bounded transport grace.
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = 2 * time.Minute
	}
	if options.DeliveryTimeout == 0 {
		options.DeliveryTimeout = 2 * time.Minute
	}
	if options.SourceTimeout == 0 {
		options.SourceTimeout = 10 * time.Minute
	}
	absolute, err := filepath.Abs(options.Root)
	if err != nil {
		return nil, err
	}
	options.Root = absolute
	if err := os.MkdirAll(absolute, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("controller root must be a private real directory")
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, err
	}
	directory, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	var directoryStat unix.Stat_t
	statErr := unix.Fstat(int(directory.Fd()), &directoryStat)
	directory.Close()
	if statErr != nil {
		root.Close()
		return nil, statErr
	}
	if directoryStat.Uid != uint32(os.Geteuid()) {
		root.Close()
		return nil, errors.New("controller root must be service-owned")
	}
	lock, err := root.OpenFile("controller.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		root.Close()
		return nil, err
	}
	fail := func(err error) (*Controller, error) { lock.Close(); root.Close(); return nil, err }
	var stat unix.Stat_t
	if err := unix.Fstat(int(lock.Fd()), &stat); err != nil {
		return fail(err)
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0077 != 0 {
		return fail(errors.New("unsafe controller lock"))
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(fmt.Errorf("controller already owns root: %w", err))
	}
	if err := root.Mkdir("artifacts", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return fail(err)
	}
	artifactInfo, err := root.Lstat("artifacts")
	if err != nil {
		return fail(err)
	}
	if !artifactInfo.IsDir() || artifactInfo.Mode().Perm()&0077 != 0 {
		return fail(errors.New("unsafe artifact root"))
	}
	previous, previousErr := options.Store.Active(context.Background())
	if previousErr != nil && !errors.Is(previousErr, store.ErrNotFound) {
		return fail(previousErr)
	}
	if previousErr == nil {
		if err := options.Store.RequireSourceCleanup(context.Background(), previous.ID); err != nil {
			return fail(err)
		}
	}
	if err := options.Store.Recover(context.Background(), options.Now()); err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Controller{options: options, root: root, lock: lock, ctx: ctx, cancel: cancel, requestTimeout: 2 * time.Minute}
	service, serviceErr := options.Store.ServiceState(ctx)
	gate, gateErr := options.Gate(ctx)
	if serviceErr == nil && gateErr == nil && !service.Paused && cleanupAllowed(gate) {
		// A failed retry leaves durable controller debt, not a startup loop that
		// loses the export ID or requires worker registration to clear it.
		_ = c.retrySourceCleanup(ctx)
	}
	return c, nil
}

type peerKey struct{}

func (c *Controller) newServer() *http.Server {
	return &http.Server{Handler: c.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: c.requestTimeout, WriteTimeout: c.requestTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			uid, err := peercred.UID(conn)
			return context.WithValue(ctx, peerKey{}, err == nil && uid == c.options.BrokerUID)
		},
	}
}

func (c *Controller) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.closed || c.running {
		c.mu.Unlock()
		return errors.New("controller is closed or already running")
	}
	c.running = true
	c.mu.Unlock()
	// Only a stale socket may be replaced; a regular file or symlink is never removed.
	if info, err := os.Lstat(c.options.Socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("worker socket path is not a socket")
		}
		connection, dialErr := net.DialTimeout("unix", c.options.Socket, time.Second)
		if dialErr == nil {
			connection.Close()
			return errors.New("worker socket already live")
		}
		if !errors.Is(dialErr, unix.ECONNREFUSED) {
			return fmt.Errorf("cannot establish stale worker socket: %w", dialErr)
		}
		if err := os.Remove(c.options.Socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: c.options.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	if err := os.Chmod(c.options.Socket, 0660); err != nil {
		listener.Close()
		return err
	}
	server := c.newServer()
	c.mu.Lock()
	c.server = server
	if c.closed {
		c.mu.Unlock()
		listener.Close()
		return errors.New("controller closed")
	}
	c.background.Add(1)
	c.mu.Unlock()
	monitorDone := make(chan struct{})
	go func() { defer c.background.Done(); defer close(monitorDone); c.monitor() }()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		err = nil
	case <-c.ctx.Done():
		err = nil
	case err = <-serveDone:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	// Stop admission immediately, while existing heartbeat requests see cancel.
	c.mu.Lock()
	c.closed = true
	if c.active != nil {
		_, cancelErr := c.options.Store.Cancel(context.Background(), c.active.job.ID, "controller shutdown", c.options.Now())
		err = errors.Join(err, cancelErr)
	}
	c.mu.Unlock()
	c.cancel()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	shutdownErr := server.Shutdown(shutdownCtx)
	cancel()
	if shutdownErr != nil {
		_ = server.Close()
	}
	<-monitorDone
	return errors.Join(err, c.Close())
}

func (c *Controller) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancel()
		server := c.server
		if c.active != nil {
			c.active.cancel()
		}
		c.mu.Unlock()
		if server != nil {
			c.closeErr = errors.Join(c.closeErr, server.Close())
		}
		c.prep.Wait()
		c.background.Wait()
		c.evidenceMu.Lock()
		c.mu.Lock()
		if c.active != nil {
			a := c.active
			c.active = nil
			c.mu.Unlock()
			cleanupErr := c.removeSource(a.job.ID)
			fail := c.options.Store.FailPreparation
			cleanupOK := cleanupErr == nil
			if a.offered {
				fail = c.options.Store.Fail
				cleanupOK = false
			}
			c.closeErr = errors.Join(c.closeErr, cleanupErr, fail(context.Background(), a.job.ID, a.job.LeaseToken, model.Interrupted, cleanupOK, "controller shutdown", c.options.Now()))
		} else {
			c.mu.Unlock()
		}
		c.evidenceMu.Unlock()
		c.closeErr = errors.Join(c.closeErr, c.root.Close(), c.lock.Close())
	})
	return c.closeErr
}

func (c *Controller) Status(ctx context.Context) (Status, error) {
	service, err := c.options.Store.ServiceState(ctx)
	if err != nil {
		return Status{}, err
	}
	gate, err := c.options.Gate(ctx)
	if err != nil {
		gate.Ready = false
		gate.Blockers = append(gate.Blockers, "readiness probe failed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	status := Status{Service: service, Gate: gate, WorkerReady: c.epoch != "" && !c.closed && !service.Quarantined && c.options.Now().Sub(c.lastSeen) <= c.options.HeartbeatTimeout, Quiescent: c.epoch != "" && c.workerIdle && !c.maintaining && c.active == nil && !service.Quarantined}
	if c.active != nil {
		status.ActiveJob = c.active.job.ID
	}
	return status, nil
}
