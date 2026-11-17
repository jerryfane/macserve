package workerclient

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
)

// A controller request of a running lease that fails transiently (a
// timeout, a lost connection, a 5xx or 429 answer) is retried after a
// backoff from retryBackoff, doubling up to maxRetryBackoff, until the
// controller would expire the lease (leaseClock). On a loaded host the
// controller answers slowly (#174): one slow request no longer ends a job.
const (
	retryBackoff    = 250 * time.Millisecond
	maxRetryBackoff = 2 * time.Second
)

// maxLogBacklog bounds the job output held in memory while its delivery to
// the controller is retried; a job that outruns it ends as when its output
// could not be delivered.
const maxLogBacklog = 4 << 20

// leaseClock tracks when the controller expires a delivered lease that is
// not finalizing: protocol.HeartbeatTimeout (its default HeartbeatTimeout)
// after the last heartbeat it answered. The worker counts from when it sent
// that heartbeat, which is never after the controller recorded it, so the
// worker never retries past the lease.
type leaseClock struct {
	mu   sync.Mutex
	beat time.Time
}

// newLeaseClock starts the window of a lease the worker received at most
// requestTimeout after the controller offered it (the controller's first
// heartbeat time).
func newLeaseClock(requestTimeout time.Duration) *leaseClock {
	return &leaseClock{beat: time.Now().Add(-requestTimeout)}
}

// renew records a heartbeat the controller answered, sent at sent.
func (l *leaseClock) renew(sent time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if sent.After(l.beat) {
		l.beat = sent
	}
}

func (l *leaseClock) expiry() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.beat.Add(protocol.HeartbeatTimeout)
}

// transient reports whether a failed controller request may succeed when
// sent again: the controller was slow or unreachable, or answered 5xx or
// 429. Another answer (410 lease gone, 409, 413 log limit, ...), a peer
// identity mismatch, a redirect or a malformed reply is final.
func transient(err error) bool {
	if errors.Is(err, ErrPeerIdentity) || errors.Is(err, errRedirect) {
		return false
	}
	var status *HTTPError
	if errors.As(err, &status) {
		return status.Status >= 500 || status.Status == http.StatusTooManyRequests
	}
	var urlErr *url.Error
	var netErr net.Error
	return errors.As(err, &urlErr) || errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF)
}

// retry runs attempt until it succeeds, fails for good, ctx ends, or the
// controller would expire the lease (clock): a transient failure is
// retried after a backoff, and each attempt ends by that expiry. The first
// attempt is made even when the lease window already passed (a finalizing
// lease outlives it), bounded by the request timeout alone.
func retry(ctx context.Context, clock *leaseClock, attempt func(context.Context) error) error {
	delay := retryBackoff
	for {
		attemptCtx, cancel := ctx, context.CancelFunc(func() {})
		if expiry := clock.expiry(); time.Now().Before(expiry) {
			attemptCtx, cancel = context.WithDeadline(ctx, expiry)
		}
		err := attempt(attemptCtx)
		cancel()
		if err == nil || !transient(err) || ctx.Err() != nil {
			return err
		}
		if !time.Now().Add(delay).Before(clock.expiry()) {
			return fmt.Errorf("%w (retried until the controller's %s lease window ended)", err, protocol.HeartbeatTimeout)
		}
		if wait(ctx, delay) != nil {
			return err
		}
		delay = min(2*delay, maxRetryBackoff)
	}
}

// remoteSink delivers a job's output and stages to the controller in the
// order the engine reports them. Log queues a chunk, numbered by its lease
// seq (protocol.Log), for one sender, and returns; at most maxLogBacklog
// bytes wait. The sender retries a transiently failed request (retry): the
// controller records each seq once, so a chunk whose first answer was lost
// is not duplicated. A refusal, a request still failing when the lease
// window ends or an overflowing backlog ends the job (cancel), as a failed
// request did before #174, and every later Log returns that error.
//
// The engine's cleanup never waits on the controller: Stage(Running), the
// gate before the job's recipe runs, waits for its delivery behind the
// queued chunks only until the job's context ends; Stage(Finalizing), the
// first step of cleanup, is queued and returns at once. Chunks and stages
// reported before the job's context ended are still delivered, in order,
// after it; later ones fail at once, as before #174. close waits for that
// delivery, at most maxDrain, before the job's end is judged.
type remoteSink struct {
	client              *Client
	ctx                 context.Context
	clock               *leaseClock
	epoch, jobID, lease string
	cancel              context.CancelCauseFunc
	// send bounds the sender's requests; close's drain bound ends it.
	send     context.Context
	stopSend context.CancelFunc

	mu      sync.Mutex
	wake    *sync.Cond
	queue   []sinkItem
	backlog int
	seq     int64
	err     error
	closed  bool
	done    chan struct{}
	once    sync.Once
}

// maxDrain bounds close's wait for the queued output once the engine
// returned: the heartbeat tolerance of the controller's finalizing window,
// which covers the transport of the job's evidence. Within the lease window
// retry already bounds each request; past it every queued request still
// gets one attempt, and maxDrain bounds them together.
const maxDrain = protocol.HeartbeatTimeout

// sinkItem is one queued chunk, or a stage whose result is reported on
// result (buffered: the sender never waits for a caller).
type sinkItem struct {
	log    protocol.Log
	stage  *protocol.Stage
	result chan error
}

func newRemoteSink(c *Client, ctx context.Context, clock *leaseClock, epoch, jobID, lease string, cancel context.CancelCauseFunc) *remoteSink {
	s := &remoteSink{client: c, ctx: ctx, clock: clock, epoch: epoch, jobID: jobID, lease: lease, cancel: cancel, done: make(chan struct{})}
	s.send, s.stopSend = context.WithCancel(context.Background())
	s.wake = sync.NewCond(&s.mu)
	go s.run()
	return s
}

var errSinkClosed = errors.New("job output delivery closed")

func (s *remoteSink) Log(stream, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.err != nil:
		return s.err
	case s.closed:
		return errSinkClosed
	case s.ctx.Err() != nil:
		return s.ctx.Err()
	case s.backlog+len(text) > maxLogBacklog:
		s.err = fmt.Errorf("controller log delivery backlog exceeded %d bytes", maxLogBacklog)
		s.cancel(s.err)
		return s.err
	}
	s.seq++
	s.backlog += len(text)
	s.queue = append(s.queue, sinkItem{log: protocol.Log{Stream: stream, Data: []byte(text), Seq: s.seq}})
	s.wake.Signal()
	return nil
}

func (s *remoteSink) Stage(state model.State) error {
	result := make(chan error, 1)
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return cmp.Or(s.ctx.Err(), errSinkClosed)
	}
	s.queue = append(s.queue, sinkItem{stage: &protocol.Stage{State: state}, result: result})
	s.wake.Signal()
	s.mu.Unlock()
	if state == model.Finalizing {
		return nil
	}
	select {
	case err := <-result:
		return err
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// close delivers what is queued, waiting at most maxDrain; then it ends the
// job (cancel) if output is still undelivered, and stops the sender.
func (s *remoteSink) close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.wake.Signal()
		s.mu.Unlock()
		timer := time.NewTimer(maxDrain)
		defer timer.Stop()
		select {
		case <-s.done:
		case <-timer.C:
			err := fmt.Errorf("job output not delivered to the controller within %s of the job's end", maxDrain)
			s.mu.Lock()
			if s.err == nil {
				s.err = err
			}
			s.mu.Unlock()
			s.cancel(err)
		}
		s.stopSend()
		<-s.done
	})
}

func (s *remoteSink) run() {
	defer close(s.done)
	path := "/jobs/" + s.jobID
	// lost: a chunk was not delivered. No later one is sent: the
	// controller would refuse the gap.
	lost := false
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && !s.closed {
			s.wake.Wait()
		}
		if len(s.queue) == 0 {
			s.mu.Unlock()
			return
		}
		item := s.queue[0]
		s.queue[0] = sinkItem{}
		s.queue = s.queue[1:]
		s.mu.Unlock()
		if item.stage != nil {
			err := retry(s.send, s.clock, func(ctx context.Context) error {
				_, err := s.client.json(ctx, http.MethodPost, path+"/stage", s.epoch, s.lease, item.stage, nil)
				return err
			})
			if err != nil {
				s.cancel(err)
			}
			item.result <- err
			continue
		}
		var err error
		if !lost {
			err = retry(s.send, s.clock, func(ctx context.Context) error {
				_, err := s.client.json(ctx, http.MethodPost, path+"/logs", s.epoch, s.lease, item.log, nil)
				return err
			})
			lost = err != nil
		}
		s.mu.Lock()
		s.backlog -= len(item.log.Data)
		if err != nil && s.err == nil {
			s.err = err
			s.cancel(err)
		}
		s.mu.Unlock()
	}
}
