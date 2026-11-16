package controller

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/receipt"
	"golang.org/x/sys/unix"
)

func decodeJSON(reader io.Reader, maximum int64, value any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maximum {
		return store.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return store.ErrInvalid
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return store.ErrInvalid
	}
	return nil
}

// respond writes a worker-socket reply. Unmapped failures and receipt
// refusals are logged with the method, route and job id only: the worker sees
// just the status, and neither request bodies nor lease headers are logged.
func respond(w http.ResponseWriter, r *http.Request, value any, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, store.ErrLease), errors.Is(err, ErrExpired):
			status = http.StatusGone
		case errors.Is(err, store.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrTransition):
			status = http.StatusConflict
		case errors.Is(err, receipt.ErrInvalid):
			// The signer refused the evidence; replaying it cannot succeed.
			status = http.StatusUnprocessableEntity
		case errors.Is(err, store.ErrInvalid), errors.Is(err, evidence.ErrArtifact):
			status = http.StatusBadRequest
		case errors.Is(err, evidence.ErrArtifactLimit), errors.Is(err, store.ErrLogLimit), errors.Is(err, store.ErrResultLimit):
			status = http.StatusRequestEntityTooLarge
		case errors.Is(err, ErrNotReady):
			status = http.StatusServiceUnavailable
		}
		if status == http.StatusInternalServerError || status == http.StatusUnprocessableEntity {
			job := r.PathValue("job")
			if !safeID(job) {
				job = "-"
			}
			log.Printf("controller worker request failed: method=%s route=%q job=%s status=%d: %v", r.Method, r.Pattern, job, status, err)
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	if value == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (c *Controller) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.Prefix+"/register", func(w http.ResponseWriter, r *http.Request) {
		var registration protocol.Registration
		err := decodeJSON(r.Body, 4096, &registration)
		if err == nil && r.Header.Get(protocol.EpochHeader) != registration.Epoch {
			err = store.ErrLease
		}
		if err == nil {
			err = c.register(r.Context(), registration)
		}
		respond(w, r, nil, err)
	})
	mux.HandleFunc("POST "+protocol.Prefix+"/next", func(w http.ResponseWriter, r *http.Request) {
		// A worker before lanes sends an empty object.
		var request protocol.NextRequest
		err := decodeJSON(r.Body, 4096, &request)
		if err == nil && (len(request.Running) > model.MaxConcurrentJobs || slices.ContainsFunc(request.Running, func(id string) bool { return !safeID(id) })) {
			err = store.ErrInvalid
		}
		if err != nil {
			respond(w, r, nil, err)
			return
		}
		lease, err := c.next(r.Context(), r.Header.Get(protocol.EpochHeader), request.Running)
		if lease == nil {
			respond(w, r, nil, err)
		} else {
			respond(w, r, lease, err)
		}
	})
	mux.HandleFunc("GET "+protocol.Prefix+"/jobs/{job}/source", c.serveSource)
	mux.HandleFunc("POST "+protocol.Prefix+"/jobs/{job}/heartbeat", c.heartbeat)
	mux.HandleFunc("POST "+protocol.Prefix+"/jobs/{job}/stage", c.stage)
	mux.HandleFunc("POST "+protocol.Prefix+"/jobs/{job}/logs", c.logs)
	mux.HandleFunc("PUT "+protocol.Prefix+"/jobs/{job}/artifacts/{artifact}", c.upload)
	mux.HandleFunc("POST "+protocol.Prefix+"/jobs/{job}/complete", func(w http.ResponseWriter, r *http.Request) {
		job, err := c.requestJob(r, true)
		if err != nil {
			respond(w, r, nil, err)
			return
		}
		var completion protocol.Completion
		if err := decodeJSON(r.Body, 64<<20, &completion); err != nil {
			respond(w, r, nil, err)
			return
		}
		if err := c.refusedAdmission(r.Context(), job, completion); err != nil {
			respond(w, r, nil, err)
			return
		}
		respond(w, r, nil, c.complete(r.Context(), job, completion.Result, completion.Seal))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated, _ := r.Context().Value(peerKey{}).(bool)
		if !authenticated {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		started := time.Now()
		mux.ServeHTTP(w, r)
		if elapsed := time.Since(started); elapsed > slowWorkerRequest {
			job := r.PathValue("job")
			if !safeID(job) {
				job = "-"
			}
			log.Printf("controller worker request slow: method=%s route=%q job=%s duration=%s", r.Method, r.Pattern, job, elapsed.Round(time.Millisecond))
		}
	})
}

// slowWorkerRequest is how long a worker request may take before it is
// logged: the worker's requests time out after at most 10 s, and it cancels
// a job on its first failed heartbeat (#167).
const slowWorkerRequest = 5 * time.Second

func (c *Controller) requestJob(r *http.Request, replay bool) (model.Job, error) {
	id := r.PathValue("job")
	if !safeID(id) {
		return model.Job{}, store.ErrNotFound
	}
	job, err := c.options.Store.Get(r.Context(), id)
	if err != nil {
		return job, err
	}
	if err := leaseMatches(r, job); err != nil {
		return job, err
	}
	if job.State.Terminal() && (!replay || len(job.Result) == 0) {
		return job, store.ErrLease
	}
	return job, nil
}

// leaseMatches checks the request's worker epoch and lease against job's.
func leaseMatches(r *http.Request, job model.Job) error {
	epoch, lease := r.Header.Get(protocol.EpochHeader), r.Header.Get(protocol.LeaseHeader)
	if epoch == "" || epoch != job.WorkerEpoch || lease == "" || subtle.ConstantTimeCompare([]byte(lease), []byte(job.LeaseToken)) != 1 {
		return store.ErrLease
	}
	return nil
}

// heartbeatStoreWait bounds how long a heartbeat waits for the store. The
// store has one connection: slow store work (a prune, a long write) would
// otherwise hold every heartbeat, and the worker cancels a job on its first
// failed heartbeat (#167).
const heartbeatStoreWait = 500 * time.Millisecond

// heartbeat renews a delivered lease and tells the worker whether to cancel.
// It never takes c.mu, which other paths hold across store calls; its
// in-memory state is guarded by c.beatMu. The job's current record decides,
// as before, when the store answers within heartbeatStoreWait. When it does
// not, the lease is checked against the execution's claim record (its lease
// token, epoch and deadline never change while it is active), and the
// cancellation is the one last observed (cancelSeen: the store publishes
// every cancellation request it commits through OnCancel, and every monitor
// tick and heartbeat refresh it), so a cancel committed before the store
// went slow is still delivered.
func (c *Controller) heartbeat(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), heartbeatStoreWait)
	job, err := c.requestJob(r.WithContext(ctx), false)
	// Only the store's own wait falls back; the worker's abandoned request
	// and every answer the store gave are handled as before.
	fresh := true
	if err != nil && ctx.Err() != nil && r.Context().Err() == nil && !errors.Is(err, store.ErrLease) && !errors.Is(err, store.ErrNotFound) {
		fresh, err = false, nil
	}
	cancel()
	value, err := func() (protocol.Heartbeat, error) {
		if err != nil {
			return protocol.Heartbeat{}, err
		}
		c.beatMu.Lock()
		defer c.beatMu.Unlock()
		a := c.delivered(r)
		if a == nil {
			return protocol.Heartbeat{}, store.ErrLease
		}
		if !fresh {
			job = a.job
		}
		if job.Deadline == nil {
			return protocol.Heartbeat{}, store.ErrLease
		}
		a.cancelSeen = a.cancelSeen || job.CancelRequested
		a.heartbeat = c.options.Now()
		c.lastSeen = a.heartbeat
		return protocol.Heartbeat{Cancel: c.closed || a.cancelSeen || !a.judgedAt(c.options.Now()).Before(*job.Deadline), Deadline: *job.Deadline}, nil
	}()
	respond(w, r, value, err)
}

// delivered returns the delivered execution of the request's job and lease,
// or nil. Its claim record's lease token and epoch never change while it is
// active, so a store read made without c.mu cannot be paired with another
// lease of the job. Callers hold c.mu or c.beatMu.
func (c *Controller) delivered(r *http.Request) *execution {
	a := c.execution(r.PathValue("job"))
	if a == nil || !a.offered || leaseMatches(r, a.job) != nil {
		return nil
	}
	return a
}

// stage records the worker's stage. Its store read and transition run
// without c.mu (the transition is conditional on the state read and the
// lease), so a slow store does not hold other jobs' requests behind c.mu;
// only the in-memory windows take it.
func (c *Controller) stage(w http.ResponseWriter, r *http.Request) {
	var value protocol.Stage
	if err := decodeJSON(r.Body, 4096, &value); err != nil {
		respond(w, r, nil, err)
		return
	}
	if value.State != model.Running && value.State != model.Finalizing || value.Held && value.State != model.Finalizing {
		respond(w, r, nil, store.ErrTransition)
		return
	}
	err := func() error {
		job, err := c.requestJob(r, false)
		if err != nil {
			return err
		}
		c.mu.Lock()
		a := c.delivered(r)
		if a == nil {
			c.mu.Unlock()
			return store.ErrLease
		}
		now := c.options.Now()
		if value.State == model.Finalizing && a.finalizingSince.IsZero() {
			a.finalizingSince = now
		}
		if value.Held && a.heldAt.IsZero() {
			// Held once: the completion waits for the worker's idle check.
			c.beatMu.Lock()
			a.heldAt = now
			a.heartbeat = a.heldAt
			c.beatMu.Unlock()
		}
		c.mu.Unlock()
		if job.State == value.State {
			return nil
		}
		if job.CancelRequested && value.State == model.Running {
			return store.ErrTransition
		}
		return c.options.Store.Transition(r.Context(), job.ID, job.LeaseToken, job.State, value.State, "", now)
	}()
	respond(w, r, nil, err)
}

// logs appends the worker's output. Like stage, it waits on the store
// without c.mu: AppendLog checks the lease and the job's state itself, and a
// log-limit rejection requests the job's cancellation in its own transaction,
// so no completion can record success between the two.
func (c *Controller) logs(w http.ResponseWriter, r *http.Request) {
	var value protocol.Log
	if err := decodeJSON(r.Body, 128<<10, &value); err != nil {
		respond(w, r, nil, err)
		return
	}
	err := func() error {
		job, err := c.requestJob(r, false)
		if err != nil {
			return err
		}
		c.beatMu.Lock()
		a := c.delivered(r)
		c.beatMu.Unlock()
		if a == nil {
			return store.ErrLease
		}
		if value.Stream != "stdout" && value.Stream != "stderr" {
			return store.ErrInvalid
		}
		_, err = c.options.Store.AppendLog(r.Context(), job.ID, job.LeaseToken, value.Stream, string(value.Data), c.options.Now())
		if errors.Is(err, store.ErrLogLimit) {
			log.Printf("controller job log evidence limit exceeded: job=%s source=%s; cancellation requested", job.ID, model.CancelLogLimit)
		}
		return err
	}()
	respond(w, r, nil, err)
}

func (c *Controller) serveSource(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	job, err := c.requestJob(r, false)
	var a *execution
	if err == nil {
		a = c.execution(job.ID)
	}
	if err == nil && (a == nil || !a.ready || !a.offered || job.CancelRequested) {
		err = store.ErrLease
	}
	var name string
	if err == nil {
		name = a.source.Path
	}
	c.mu.Unlock()
	if err != nil {
		respond(w, r, nil, err)
		return
	}
	file, err := os.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		respond(w, r, nil, err)
		return
	}
	defer file.Close()
	info, err := privateRegular(file)
	if err != nil {
		respond(w, r, nil, err)
		return
	}
	// Source ingestion has a larger bounded budget than ordinary RPCs. Override
	// the per-connection server deadline only for this authenticated transfer.
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(c.options.SourceTimeout + c.options.HeartbeatTimeout)); err != nil {
		respond(w, r, nil, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	http.ServeContent(w, r, "source.tar", info.ModTime(), file)
}

func (c *Controller) upload(w http.ResponseWriter, r *http.Request) {
	job, err := c.requestJob(r, true)
	if err != nil {
		respond(w, r, nil, err)
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(r.Header.Get(protocol.ArtifactHeader))
	if err != nil {
		respond(w, r, nil, store.ErrInvalid)
		return
	}
	var artifact evidence.Artifact
	if err := decodeJSON(bytes.NewReader(raw), 8192, &artifact); err != nil {
		respond(w, r, nil, err)
		return
	}
	if artifact.ID != r.PathValue("artifact") || r.ContentLength != artifact.SizeBytes {
		respond(w, r, nil, store.ErrInvalid)
		return
	}
	respond(w, r, nil, c.putArtifact(r.Context(), job, artifact, r.Body))
}

// The caller has already authenticated its public principal and authorized the
// job. Private protocol authorization never accepts a controller filesystem path.
func (c *Controller) Receipt(ctx context.Context, id string) (json.RawMessage, error) {
	if !safeID(id) {
		return nil, store.ErrNotFound
	}
	job, err := c.options.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !job.State.Terminal() || len(job.Result) == 0 {
		return nil, ErrNotReady
	}
	var completion Completion
	if err := json.Unmarshal(job.Result, &completion); err != nil {
		return nil, err
	}
	if len(completion.Receipt) == 0 {
		return nil, ErrNotReady
	}
	return completion.Receipt, nil
}
