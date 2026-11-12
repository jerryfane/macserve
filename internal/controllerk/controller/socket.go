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
		respond(w, r, nil, c.complete(r.Context(), job, completion.Result, completion.Seal))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated, _ := r.Context().Value(peerKey{}).(bool)
		if !authenticated {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (c *Controller) requestJob(r *http.Request, replay bool) (model.Job, error) {
	id := r.PathValue("job")
	if !safeID(id) {
		return model.Job{}, store.ErrNotFound
	}
	job, err := c.options.Store.Get(r.Context(), id)
	if err != nil {
		return job, err
	}
	epoch, lease := r.Header.Get(protocol.EpochHeader), r.Header.Get(protocol.LeaseHeader)
	if epoch == "" || epoch != job.WorkerEpoch || lease == "" || subtle.ConstantTimeCompare([]byte(lease), []byte(job.LeaseToken)) != 1 {
		return job, store.ErrLease
	}
	if job.State.Terminal() && (!replay || len(job.Result) == 0) {
		return job, store.ErrLease
	}
	return job, nil
}

func (c *Controller) heartbeat(w http.ResponseWriter, r *http.Request) {
	value, err := func() (protocol.Heartbeat, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		job, err := c.requestJob(r, false)
		if err != nil {
			return protocol.Heartbeat{}, err
		}
		a := c.execution(job.ID)
		if a == nil || !a.offered || job.Deadline == nil {
			return protocol.Heartbeat{}, store.ErrLease
		}
		a.heartbeat = c.options.Now()
		c.lastSeen = a.heartbeat
		return protocol.Heartbeat{Cancel: c.closed || job.CancelRequested || !a.judgedAt(c.options.Now()).Before(*job.Deadline), Deadline: *job.Deadline}, nil
	}()
	respond(w, r, value, err)
}

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
		c.mu.Lock()
		defer c.mu.Unlock()
		job, err := c.requestJob(r, false)
		if err != nil {
			return err
		}
		a := c.execution(job.ID)
		if a == nil || !a.offered {
			return store.ErrLease
		}
		if value.State == model.Finalizing && a.finalizingSince.IsZero() {
			a.finalizingSince = c.options.Now()
		}
		if value.Held && a.heldAt.IsZero() {
			// Held once: the completion waits for the worker's idle check.
			a.heldAt = c.options.Now()
			a.heartbeat = a.heldAt
		}
		if job.State == value.State {
			return nil
		}
		if job.CancelRequested && value.State == model.Running {
			return store.ErrTransition
		}
		return c.options.Store.Transition(r.Context(), job.ID, job.LeaseToken, job.State, value.State, "", c.options.Now())
	}()
	respond(w, r, nil, err)
}

func (c *Controller) logs(w http.ResponseWriter, r *http.Request) {
	var value protocol.Log
	if err := decodeJSON(r.Body, 128<<10, &value); err != nil {
		respond(w, r, nil, err)
		return
	}
	err := func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		job, err := c.requestJob(r, false)
		if err != nil {
			return err
		}
		if a := c.execution(job.ID); a == nil || !a.offered {
			return store.ErrLease
		}
		if value.Stream != "stdout" && value.Stream != "stderr" {
			return store.ErrInvalid
		}
		_, err = c.options.Store.AppendLog(r.Context(), job.ID, job.LeaseToken, value.Stream, string(value.Data), c.options.Now())
		if errors.Is(err, store.ErrLogLimit) {
			_, _ = c.cancelJob(r.Context(), job, "log evidence limit exceeded", model.CancelReason{Source: model.CancelLogLimit}, c.options.Now())
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
