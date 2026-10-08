package controller

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/store"
	"github.com/jerryfane/macserve/internal/worker"
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

func respond(w http.ResponseWriter, value any, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, store.ErrLease), errors.Is(err, ErrExpired):
			status = http.StatusGone
		case errors.Is(err, store.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrTransition):
			status = http.StatusConflict
		case errors.Is(err, store.ErrInvalid), errors.Is(err, evidence.ErrArtifact):
			status = http.StatusBadRequest
		case errors.Is(err, evidence.ErrArtifactLimit), errors.Is(err, store.ErrLogLimit), errors.Is(err, store.ErrResultLimit):
			status = http.StatusRequestEntityTooLarge
		case errors.Is(err, ErrNotReady):
			status = http.StatusServiceUnavailable
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
		respond(w, nil, err)
	})
	mux.HandleFunc("POST "+protocol.Prefix+"/next", func(w http.ResponseWriter, r *http.Request) {
		var empty struct{}
		if err := decodeJSON(r.Body, 4096, &empty); err != nil {
			respond(w, nil, err)
			return
		}
		lease, err := c.next(r.Context(), r.Header.Get(protocol.EpochHeader))
		if lease == nil {
			respond(w, nil, err)
		} else {
			respond(w, lease, err)
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
			respond(w, nil, err)
			return
		}
		var result worker.Result
		if err := decodeJSON(r.Body, 64<<20, &result); err != nil {
			respond(w, nil, err)
			return
		}
		respond(w, nil, c.complete(r.Context(), job, result))
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
		if c.active == nil || c.active.job.ID != job.ID || !c.active.offered || job.Deadline == nil {
			return protocol.Heartbeat{}, store.ErrLease
		}
		c.active.heartbeat = c.options.Now()
		c.lastSeen = c.active.heartbeat
		return protocol.Heartbeat{Cancel: c.closed || job.CancelRequested || !c.options.Now().Before(*job.Deadline), Deadline: *job.Deadline}, nil
	}()
	respond(w, value, err)
}

func (c *Controller) stage(w http.ResponseWriter, r *http.Request) {
	var value protocol.Stage
	if err := decodeJSON(r.Body, 4096, &value); err != nil {
		respond(w, nil, err)
		return
	}
	if value.State != model.Running && value.State != model.Finalizing {
		respond(w, nil, store.ErrTransition)
		return
	}
	err := func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		job, err := c.requestJob(r, false)
		if err != nil {
			return err
		}
		if c.active == nil || c.active.job.ID != job.ID || !c.active.offered {
			return store.ErrLease
		}
		if job.State == value.State {
			return nil
		}
		if job.CancelRequested && value.State == model.Running {
			return store.ErrTransition
		}
		return c.options.Store.Transition(r.Context(), job.ID, job.LeaseToken, job.State, value.State, "", c.options.Now())
	}()
	respond(w, nil, err)
}

func (c *Controller) logs(w http.ResponseWriter, r *http.Request) {
	var value protocol.Log
	if err := decodeJSON(r.Body, 128<<10, &value); err != nil {
		respond(w, nil, err)
		return
	}
	err := func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		job, err := c.requestJob(r, false)
		if err != nil {
			return err
		}
		if c.active == nil || c.active.job.ID != job.ID || !c.active.offered {
			return store.ErrLease
		}
		if value.Stream != "stdout" && value.Stream != "stderr" {
			return store.ErrInvalid
		}
		_, err = c.options.Store.AppendLog(r.Context(), job.ID, job.LeaseToken, value.Stream, string(value.Data), c.options.Now())
		if errors.Is(err, store.ErrLogLimit) {
			_, _ = c.options.Store.Cancel(r.Context(), job.ID, "log evidence limit exceeded", c.options.Now())
		}
		return err
	}()
	respond(w, nil, err)
}

func (c *Controller) serveSource(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	job, err := c.requestJob(r, false)
	if err == nil && (c.active == nil || c.active.job.ID != job.ID || !c.active.ready || !c.active.offered || job.CancelRequested) {
		err = store.ErrLease
	}
	var name string
	if err == nil {
		name = c.active.source.Path
	}
	c.mu.Unlock()
	if err != nil {
		respond(w, nil, err)
		return
	}
	file, err := os.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		respond(w, nil, err)
		return
	}
	defer file.Close()
	info, err := privateRegular(file)
	if err != nil {
		respond(w, nil, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	http.ServeContent(w, r, "source.tar", info.ModTime(), file)
}

func (c *Controller) upload(w http.ResponseWriter, r *http.Request) {
	job, err := c.requestJob(r, true)
	if err != nil {
		respond(w, nil, err)
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(r.Header.Get(protocol.ArtifactHeader))
	if err != nil {
		respond(w, nil, store.ErrInvalid)
		return
	}
	var artifact evidence.Artifact
	if err := decodeJSON(bytes.NewReader(raw), 8192, &artifact); err != nil {
		respond(w, nil, err)
		return
	}
	if artifact.ID != r.PathValue("artifact") || r.ContentLength != artifact.SizeBytes {
		respond(w, nil, store.ErrInvalid)
		return
	}
	respond(w, nil, c.putArtifact(r.Context(), job, artifact, r.Body))
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
