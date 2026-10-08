// Package api exposes the authenticated controller HTTP surface, without owning a listener.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/store"
)

type Options struct {
	Store    *store.Store
	Profiles *profiles.Registry
	Status   func(context.Context) (controller.Status, error)
	Artifact func(context.Context, string, string) (*os.File, evidence.Artifact, error)
	Receipt  func(context.Context, string) (json.RawMessage, error)
	Now      func() time.Time
}
type handler struct{ Options }

var ErrForbidden = errors.New("scope or repository denied")

func New(o Options) (http.Handler, error) {
	if o.Store == nil || o.Profiles == nil || o.Status == nil || o.Artifact == nil || o.Receipt == nil {
		return nil, errors.New("API dependencies are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &handler{o}, nil
}

// Submit is shared by HTTP and authenticated coordinator integrations. Replays
// normalize defaults using the admitted snapshot, never today's profile registry.
func Submit(ctx context.Context, db *store.Store, registry *profiles.Registry, principal store.Principal, key string, request model.Request, now time.Time) (model.Job, bool, error) {
	if !principal.HasScope("jobs:submit") || !principal.AllowsRepository(request.Repo) {
		return model.Job{}, false, ErrForbidden
	}
	original, err := db.Lookup(ctx, principal.ID, key)
	if err == nil {
		request.Repo = strings.ToLower(request.Repo)
		request.SHA = strings.ToLower(request.SHA)
		if request.TimeoutSeconds == 0 {
			request.TimeoutSeconds = original.Profile.DefaultTimeoutSeconds
		}
		return db.Enqueue(ctx, principal.ID, key, model.Admission{Request: request, Profile: original.Profile, ProfileDigest: original.ProfileDigest}, now)
	}
	if !errors.Is(err, store.ErrNotFound) {
		return model.Job{}, false, err
	}
	admission, err := registry.Resolve(request)
	if err != nil {
		return model.Job{}, false, err
	}
	return db.Enqueue(ctx, principal.ID, key, admission, now)
}

func bearer(r *http.Request) string {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return ""
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return token
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		writeError(w, errUnavailable)
		return
	}
	w.Header().Set("X-Request-ID", hex.EncodeToString(id[:]))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	p, err := h.Store.Authenticate(r.Context(), bearer(r))
	if err != nil {
		writeError(w, err)
		return
	}
	path := r.URL.Path
	scope := "jobs:read"
	if strings.HasPrefix(path, "/v1/admin/") {
		scope = "service:admin"
	} else if path == "/v1/jobs" && r.Method == http.MethodPost {
		scope = "jobs:submit"
	} else if strings.HasSuffix(path, "/cancel") {
		scope = "jobs:cancel"
	}
	if !p.HasScope(scope) {
		writeError(w, ErrForbidden)
		return
	}
	switch {
	case path == "/v1/capabilities" && r.Method == http.MethodGet:
		h.capabilities(w, r, p)
	case path == "/v1/jobs" && r.Method == http.MethodPost:
		h.submit(w, r, p)
	case path == "/v1/jobs" && r.Method == http.MethodGet:
		h.list(w, r, p)
	case strings.HasPrefix(path, "/v1/jobs/"):
		h.job(w, r, p)
	case path == "/v1/admin/state" && r.Method == http.MethodGet:
		state, err := h.Status(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, 200, state)
	case path == "/v1/admin/pause" && r.Method == http.MethodPut:
		var body struct {
			Reason string `json:"reason"`
			Mode   string `json:"mode"`
		}
		if err := decode(w, r, &body); err != nil {
			writeError(w, err)
			return
		}
		state, err := h.Store.Pause(r.Context(), body.Reason, body.Mode, h.Now())
		if err != nil {
			writeError(w, err)
			return
		}
		status, err := h.Status(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"generation": state.Generation, "active_job": status.ActiveJob, "service": state})
	case path == "/v1/admin/pause" && r.Method == http.MethodDelete:
		state, err := h.Store.Resume(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, 200, state)
	default:
		writeError(w, store.ErrNotFound)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, err error) {
	status, code, message, retry := 500, "internal_error", "request could not be completed", false
	switch {
	case errors.Is(err, store.ErrUnauthenticated):
		status, code, message = 401, "unauthenticated", "valid bearer credential required"
		w.Header().Set("WWW-Authenticate", `Bearer realm="macserve"`)
	case errors.Is(err, ErrForbidden):
		status, code, message = 403, "forbidden", "permission denied"
	case errors.Is(err, store.ErrNotFound), errors.Is(err, os.ErrNotExist):
		status, code, message = 404, "not_found", "resource not found"
	case errors.Is(err, store.ErrInvalid), errors.Is(err, profiles.ErrInvalid):
		status, code, message = 400, "invalid_request", "malformed or invalid request"
	case errors.Is(err, profiles.ErrUnsupported):
		status, code, message = 422, "unsupported_request", "unsupported profile, toolchain or kind"
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrTransition):
		status, code, message = 409, "conflict", "request conflicts with existing state"
	case errors.Is(err, controller.ErrNotReady):
		status, code, message = 409, "result_not_ready", "result is not ready"
	case errors.Is(err, controller.ErrExpired), errors.Is(err, store.ErrLogExpired):
		status, code, message = 410, "expired", "evidence bytes expired"
	case errors.Is(err, store.ErrFull):
		status, code, message, retry = 429, "queue_full", "queue capacity reached", true
	case errors.Is(err, errUnavailable):
		status, code, message, retry = 503, "unavailable", "service temporarily unavailable", true
	}
	if retry {
		w.Header().Set("Retry-After", "5")
	}
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "retryable": retry}, "request_id": w.Header().Get("X-Request-ID")})
}

var errUnavailable = errors.New("unavailable")

// decode rejects unknown fields, duplicate keys, null roots, trailing values and
// excessive nesting as well as bounding total request bytes.
func decode(w http.ResponseWriter, r *http.Request, target any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return store.ErrInvalid
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		return store.ErrInvalid
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' || !utf8.Valid(data) {
		return store.ErrInvalid
	}
	tokens := json.NewDecoder(bytes.NewReader(data))
	if err := jsonValue(tokens, 0); err != nil {
		return store.ErrInvalid
	}
	if _, err := tokens.Token(); err != io.EOF {
		return store.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return store.ErrInvalid
	}
	return nil
}
func jsonValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return store.ErrInvalid
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return store.ErrInvalid
			}
			seen[name] = true
			if err := jsonValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := jsonValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return store.ErrInvalid
	}
	_, err = d.Token()
	return err
}
