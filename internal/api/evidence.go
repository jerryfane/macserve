package api

import (
	"encoding/json"
	"mime"
	"net/http"
	"strconv"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/store"
)

func completion(job model.Job) (controller.Completion, error) {
	var result controller.Completion
	if !job.State.Terminal() || len(job.Result) == 0 {
		return result, controller.ErrNotReady
	}
	if err := json.Unmarshal(job.Result, &result); err != nil {
		return result, err
	}
	return result, nil
}
func (h *handler) results(w http.ResponseWriter, r *http.Request, job model.Job, junit bool) {
	result, err := completion(job)
	if err != nil {
		writeError(w, err)
		return
	}
	if result.Result.Summary == nil {
		writeError(w, controller.ErrNotReady)
		return
	}
	if junit {
		data, err := evidence.JUnit(*result.Result.Summary)
		if err != nil {
			writeError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="results.xml"`)
		w.WriteHeader(200)
		_, _ = w.Write(data)
		return
	}
	writeJSON(w, 200, result.Result.Summary)
}
func (h *handler) artifacts(w http.ResponseWriter, r *http.Request, job model.Job) {
	result, err := completion(job)
	if err != nil {
		writeError(w, err)
		return
	}
	after, err := logCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, err)
		return
	}
	limit, err := intQuery(r, "limit", 50, 1000)
	if err != nil {
		writeError(w, err)
		return
	}
	items := result.Result.Artifacts
	if after > int64(len(items)) {
		writeError(w, store.ErrInvalid)
		return
	}
	end := int(after) + limit
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = cursor(int64(end))
	}
	page := items[int(after):end]
	if page == nil {
		page = []evidence.Artifact{}
	}
	writeJSON(w, 200, map[string]any{"items": page, "next_cursor": next})
}
func (h *handler) artifact(w http.ResponseWriter, r *http.Request, job model.Job, id string) {
	if !job.State.Terminal() {
		writeError(w, controller.ErrNotReady)
		return
	}
	file, artifact, err := h.Artifact(r.Context(), job.ID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	defer file.Close()
	if !artifact.ExpiresAt.IsZero() && !h.Now().Before(artifact.ExpiresAt) {
		writeError(w, controller.ErrExpired)
		return
	}
	// ServeContent handles byte ranges and conditional requests over the sealed
	// descriptor; the client never supplies a filename to the filesystem.
	w.Header().Set("ETag", strconv.Quote(artifact.SHA256))
	w.Header().Set("X-Content-SHA256", artifact.SHA256)
	w.Header().Set("Content-Type", artifact.MediaType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": artifact.Name}))
	response := &contentResponse{ResponseWriter: w}
	http.ServeContent(response, r, artifact.Name, job.UpdatedAt, file)
	if response.failure != 0 {
		w.Header().Del("Content-Length")
		w.Header().Del("Content-Disposition")
		code, message := "content_error", "artifact could not be served"
		if response.failure == http.StatusRequestedRangeNotSatisfiable {
			code, message = "invalid_range", "requested byte range is not satisfiable"
		}
		if response.failure == http.StatusPreconditionFailed {
			code, message = "precondition_failed", "artifact precondition failed"
		}
		writeJSON(w, response.failure, map[string]any{"error": map[string]any{"code": code, "message": message, "retryable": false}, "request_id": w.Header().Get("X-Request-ID")})
	}
}

// Delay only ServeContent errors so its text errors use the API envelope, while
// successful ranges and full responses stream directly without buffering.
type contentResponse struct {
	http.ResponseWriter
	failure int
}

func (w *contentResponse) WriteHeader(status int) {
	if status >= 400 {
		w.failure = status
		return
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *contentResponse) Write(data []byte) (int, error) {
	if w.failure != 0 {
		return len(data), nil
	}
	return w.ResponseWriter.Write(data)
}
