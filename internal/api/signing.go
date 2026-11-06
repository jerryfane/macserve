package api

import (
	"errors"
	"net/http"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/store"
)

// sign is POST /v1/jobs/<id>/sign (scope release:sign, checked by
// ServeHTTP): the job's own principal or an admin starts signing a
// succeeded ios_archive job. Idempotent: 202 while signing (started now or
// before), 200 once signed; a failed signing is retried.
func (h *handler) sign(w http.ResponseWriter, r *http.Request, p store.Principal, job model.Job) {
	if p.ID != job.Principal && !p.HasScope("service:admin") {
		writeError(w, ErrForbidden)
		return
	}
	if h.Sign == nil {
		writeError(w, controller.ErrSigningUnavailable)
		return
	}
	if job.Request.Kind != model.IOSArchive {
		writeError(w, store.ErrInvalid)
		return
	}
	if !job.State.Terminal() {
		writeError(w, controller.ErrNotReady)
		return
	}
	record, err := h.Sign(r.Context(), job.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	status := http.StatusAccepted
	if record.Status == store.Signed {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"job_id": job.ID, "state": job.State, "signing": signingView(job.ID, record)})
}

// signing is GET /v1/jobs/<id>/signing: the job's signing sub-status.
func (h *handler) signing(w http.ResponseWriter, r *http.Request, job model.Job) {
	if job.Request.Kind != model.IOSArchive {
		writeError(w, store.ErrNotFound)
		return
	}
	record, err := h.Store.GetSigning(r.Context(), job.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, store.ErrNotFound)
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job_id": job.ID, "state": job.State, "signing": signingView(job.ID, record)})
}

// signingView is a signing record with each stored artifact's download
// link (served by the job's artifacts route).
func signingView(id string, record store.SigningRecord) map[string]any {
	view := map[string]any{"status": record.Status, "started_at": record.StartedAt, "updated_at": record.UpdatedAt}
	if record.Reason != "" {
		view["reason"] = record.Reason
	}
	if record.Status == store.Signed {
		artifacts := make([]map[string]any, 0, len(record.Artifacts))
		for _, a := range record.Artifacts {
			artifacts = append(artifacts, map[string]any{"id": a.ID, "name": a.Name, "media_type": a.MediaType, "size_bytes": a.SizeBytes, "sha256": a.SHA256, "expires_at": a.ExpiresAt, "url": "/v1/jobs/" + id + "/artifacts/" + a.ID})
		}
		view["artifacts"] = artifacts
	}
	return view
}
