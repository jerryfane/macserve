package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/store"
)

func (h *handler) submit(w http.ResponseWriter, r *http.Request, p store.Principal) {
	var request model.Request
	if err := decode(w, r, &request); err != nil {
		writeError(w, err)
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		writeError(w, store.ErrInvalid)
		return
	}
	if !p.AllowsRepository(request.Repo) {
		writeError(w, ErrForbidden)
		return
	}
	job, err := h.Store.Replay(r.Context(), p.ID, keys[0], request)
	status := http.StatusOK
	if errors.Is(err, store.ErrNotFound) {
		// Only an absent replay may admit new work. Never carry an old
		// snapshot across the readiness check into Enqueue.
		current, statusErr := h.Status(r.Context())
		if statusErr != nil || !current.Gate.Ready {
			writeError(w, errUnavailable)
			return
		}
		var replay bool
		job, replay, err = Submit(r.Context(), h.Store, h.Profiles, p, keys[0], request, h.Now())
		if !replay {
			status = http.StatusAccepted
		}
	}
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Location", "/v1/jobs/"+job.ID)
	h.renderJob(w, r, status, job)
}

func intQuery(r *http.Request, key string, fallback, max int) (int, error) {
	values, exists := r.URL.Query()[key]
	if !exists {
		return fallback, nil
	}
	if len(values) != 1 {
		return 0, store.ErrInvalid
	}
	n, err := strconv.Atoi(values[0])
	if err != nil || n < 1 || n > max {
		return 0, store.ErrInvalid
	}
	return n, nil
}
func (h *handler) list(w http.ResponseWriter, r *http.Request, p store.Principal) {
	limit, err := intQuery(r, "limit", 50, 1000)
	if err != nil {
		writeError(w, err)
		return
	}
	repos := p.Repositories
	if repo := r.URL.Query().Get("repo"); repo != "" {
		if !p.AllowsRepository(repo) {
			writeError(w, store.ErrNotFound)
			return
		}
		repos = []string{strings.ToLower(repo)}
	}
	jobs, next, err := h.Store.List(r.Context(), repos, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeError(w, err)
		return
	}
	blocked := h.blocked(r)
	items := make([]map[string]any, 0, len(jobs))
	for _, job := range jobs {
		view := jobView(job)
		if job.State == model.Queued {
			view["blocked_by"] = blocked
		}
		items = append(items, view)
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func jobView(job model.Job) map[string]any {
	base := "/v1/jobs/" + job.ID
	view := map[string]any{"id": job.ID, "state": job.State, "stage": job.State, "repo": job.Request.Repo, "sha": job.Request.SHA, "kind": job.Request.Kind, "profile": job.Request.Profile, "requested": job.Request, "created_at": job.CreatedAt, "updated_at": job.UpdatedAt, "started_at": job.StartedAt, "finished_at": job.FinishedAt, "deadline": job.Deadline, "timeout_seconds": job.Request.TimeoutSeconds, "cleanup_ok": job.CleanupOK, "cancel_requested": job.CancelRequested, "blocked_by": []string{}, "links": map[string]string{"status": base, "logs": base + "/logs", "results": base + "/results", "artifacts": base + "/artifacts", "receipt": base + "/receipt"}}
	if job.State == model.Failed || job.State == model.TimedOut || job.State == model.Interrupted || job.State == model.Expired {
		view["failure_category"] = job.State
	}
	if len(job.Result) > 0 {
		var completion controller.Completion
		if json.Unmarshal(job.Result, &completion) == nil {
			result := completion.Result
			view["exit_code"] = result.ExitCode
			view["signal"] = result.Signal
			view["resolved"] = map[string]any{"xcode": result.Observation.Xcode, "sdk_version": result.Observation.SDKVersion, "sdk_build": result.Observation.SDKBuild, "runtime_version": result.Observation.RuntimeVersion, "runtime_build": result.Observation.RuntimeBuild, "architecture": result.Observation.Architecture}
		}
	}
	return view
}

func (h *handler) job(w http.ResponseWriter, r *http.Request, p store.Principal) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/jobs/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, store.ErrNotFound)
		return
	}
	job, err := h.Store.Get(r.Context(), parts[0])
	if err != nil {
		writeError(w, err)
		return
	}
	if !p.AllowsRepository(job.Request.Repo) {
		writeError(w, store.ErrNotFound)
		return
	}
	suffix := strings.Join(parts[1:], "/")
	if suffix == "cancel" && r.Method == http.MethodPost {
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decode(w, r, &body); err != nil {
			writeError(w, err)
			return
		}
		previous := job.State
		job, err = h.Store.Cancel(r.Context(), job.ID, body.Reason, h.Now())
		if err != nil {
			writeError(w, err)
			return
		}
		status := 202
		if previous.Terminal() || previous == model.Cancelling || job.State.Terminal() {
			status = 200
		}
		h.renderJob(w, r, status, job)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, store.ErrNotFound)
		return
	}
	switch {
	case suffix == "":
		h.renderJob(w, r, 200, job)
	case suffix == "logs":
		h.logs(w, r, job)
	case suffix == "logs/stream":
		h.stream(w, r, job)
	case suffix == "results" || suffix == "results/junit":
		h.results(w, r, job, suffix == "results/junit")
	case suffix == "artifacts":
		h.artifacts(w, r, job)
	case strings.HasPrefix(suffix, "artifacts/") && len(parts) == 3:
		h.artifact(w, r, job, parts[2])
	case suffix == "receipt":
		if !job.State.Terminal() {
			writeError(w, controller.ErrNotReady)
			return
		}
		receipt, err := h.Receipt(r.Context(), job.ID)
		if err != nil {
			writeError(w, err)
			return
		}
		if len(receipt) == 0 || string(receipt) == "null" {
			writeError(w, controller.ErrNotReady)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(receipt)
	case suffix == "receipt/manifest":
		h.receiptManifest(w, r, job)
	default:
		writeError(w, store.ErrNotFound)
	}
}

func (h *handler) capabilities(w http.ResponseWriter, r *http.Request, p store.Principal) {
	status, err := h.Status(r.Context())
	if err != nil {
		writeError(w, errUnavailable)
		return
	}
	items := []map[string]any{}
	for _, profile := range h.Profiles.List() {
		if !p.AllowsRepository(profile.Repo) {
			continue
		}
		items = append(items, map[string]any{"id": profile.ID, "version": profile.Version, "repo": profile.Repo, "kind": profile.Kind, "xcode": profile.Xcode, "simulator": profile.Simulator, "default_timeout_seconds": profile.DefaultTimeoutSeconds, "max_timeout_seconds": profile.MaxTimeoutSeconds})
	}
	// Do not expose active job IDs, trusted command recipes or filesystem paths.
	blocked := append([]string{}, status.Gate.Blockers...)
	if status.Service.Paused {
		blocked = append(blocked, "manual_pause")
	}
	if status.Service.Quarantined {
		blocked = append(blocked, "quarantined")
	}
	writeJSON(w, 200, map[string]any{"api_version": "v1", "service_version": "development", "repositories": p.Repositories, "profiles": items, "worker_ready": status.WorkerReady, "gui_ready": status.WorkerReady && status.Gate.Ready, "quiescent": status.Quiescent, "blocked_by": blocked, "paused": status.Service.Paused})
}

func (h *handler) blocked(r *http.Request) []string {
	status, err := h.Status(r.Context())
	if err != nil {
		return []string{"service_unavailable"}
	}
	blocked := append([]string{}, status.Gate.Blockers...)
	if status.Service.Paused {
		blocked = append(blocked, "manual_pause")
	}
	if status.Service.Quarantined {
		blocked = append(blocked, "quarantined")
	}
	if !status.WorkerReady {
		blocked = append(blocked, "worker_unavailable")
	}
	return blocked
}

func (h *handler) renderJob(w http.ResponseWriter, r *http.Request, status int, job model.Job) {
	view := jobView(job)
	if job.State == model.Queued {
		view["blocked_by"] = h.blocked(r)
	}
	writeJSON(w, status, view)
}
