package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubwire"
)

// ErrNoGitHubPull refuses a GitHub rerun on a controller without GitHub pull
// mode.
var ErrNoGitHubPull = errors.New("GitHub rerun requires the controller's GitHub pull mode")

// githubRerun is POST /v1/admin/github/rerun (scope service:admin): a
// requested rerun of one pull-mode run, named by repository_id and/or repo,
// sha, profile and, for a policy matrix entry's run, shard. 202 with the new
// attempt; 200 when the latest attempt is still queued or active (nothing
// started).
func (h *handler) githubRerun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RepositoryID int64  `json:"repository_id"`
		Repo         string `json:"repo"`
		SHA          string `json:"sha"`
		Profile      string `json:"profile"`
		Shard        string `json:"shard"`
	}
	if err := decode(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	repo := strings.ToLower(body.Repo)
	if body.RepositoryID < 0 || body.RepositoryID == 0 && repo == "" || repo != "" && !controllerconfig.ValidRepository(repo) || body.SHA == "" || body.Profile == "" {
		writeError(w, store.ErrInvalid)
		return
	}
	if h.GitHubRerun == nil {
		writeError(w, ErrNoGitHubPull)
		return
	}
	run, started, err := h.GitHubRerun(r.Context(), body.RepositoryID, repo, body.SHA, body.Profile, body.Shard, h.Now())
	if err != nil {
		writeError(w, err)
		return
	}
	status := http.StatusOK
	if started {
		status = http.StatusAccepted
	}
	reply := map[string]any{"rerun": started, "run_key": run.Key, "repository_id": run.RepositoryID, "repo": run.Repository, "sha": run.SHA,
		"profile": run.Profile, "check_name": githubwire.CheckName(run.Profile, run.Shard), "job_id": run.JobID, "attempt_id": run.AttemptID}
	if run.Shard != "" {
		reply["shard"] = run.Shard
	}
	writeJSON(w, status, reply)
}
