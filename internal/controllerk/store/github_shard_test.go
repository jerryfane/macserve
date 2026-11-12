package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A policy matrix run records its shard: a store from before matrices gains
// the column with its runs unsharded, a run's shard must be its request's,
// and runs of one head and profile are told apart by shard.
func TestGitHubRunShard(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE github_runs DROP COLUMN shard"); err != nil {
		t.Fatal(err)
	}
	legacy := githubFixture()
	if _, err := s.db.ExecContext(ctx, "INSERT INTO github_runs(run_key,repository_id,repository,sha,profile,policy_revision) VALUES(?,?,?,?,?,?)", legacy.Run.Key, legacy.Run.RepositoryID, legacy.Run.Repository, legacy.Run.SHA, legacy.Run.Profile, legacy.Run.PolicyRevision); err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeGitHub(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeGitHub(ctx); err != nil {
		t.Fatalf("second initialization: %v", err)
	}
	run, err := s.GitHubRun(ctx, legacy.Run.Key)
	if err != nil || run.Shard != "" || run.Profile != legacy.Run.Profile {
		t.Fatalf("legacy run %+v %v", run, err)
	}
	if run, err = s.AdmitGitHub(ctx, legacy, testNow); err != nil || run.JobID == "" {
		t.Fatalf("legacy run admission %+v %v", run, err)
	}

	mismatched := githubFixture()
	mismatched.Run.Key, mismatched.Run.Shard = strings.Repeat("c", 64), "chat"
	if _, err := s.AdmitGitHub(ctx, mismatched, testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("run shard unlike its request's admitted: %v", err)
	}
	blocked := mismatched.Run
	if err := s.BlockGitHub(ctx, blocked, "no shard", testNow); err != nil {
		t.Fatal(err)
	}
	for shard, key := range map[string]string{"": legacy.Run.Key, "chat": blocked.Key} {
		runs, err := s.GitHubRunsByHead(ctx, 123, "", legacy.Run.SHA, legacy.Run.Profile, shard)
		if err != nil || len(runs) != 1 || runs[0].Key != key || runs[0].Shard != shard {
			t.Fatalf("shard %q: %+v %v", shard, runs, err)
		}
	}
	if runs, err := s.GitHubRunsByHead(ctx, 123, "", legacy.Run.SHA, legacy.Run.Profile, "gram"); err != nil || len(runs) != 0 {
		t.Fatalf("unknown shard: %+v %v", runs, err)
	}
}
