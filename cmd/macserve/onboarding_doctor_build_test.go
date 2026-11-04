package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/doctor"
	"github.com/jerryfane/macserve/internal/onboarding"
)

func TestDoctorCommandExitCodes(t *testing.T) {
	probe := doctor.Probe{GOOS: "linux"}
	var stdout, stderr bytes.Buffer
	if got := runDoctorWith(probe, []string{"--json"}, &stdout, &stderr); got != 1 {
		t.Errorf("failing host: exit %d", got)
	}
	var r doctor.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil || r.Schema != 1 || len(r.Checks) != len(doctor.IDs) {
		t.Errorf("json %v %+v", err, r)
	}
	for _, args := range [][]string{{"extra"}, {"--sha256", "nothex"}, {"--sha256", strings.Repeat("a", 64), "--sha256sums", "x"}, {"--nope"}} {
		stdout.Reset()
		if got := runDoctorWith(probe, args, &stdout, &stderr); got != 2 || stdout.Len() != 0 {
			t.Errorf("%q: exit %d", args, got)
		}
	}
}

// TestDoctorLiveNeedsRoot: --live is refused without sudo (tests do not
// run as root).
func TestDoctorLiveNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{"doctor", "--live"}, &stdout, &stderr); got != 2 || !strings.Contains(stderr.String(), "needs sudo") {
		t.Errorf("exit %d stderr %q", got, stderr.String())
	}
}

const buildToken = "msv_SECRET_build_token"

func buildTestHost(t *testing.T, handler http.HandlerFunc) buildHost {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	env := "CONTROLLER_USER=buildcontroller\nCONTROLLER_UID=610\nCONTROLLER_GID=610\nJOB_USER=buildjob\nJOB_UID=611\nJOB_GID=611\nOWNER_USER=operatorowner\nOWNER_UID=501\nTAILNET_IP=100.64.0.10\nPORT=9443\nPROTECTED_PORTS=22,9443\nHOST_ADDRESSES=127.0.0.1,::1,100.64.0.10\nDEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer\nREPOSITORIES=jdoe/app:12345\n"
	files := map[string]string{
		deploy.Prefix + "/config/deploy.env":           env,
		deploy.Prefix + "/config/deployment-pins.json": `{"receipt_key_id":"k1","receipt_public_key":"","tls_certificate_sha256":""}`,
	}
	return buildHost{
		readFile: func(path string, _ int64) ([]byte, error) {
			if s, ok := files[path]; ok {
				return []byte(s), nil
			}
			return nil, fs.ErrNotExist
		},
		token: func(context.Context) (string, error) { return buildToken, nil },
		local: func(string) (string, string, []byte, error) {
			return "jdoe/app", strings.Repeat("a", 40), nil, nil
		},
		cwd: func() (string, error) { return "/repo", nil },
		configure: func(b *onboarding.Build) {
			if b.Endpoint != "https://100.64.0.10:9443" {
				t.Errorf("endpoint %s", b.Endpoint)
			}
			b.Endpoint, b.HTTP = srv.URL, srv.Client()
			b.Sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
		},
	}
}

func TestBuildCommand(t *testing.T) {
	var submitted int
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/capabilities":
			io.WriteString(w, `{"templates":[{"id":"org","owners":["jdoe"],"kind":"build","xcode":{"version":"16.2","build":"16C5032a"}}]}`)
		case "/v1/jobs":
			submitted++
			io.WriteString(w, `{"id":"job1","state":"queued"}`)
		case "/v1/jobs/job1":
			io.WriteString(w, `{"id":"job1","state":"failed","exit_code":65}`)
		case "/v1/jobs/job1/logs":
			io.WriteString(w, `{"records":[{"seq":1,"stream":"stdout","text":"error: build failed"}],"next_cursor":"x","eof":true}`)
		default:
			w.WriteHeader(404)
		}
	}
	host := buildTestHost(t, handler)
	var stdout, stderr bytes.Buffer
	if got := runBuildWith(context.Background(), host, nil, &stdout, &stderr); got != 1 {
		t.Errorf("failed job: exit %d stderr %q", got, stderr.String())
	}
	if submitted != 1 || !strings.Contains(stdout.String(), "error: build failed") || !strings.Contains(stdout.String(), "exit code 65") {
		t.Errorf("stdout %q", stdout.String())
	}
	stdout.Reset()
	if got := runBuildWith(context.Background(), host, []string{"--no-follow"}, &stdout, &stderr); got != 0 || !strings.Contains(stdout.String(), "--follow job1") {
		t.Errorf("--no-follow: exit %d %q", got, stdout.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), buildToken) {
		t.Error("token printed")
	}
	// Interrupted: a cancelled context exits 3 and names --follow.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stderr.Reset()
	if got := runBuildWith(ctx, host, []string{"--follow", "job1"}, &stdout, &stderr); got != buildInterrupted || !strings.Contains(stderr.String(), "--follow job1") {
		t.Errorf("interrupted: exit %d %q", got, stderr.String())
	}
	host.local = func(string) (string, string, []byte, error) { return "", "", nil, errors.New("not a repo") }
	if got := runBuildWith(context.Background(), host, nil, &stdout, &stderr); got != 1 {
		t.Errorf("no repo: exit %d", got)
	}
	for _, args := range [][]string{{"extra"}, {"--follow", "job1", "--repo", "a/b"}} {
		if got := runBuildWith(context.Background(), host, args, &stdout, &stderr); got != 2 {
			t.Errorf("%q: exit %d", args, got)
		}
	}
}
