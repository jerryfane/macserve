// Package testflight uploads a signed ios_archive job's App.ipa to App Store
// Connect from the agent side. It holds no Apple key and sends nothing secret
// to macserve: every App Store Connect request carries a short-lived JWT that
// the local keyring relay signs, and the ipa is uploaded only after the
// signer receipt verifies under the signer key macserve publishes.
package testflight

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"
)

// Options configures one upload. API, JobID, Keyring, KeyringRole, AppID and
// ASC are required; the rest default.
type Options struct {
	// API is the macserve base URL that authenticates this agent, e.g. the
	// keyring relay route http://127.0.0.1:7700/<role>/macserve-builds.
	API   string
	JobID string
	// Keyring is the keyring relay base; tokens come from
	// POST <Keyring>/<KeyringRole>/_keyring/sign/appstoreconnect.
	Keyring     string
	KeyringRole string
	// AppID is the numeric App Store Connect app ID.
	AppID string
	// ASC is the App Store Connect API base URL.
	ASC string
	// WorkDir holds the private download directory; "" is os.TempDir().
	WorkDir string
	// HTTPClient sends every request; redirects are never followed. nil is
	// a client without a total timeout (requests are bounded per attempt).
	HTTPClient *http.Client
	// PollInterval spaces build upload state reads (default 15 s).
	PollInterval time.Duration
	// Backoff is the first retry delay, doubled per attempt up to 30 s
	// (default 1 s); Attempts bounds tries per request (default 5).
	Backoff  time.Duration
	Attempts int
	Now      func() time.Time
	// Log receives progress lines; nil discards them.
	Log io.Writer
}

// Evidence binds the verified signer receipt and ipa to the App Store
// Connect build upload and its final state.
type Evidence struct {
	JobID               string        `json:"job_id"`
	SignerReceiptSHA256 string        `json:"signer_receipt_sha256"`
	IPASHA256           string        `json:"ipa_sha256"`
	IPASize             int64         `json:"ipa_size"`
	AppID               string        `json:"app_id"`
	BundleID            string        `json:"bundle_id"`
	BuildName           string        `json:"build_name"`
	BuildNumber         string        `json:"build_number"`
	BuildUploadID       string        `json:"build_upload_id"`
	Resumed             bool          `json:"resumed"`
	FinalState          string        `json:"final_state"`
	StateErrors         []StateDetail `json:"state_errors,omitempty"`
	Error               string        `json:"error,omitempty"`
	StartedAt           time.Time     `json:"started_at"`
	FinishedAt          time.Time     `json:"finished_at"`
}

// StateDetail is one App Store Connect state error or warning.
type StateDetail struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

var (
	jobIDPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	rolePattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	appIDPattern   = regexp.MustCompile(`^[0-9]{1,20}$`)
	errNotComplete = errors.New("build upload did not complete")
)

// Run verifies the job's signed ipa, uploads it (or resumes an existing
// upload of the same app, version and build) and polls the build upload to
// COMPLETE or FAILED. The returned Evidence is filled as far as Run got; its
// BuildUploadID is set once an upload exists, also when Run fails later.
func Run(ctx context.Context, o Options) (Evidence, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	ev := Evidence{JobID: o.JobID, AppID: o.AppID, StartedAt: o.Now().UTC()}
	finish := func(err error) (Evidence, error) {
		ev.FinishedAt = o.Now().UTC()
		if err != nil {
			ev.Error = err.Error()
		}
		return ev, err
	}
	o, apiBase, keyringBase, ascBase, err := o.normalize()
	if err != nil {
		return finish(err)
	}
	retry := retryPolicy{attempts: o.Attempts, backoff: o.Backoff}
	dir, err := os.MkdirTemp(o.WorkDir, "macserve-upload-")
	if err != nil {
		return finish(err)
	}
	defer os.RemoveAll(dir)
	api := &apiClient{base: apiBase, http: o.HTTPClient, retry: retry}
	signed, err := fetchSignedIPA(ctx, api, o.JobID, dir, o.logf)
	if err != nil {
		return finish(err)
	}
	defer signed.file.Close()
	ev.SignerReceiptSHA256, ev.IPASHA256, ev.IPASize = signed.receiptSHA256, signed.sha256, signed.size
	ev.BundleID, ev.BuildName, ev.BuildNumber = signed.bundleID, signed.receipt.BuildName, signed.receipt.BuildNumber
	o.logf("verified job %s: %s %s (%s), ipa sha256 %s, %d bytes", o.JobID, signed.bundleID, ev.BuildName, ev.BuildNumber, ev.IPASHA256, ev.IPASize)

	tokens := &tokenSource{url: keyringBase.JoinPath(o.KeyringRole, "_keyring", "sign", "appstoreconnect").String(), http: o.HTTPClient, now: o.Now, retry: retry}
	asc := &ascClient{base: ascBase, http: o.HTTPClient, tokens: tokens, retry: retry, logf: o.logf}
	if err := asc.checkApp(ctx, o.AppID, signed.bundleID); err != nil {
		return finish(err)
	}
	upload, resumed, err := asc.ensureUpload(ctx, release{appID: o.AppID, version: ev.BuildName, build: ev.BuildNumber})
	record := func(u buildUpload) {
		ev.FinalState = u.state()
		if u.Attributes.State != nil {
			ev.StateErrors = u.Attributes.State.Errors
		}
	}
	if upload.ID != "" {
		ev.BuildUploadID, ev.Resumed = upload.ID, resumed
		record(upload)
	}
	if err != nil {
		return finish(err)
	}
	if resumed {
		o.logf("resuming build upload %s in state %s", upload.ID, upload.state())
	} else {
		o.logf("created build upload %s", upload.ID)
	}
	if err := asc.deliver(ctx, upload, signed); err != nil {
		if errors.Is(err, errUnbound) {
			// Another ipa's state is no evidence for this one.
			ev.FinalState, ev.StateErrors = "", nil
		}
		return finish(err)
	}
	final, err := asc.poll(ctx, upload.ID, o.PollInterval)
	if final.ID != "" {
		record(final)
	}
	if err != nil {
		return finish(fmt.Errorf("build upload %s: last state %s: %w", upload.ID, ev.FinalState, err))
	}
	if ev.FinalState != stateComplete {
		return finish(fmt.Errorf("build upload %s: %s%s: %w", upload.ID, ev.FinalState, describe(ev.StateErrors), errNotComplete))
	}
	return finish(nil)
}

func (o Options) normalize() (Options, *url.URL, *url.URL, *url.URL, error) {
	if !jobIDPattern.MatchString(o.JobID) {
		return o, nil, nil, nil, errors.New("invalid job ID")
	}
	if !rolePattern.MatchString(o.KeyringRole) {
		return o, nil, nil, nil, errors.New("invalid keyring role")
	}
	if !appIDPattern.MatchString(o.AppID) {
		return o, nil, nil, nil, errors.New("app ID must be the numeric App Store Connect app ID")
	}
	var bases [3]*url.URL
	for i, raw := range []string{o.API, o.Keyring, o.ASC} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return o, nil, nil, nil, fmt.Errorf("invalid base URL %q", raw)
		}
		bases[i] = u
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{}
	}
	client := *o.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	o.HTTPClient = &client
	if o.PollInterval <= 0 {
		o.PollInterval = 15 * time.Second
	}
	if o.Backoff <= 0 {
		o.Backoff = time.Second
	}
	if o.Attempts <= 0 {
		o.Attempts = 5
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	return o, bases[0], bases[1], bases[2], nil
}

func (o Options) logf(format string, args ...any) {
	fmt.Fprintf(o.Log, format+"\n", args...)
}

func describe(details []StateDetail) string {
	text := ""
	for _, d := range details {
		text += fmt.Sprintf("; %s: %s", d.Code, d.Description)
	}
	return text
}

// retryPolicy bounds attempts and spaces them with doubling backoff.
type retryPolicy struct {
	attempts int
	backoff  time.Duration
}

// wait sleeps before attempt+1: backoff·2^(attempt-1), at most 30 s, or
// retryAfter when the server named a longer delay (at most 60 s).
func (p retryPolicy) wait(ctx context.Context, attempt int, retryAfter time.Duration) error {
	delay := p.backoff
	for i := 1; i < attempt && delay < 30*time.Second; i++ {
		delay *= 2
	}
	delay = min(delay, 30*time.Second)
	if retryAfter > delay {
		delay = min(retryAfter, time.Minute)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
