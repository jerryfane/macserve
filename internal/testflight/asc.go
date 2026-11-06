package testflight

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// App Store Connect Build Upload API (WWDC25), App Store Connect API 4.x:
//
//	GET   /v1/apps/{id}                           https://developer.apple.com/documentation/appstoreconnectapi/get-v1-apps-_id_
//	GET   /v1/apps/{id}/buildUploads              https://developer.apple.com/documentation/appstoreconnectapi/get-v1-apps-_id_-builduploads
//	POST  /v1/buildUploads                        https://developer.apple.com/documentation/appstoreconnectapi/post-v1-builduploads
//	GET   /v1/buildUploads/{id}/buildUploadFiles  https://developer.apple.com/documentation/appstoreconnectapi/get-v1-builduploads-_id_-builduploadfiles
//	POST  /v1/buildUploadFiles                    https://developer.apple.com/documentation/appstoreconnectapi/post-v1-builduploadfiles
//	PATCH /v1/buildUploadFiles/{id}               https://developer.apple.com/documentation/appstoreconnectapi/patch-v1-builduploadfiles-_id_
//	GET   /v1/buildUploads/{id}                   https://developer.apple.com/documentation/appstoreconnectapi/get-v1-builduploads-_id_
//
// Upload operations (method, url, offset, length, requestHeaders) and the
// MD5 sourceFileChecksum convention follow
// https://developer.apple.com/documentation/appstoreconnectapi/uploading-assets-to-app-store-connect;
// states are https://developer.apple.com/documentation/appstoreconnectapi/builduploadstate.
const (
	stateAwaitingUpload = "AWAITING_UPLOAD"
	stateProcessing     = "PROCESSING"
	stateComplete       = "COMPLETE"
	stateFailed         = "FAILED"
	// assetDeliveryState once committed (AppMediaAssetState).
	fileUploadComplete = "UPLOAD_COMPLETE"

	platformIOS = "IOS"
	ipaUTI      = "com.apple.ipa"
	assetType   = "ASSET"

	maxASCBody   = 4 << 20
	maxListPages = 20
	ascAttempt   = 2 * time.Minute
	partAttempt  = 30 * time.Minute
)

type release struct{ appID, version, build string }

type buildUpload struct {
	ID         string `json:"id"`
	Attributes struct {
		CFBundleShortVersionString string     `json:"cfBundleShortVersionString"`
		CFBundleVersion            string     `json:"cfBundleVersion"`
		Platform                   string     `json:"platform"`
		CreatedDate                *time.Time `json:"createdDate"`
		State                      *struct {
			State    string        `json:"state"`
			Errors   []StateDetail `json:"errors"`
			Warnings []StateDetail `json:"warnings"`
		} `json:"state"`
	} `json:"attributes"`
}

func (u buildUpload) state() string {
	if u.Attributes.State == nil {
		return ""
	}
	return u.Attributes.State.State
}

type uploadFile struct {
	ID         string `json:"id"`
	Attributes struct {
		AssetDeliveryState *struct {
			State  string        `json:"state"`
			Errors []StateDetail `json:"errors"`
		} `json:"assetDeliveryState"`
		AssetType           string      `json:"assetType"`
		FileName            string      `json:"fileName"`
		FileSize            int64       `json:"fileSize"`
		UTI                 string      `json:"uti"`
		SourceFileChecksums *checksums  `json:"sourceFileChecksums"`
		UploadOperations    []operation `json:"uploadOperations"`
	} `json:"attributes"`
}

func (f uploadFile) state() string {
	if f.Attributes.AssetDeliveryState == nil {
		return ""
	}
	return f.Attributes.AssetDeliveryState.State
}

type checksums struct {
	File *checksum `json:"file,omitempty"`
}

type checksum struct {
	Hash      string `json:"hash"`
	Algorithm string `json:"algorithm"`
}

// operation is a DeliveryFileUploadOperation.
type operation struct {
	Method         string `json:"method"`
	URL            string `json:"url"`
	Offset         int64  `json:"offset"`
	Length         int64  `json:"length"`
	RequestHeaders []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"requestHeaders"`
}

// statusError is a non-2xx response. Its text is the service's error
// response at most, never a token or a pre-signed URL.
type statusError struct {
	service, method, route string
	status                 int
	detail                 string
	retryAfter             time.Duration
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s %s %s: HTTP %d%s", e.service, e.method, e.route, e.status, e.detail)
}

func statusOf(err error) int {
	var e *statusError
	if errors.As(err, &e) {
		return e.status
	}
	return 0
}

// transient reports an error worth another attempt: no response (including
// a per-attempt timeout; callers stop once their own context ends) or 5xx.
// Keyring failures were already retried by tokenSource.
func transient(err error) bool {
	var k *keyringError
	if errors.As(err, &k) {
		return false
	}
	status := statusOf(err)
	return status == 0 && !errors.Is(err, context.Canceled) || status >= 500
}

// stripURL drops the request URL from a transport error.
func stripURL(err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err
	}
	return err
}

type ascClient struct {
	base   *url.URL
	http   *http.Client
	tokens *tokenSource
	retry  retryPolicy
	logf   func(string, ...any)
}

// do sends one JSON:API request to App Store Connect with a fresh keyring
// JWT and decodes a 2xx body into out. A 401 refreshes the JWT and resends
// once. Transient failures (no response, 5xx) are resent with backoff only
// when idempotent; any other 4xx fails at once.
func (c *ascClient) do(ctx context.Context, method, target string, body, out any, idempotent bool) error {
	u, err := c.resolve(target)
	if err != nil {
		return err
	}
	route := u.Path
	var payload []byte
	if body != nil {
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	refreshed := false
	for attempt := 1; ; attempt++ {
		err := c.once(ctx, method, u.String(), route, payload, out)
		switch {
		case err == nil:
			return nil
		case statusOf(err) == http.StatusUnauthorized && !refreshed:
			// An expired or rejected JWT: the request was not processed.
			refreshed = true
			c.tokens.invalidate()
			c.logf("App Store Connect %s %s: 401, refreshing the keyring token once", method, route)
			attempt--
			continue
		case !idempotent || !transient(err) || attempt >= c.retry.attempts || ctx.Err() != nil:
			return err
		}
		c.logf("%v; retrying (%d/%d)", err, attempt, c.retry.attempts)
		if err := c.retry.wait(ctx, attempt, retryAfter(err)); err != nil {
			return err
		}
	}
}

// resolve accepts a route or a links.next URL on the App Store Connect
// origin only: the JWT never leaves it.
func (c *ascClient) resolve(target string) (*url.URL, error) {
	if strings.HasPrefix(target, "/") {
		u := *c.base
		ref, err := url.Parse(target)
		if err != nil {
			return nil, err
		}
		u.Path = strings.TrimSuffix(c.base.Path, "/") + ref.Path
		u.RawPath = ""
		u.RawQuery = ref.RawQuery
		return &u, nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != c.base.Scheme || u.Host != c.base.Host || u.User != nil || u.Fragment != "" || !strings.HasPrefix(u.Path, strings.TrimSuffix(c.base.Path, "/")+"/v1/") {
		return nil, fmt.Errorf("App Store Connect returned a link outside its API: %q", clean(target))
	}
	return u, nil
}

func (c *ascClient) once(ctx context.Context, method, target, route string, payload []byte, out any) error {
	token, err := c.tokens.get(ctx)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, ascAttempt)
	defer cancel()
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("App Store Connect %s %s: %w", method, route, stripURL(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxASCBody+1))
	if err == nil && len(raw) > maxASCBody {
		err = errors.New("response too large")
	}
	if err != nil {
		return fmt.Errorf("App Store Connect %s %s: %w", method, route, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &statusError{service: "App Store Connect", method: method, route: route, status: resp.StatusCode, detail: ascErrorDetail(raw)}
		if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
			e.retryAfter = time.Duration(seconds) * time.Second
		}
		return e
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("App Store Connect %s %s: invalid JSON: %w", method, route, err)
		}
	}
	return nil
}

// retryAfter is a 5xx response's Retry-After delay, if any.
func retryAfter(err error) time.Duration {
	var e *statusError
	if errors.As(err, &e) {
		return e.retryAfter
	}
	return 0
}

// ascErrorDetail renders an ErrorResponse's errors on one bounded line.
func ascErrorDetail(raw []byte) string {
	var response struct {
		Errors []struct {
			Code   string `json:"code"`
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &response) != nil || len(response.Errors) == 0 {
		return ""
	}
	parts := make([]string, 0, len(response.Errors))
	for _, e := range response.Errors {
		parts = append(parts, e.Code+": "+e.Title+" "+e.Detail)
	}
	return ": " + clean(strings.Join(parts, "; "))
}

// checkApp requires the App Store Connect app to be the signed bundle's.
func (c *ascClient) checkApp(ctx context.Context, appID, bundleID string) error {
	var app struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				BundleID string `json:"bundleId"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/apps/"+appID+"?fields%5Bapps%5D=bundleId", nil, &app, true); err != nil {
		return err
	}
	if app.Data.ID != appID || app.Data.Attributes.BundleID != bundleID {
		return fmt.Errorf("App Store Connect app %s has bundle ID %q, the signed ipa %q", appID, app.Data.Attributes.BundleID, bundleID)
	}
	return nil
}

// findUpload lists the app's build uploads for this version and build on
// IOS (filtered server-side and again here) and picks the one to resume:
// COMPLETE, else PROCESSING, else the newest AWAITING_UPLOAD; with only
// FAILED uploads it returns the newest FAILED one.
func (c *ascClient) findUpload(ctx context.Context, r release) (buildUpload, bool, error) {
	query := url.Values{
		"filter[cfBundleShortVersionString]": {r.version},
		"filter[cfBundleVersion]":            {r.build},
		"filter[platform]":                   {platformIOS},
		"limit":                              {"200"},
	}
	next := "/v1/apps/" + r.appID + "/buildUploads?" + query.Encode()
	var matches []buildUpload
	for page := 0; next != ""; page++ {
		if page == maxListPages {
			return buildUpload{}, false, errors.New("App Store Connect lists too many build uploads for this version")
		}
		var list struct {
			Data  []buildUpload `json:"data"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if err := c.do(ctx, http.MethodGet, next, nil, &list, true); err != nil {
			return buildUpload{}, false, err
		}
		for _, u := range list.Data {
			a := u.Attributes
			if u.ID != "" && a.CFBundleShortVersionString == r.version && a.CFBundleVersion == r.build && a.Platform == platformIOS {
				matches = append(matches, u)
			}
		}
		next = list.Links.Next
	}
	if len(matches) == 0 {
		return buildUpload{}, false, nil
	}
	rank := map[string]int{stateComplete: 0, stateProcessing: 1, stateAwaitingUpload: 2, stateFailed: 3}
	slices.SortStableFunc(matches, func(a, b buildUpload) int {
		ra, ok := rank[a.state()]
		if !ok {
			ra = 2
		}
		rb, ok := rank[b.state()]
		if !ok {
			rb = 2
		}
		if ra != rb {
			return ra - rb
		}
		return created(b).Compare(created(a))
	})
	return matches[0], true, nil
}

func created(u buildUpload) time.Time {
	if u.Attributes.CreatedDate == nil {
		return time.Time{}
	}
	return *u.Attributes.CreatedDate
}

// ensureUpload resumes the app's existing build upload for this version and
// build or creates one. Creation is never blindly resent: after a lost
// response, a 5xx or a 409 it lists again and resumes what exists.
func (c *ascClient) ensureUpload(ctx context.Context, r release) (buildUpload, bool, error) {
	var conflict error
	for attempt := 1; ; attempt++ {
		existing, found, err := c.findUpload(ctx, r)
		if err != nil {
			return buildUpload{}, false, err
		}
		if found {
			if existing.state() == stateFailed {
				return existing, true, fmt.Errorf("build upload %s for %s (%s) already FAILED%s; delete it in App Store Connect or archive a new build number", existing.ID, r.version, r.build, describe(existing.Attributes.State.Errors))
			}
			return existing, true, nil
		}
		if conflict != nil {
			return buildUpload{}, false, conflict
		}
		body := map[string]any{"data": map[string]any{
			"type":          "buildUploads",
			"attributes":    map[string]any{"cfBundleShortVersionString": r.version, "cfBundleVersion": r.build, "platform": platformIOS},
			"relationships": map[string]any{"app": map[string]any{"data": map[string]any{"type": "apps", "id": r.appID}}},
		}}
		var created struct {
			Data buildUpload `json:"data"`
		}
		err = c.do(ctx, http.MethodPost, "/v1/buildUploads", body, &created, false)
		switch {
		case err == nil && created.Data.ID != "":
			return created.Data, false, nil
		case err == nil:
			return buildUpload{}, false, errors.New("App Store Connect created a build upload without an ID")
		case statusOf(err) == http.StatusConflict:
			conflict = err
			continue
		case !transient(err) || attempt >= c.retry.attempts || ctx.Err() != nil:
			return buildUpload{}, false, err
		}
		c.logf("%v; listing build uploads before creating again (%d/%d)", err, attempt, c.retry.attempts)
		if err := c.retry.wait(ctx, attempt, retryAfter(err)); err != nil {
			return buildUpload{}, false, err
		}
	}
}

// deliver uploads and commits the ipa. A build upload already past
// AWAITING_UPLOAD is not touched, but its listed ipa file must have this
// ipa's size and, when it carries one, its checksum.
func (c *ascClient) deliver(ctx context.Context, upload buildUpload, ipa *signedIPA) error {
	if s := upload.state(); s == stateProcessing || s == stateComplete {
		file, found, err := c.findFile(ctx, upload.ID, ipa)
		if err == nil && !found {
			err = fmt.Errorf("build upload %s is %s but lists no ipa file to compare with this one", upload.ID, s)
		}
		if err == nil {
			_, err = commitChecksums(file, ipa)
		}
		return err
	}
	file, err := c.ensureFile(ctx, upload.ID, ipa)
	if err != nil {
		return err
	}
	commit, err := commitChecksums(file, ipa)
	if err != nil {
		return err
	}
	switch file.state() {
	case fileUploadComplete, stateComplete:
		c.logf("build upload file %s is already committed", file.ID)
		return nil
	case stateFailed:
		return fmt.Errorf("build upload file %s FAILED%s", file.ID, describe(file.Attributes.AssetDeliveryState.Errors))
	}
	if err := c.upload(ctx, file, ipa); err != nil {
		return err
	}
	body := map[string]any{"data": map[string]any{
		"type":       "buildUploadFiles",
		"id":         file.ID,
		"attributes": map[string]any{"uploaded": true, "sourceFileChecksums": commit},
	}}
	err = c.do(ctx, http.MethodPatch, "/v1/buildUploadFiles/"+file.ID, body, nil, true)
	if err == nil || ctx.Err() != nil {
		return err
	}
	// A commit that App Store Connect already applied (a lost response
	// resent, or an earlier run) is refused; accept it only once the build
	// upload reports processing.
	var current struct {
		Data buildUpload `json:"data"`
	}
	if lookup := c.do(ctx, http.MethodGet, "/v1/buildUploads/"+upload.ID, nil, &current, true); lookup == nil {
		if s := current.Data.state(); s == stateProcessing || s == stateComplete {
			return nil
		}
	}
	return err
}

// findFile returns the build upload's ipa file reservation, which must be
// for an ipa of this size.
func (c *ascClient) findFile(ctx context.Context, uploadID string, ipa *signedIPA) (uploadFile, bool, error) {
	var list struct {
		Data []uploadFile `json:"data"`
	}
	route := "/v1/buildUploads/" + uploadID + "/buildUploadFiles?fields%5BbuildUploadFiles%5D=assetDeliveryState,assetType,fileName,fileSize,sourceFileChecksums,uploadOperations,uti&limit=50"
	if err := c.do(ctx, http.MethodGet, route, nil, &list, true); err != nil {
		return uploadFile{}, false, err
	}
	for _, f := range list.Data {
		if f.Attributes.AssetType != assetType || f.Attributes.UTI != ipaUTI {
			continue
		}
		if f.Attributes.FileSize != ipa.size {
			return uploadFile{}, false, fmt.Errorf("build upload %s already holds a %d-byte ipa, not this %d-byte one", uploadID, f.Attributes.FileSize, ipa.size)
		}
		return f, true, nil
	}
	return uploadFile{}, false, nil
}

// ensureFile returns the build upload's ipa file reservation, creating it
// when there is none. Like ensureUpload it lists again rather than resend a
// creation that may have been applied.
func (c *ascClient) ensureFile(ctx context.Context, uploadID string, ipa *signedIPA) (uploadFile, error) {
	var conflict error
	for attempt := 1; ; attempt++ {
		existing, found, err := c.findFile(ctx, uploadID, ipa)
		if err != nil {
			return uploadFile{}, err
		}
		if found {
			c.logf("resuming build upload file %s in state %s", existing.ID, existing.state())
			return existing, nil
		}
		if conflict != nil {
			return uploadFile{}, conflict
		}
		body := map[string]any{"data": map[string]any{
			"type":          "buildUploadFiles",
			"attributes":    map[string]any{"fileName": "App.ipa", "fileSize": ipa.size, "uti": ipaUTI, "assetType": assetType},
			"relationships": map[string]any{"buildUpload": map[string]any{"data": map[string]any{"type": "buildUploads", "id": uploadID}}},
		}}
		var created struct {
			Data uploadFile `json:"data"`
		}
		err = c.do(ctx, http.MethodPost, "/v1/buildUploadFiles", body, &created, false)
		switch {
		case err == nil && created.Data.ID != "":
			return created.Data, nil
		case err == nil:
			return uploadFile{}, errors.New("App Store Connect reserved a build upload file without an ID")
		case statusOf(err) == http.StatusConflict:
			conflict = err
			continue
		case !transient(err) || attempt >= c.retry.attempts || ctx.Err() != nil:
			return uploadFile{}, err
		}
		c.logf("%v; listing build upload files before reserving again (%d/%d)", err, attempt, c.retry.attempts)
		if err := c.retry.wait(ctx, attempt, retryAfter(err)); err != nil {
			return uploadFile{}, err
		}
	}
}

// commitChecksums is the commit's sourceFileChecksums: the whole ipa's
// file checksum in the algorithm the reservation names (SHA_256 or MD5),
// MD5 when it names none, as Apple's upload guide specifies for
// sourceFileChecksum. A hash the reservation already carries must be ours.
func commitChecksums(file uploadFile, ipa *signedIPA) (checksums, error) {
	algorithm := "MD5"
	if c := file.Attributes.SourceFileChecksums; c != nil && c.File != nil && c.File.Algorithm != "" {
		algorithm = c.File.Algorithm
	}
	sums := map[string]string{"MD5": ipa.md5, "SHA_256": ipa.sha256}
	hash, ok := sums[algorithm]
	if !ok {
		return checksums{}, fmt.Errorf("build upload file %s asks for unsupported checksum algorithm %q", file.ID, clean(algorithm))
	}
	if c := file.Attributes.SourceFileChecksums; c != nil && c.File != nil && c.File.Hash != "" && !strings.EqualFold(c.File.Hash, hash) {
		return checksums{}, fmt.Errorf("build upload file %s carries %s %s, not this ipa's %s", file.ID, algorithm, clean(c.File.Hash), hash)
	}
	return checksums{File: &checksum{Hash: hash, Algorithm: algorithm}}, nil
}

// upload runs every upload operation, in offset order, sending exactly its
// byte range with exactly its request headers and no JWT (the URLs are
// pre-signed). The operations must cover the ipa without gaps or overlap.
func (c *ascClient) upload(ctx context.Context, file uploadFile, ipa *signedIPA) error {
	ops := slices.Clone(file.Attributes.UploadOperations)
	if len(ops) == 0 {
		return fmt.Errorf("build upload file %s has no upload operations (its reservation may have expired; delete the build upload and rerun)", file.ID)
	}
	slices.SortStableFunc(ops, func(a, b operation) int { return cmp.Compare(a.Offset, b.Offset) })
	var covered int64
	for i, op := range ops {
		u, err := url.Parse(op.URL)
		switch {
		case err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && c.base.Scheme == "http")):
			return fmt.Errorf("upload operation %d has an invalid URL", i+1)
		case op.Method == "" || strings.ToUpper(op.Method) != op.Method || strings.ContainsAny(op.Method, " \t\r\n"):
			return fmt.Errorf("upload operation %d has an invalid method %q", i+1, clean(op.Method))
		case op.Offset != covered || op.Length <= 0 || op.Length > ipa.size-op.Offset:
			return fmt.Errorf("upload operations do not cover the %d-byte ipa exactly (operation %d: offset %d, length %d)", ipa.size, i+1, op.Offset, op.Length)
		}
		covered += op.Length
	}
	if covered != ipa.size {
		return fmt.Errorf("upload operations cover %d of %d bytes", covered, ipa.size)
	}
	for i, op := range ops {
		c.logf("uploading part %d/%d: offset %d, %d bytes", i+1, len(ops), op.Offset, op.Length)
		if err := c.part(ctx, op, ipa); err != nil {
			return fmt.Errorf("upload operation %d/%d: %w", i+1, len(ops), err)
		}
	}
	return nil
}

func (c *ascClient) part(ctx context.Context, op operation, ipa *signedIPA) error {
	for attempt := 1; ; attempt++ {
		err := func() error {
			ctx, cancel := context.WithTimeout(ctx, partAttempt)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, op.Method, op.URL, io.NewSectionReader(ipa.file, op.Offset, op.Length))
			if err != nil {
				return err
			}
			req.ContentLength = op.Length
			for _, h := range op.RequestHeaders {
				if strings.EqualFold(h.Name, "Host") {
					req.Host = h.Value
					continue
				}
				req.Header[http.CanonicalHeaderKey(h.Name)] = append(req.Header[http.CanonicalHeaderKey(h.Name)], h.Value)
			}
			resp, err := c.http.Do(req)
			if err != nil {
				// Never echo the pre-signed URL.
				return fmt.Errorf("%s: %w", op.Method, stripURL(err))
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				return &statusError{service: "upload", method: op.Method, route: "(pre-signed URL)", status: resp.StatusCode}
			}
			return nil
		}()
		if err == nil || !transient(err) || attempt >= c.retry.attempts || ctx.Err() != nil {
			return err
		}
		c.logf("%v; retrying (%d/%d)", err, attempt, c.retry.attempts)
		if err := c.retry.wait(ctx, attempt, 0); err != nil {
			return err
		}
	}
}

// poll reads the build upload until COMPLETE or FAILED, returning the last
// state read (also on a deadline).
func (c *ascClient) poll(ctx context.Context, id string, interval time.Duration) (buildUpload, error) {
	var last buildUpload
	previous := ""
	for {
		var current struct {
			Data buildUpload `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, "/v1/buildUploads/"+id, nil, &current, true); err != nil {
			return last, err
		}
		last = current.Data
		if s := last.state(); s != previous {
			c.logf("build upload %s: %s", id, s)
			previous = s
		}
		if s := last.state(); s == stateComplete || s == stateFailed {
			return last, nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return last, ctx.Err()
		case <-timer.C:
		}
	}
}
