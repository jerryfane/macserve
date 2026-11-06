package testflight

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/signer"
)

const (
	testJob      = "job_0123456789abcdef"
	testRepo     = "example-org/example-app"
	testAppID    = "6760713318"
	testBundleID = "com.example.app"
	testVersion  = "2.0.1"
	testBuild    = "17"
	testRole     = "example-role"
)

var testCommit = strings.Repeat("c", 40)

// clock is a settable test clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// fixture is a signed job served by a fake macserve, a fake keyring relay
// and a fake App Store Connect with its pre-signed storage URLs.
type fixture struct {
	t     *testing.T
	clock *clock

	signerKey  ed25519.PrivateKey
	jobReceipt []byte
	ipa        []byte
	payload    signer.ReceiptPayload
	// receiptKey signs the signer receipt; signerKey is what capabilities
	// publish.
	receiptKey ed25519.PrivateKey
	// served replaces the ipa bytes macserve serves; listedSize replaces
	// the signing record's App.ipa size.
	served     []byte
	listedSize int64

	macserve, keyring, asc *httptest.Server
	ascState               *fakeASC
	keyringCalls           int
	keyringTTL             time.Duration
	mu                     sync.Mutex
}

func newFixture(t *testing.T, infoPlist []byte) *fixture {
	t.Helper()
	_, signerKey, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{t: t, clock: &clock{now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}, signerKey: signerKey, receiptKey: signerKey, keyringTTL: 20 * time.Minute}
	f.jobReceipt = []byte(`{"payload":{"job_id":"` + testJob + `"},"signature":{}}`)
	f.ipa = buildIPA(t, "Example.app", infoPlist)
	f.payload = signer.ReceiptPayload{
		Schema: signer.ReceiptSchema, JobID: testJob, JobReceiptSHA256: hexSHA256(f.jobReceipt),
		Repository: signer.RepositoryRef{ID: 42, Name: testRepo}, Commit: testCommit, BuildName: testVersion, BuildNumber: testBuild,
		Archive:               signer.DigestRef{Name: "App.xcarchive.tar", SHA256: strings.Repeat("a", 64), SizeBytes: 1024},
		SigningManifestSHA256: strings.Repeat("b", 64), IdentitySHA1: strings.Repeat("A", 40), TeamID: "ABCDE12345",
		IPA:     signer.DigestRef{Name: signer.IPAArtifact, SHA256: hexSHA256(f.ipa), SizeBytes: int64(len(f.ipa))},
		Bundles: []signer.SignedBundle{{Path: "Products/Applications/Example.app", BundleID: testBundleID, ProfileUUID: "8A464E05-BF03-7AF2-4322-00C8687455FC", ProfileSHA256: strings.Repeat("d", 64), EntitlementsSHA256: strings.Repeat("e", 64)}},
		Dylibs:  []string{}, SignedAt: time.Unix(1, 0).UTC(), Signer: signer.SignerReference{KeyID: "signer-1"},
	}
	f.ascState = newFakeASC(t, f)
	f.macserve = httptest.NewServer(http.HandlerFunc(f.serveMacserve))
	f.keyring = httptest.NewServer(http.HandlerFunc(f.serveKeyring))
	f.asc = httptest.NewServer(f.ascState)
	t.Cleanup(func() { f.macserve.Close(); f.keyring.Close(); f.asc.Close() })
	return f
}

func (f *fixture) options() Options {
	return Options{
		API: f.macserve.URL + "/" + testRole + "/macserve-builds", JobID: testJob,
		Keyring: f.keyring.URL, KeyringRole: testRole, AppID: testAppID, ASC: f.asc.URL,
		WorkDir: f.t.TempDir(), PollInterval: time.Millisecond, Backoff: time.Millisecond, Attempts: 3,
		Now: f.clock.Now,
	}
}

func (f *fixture) run() (Evidence, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return Run(ctx, f.options())
}

func (f *fixture) signerReceipt() []byte {
	raw, _ := json.Marshal(f.payload)
	canonical, err := receipt.Canonical(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	envelope, _ := json.Marshal(receipt.Envelope{Payload: canonical, Signature: receipt.Signature{Algorithm: "Ed25519", KeyID: f.payload.Signer.KeyID, Encoding: "base64", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(f.receiptKey, canonical))}})
	out, err := receipt.Canonical(envelope)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *fixture) serveMacserve(w http.ResponseWriter, r *http.Request) {
	prefix := "/" + testRole + "/macserve-builds"
	route, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok || r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
		http.Error(w, "unexpected", http.StatusTeapot)
		return
	}
	signed := f.signerReceipt()
	ipa := f.ipa
	if f.served != nil {
		ipa = f.served
	}
	size := int64(len(f.ipa))
	if f.listedSize != 0 {
		size = f.listedSize
	}
	ipaID, receiptID := hexSHA256(f.ipa), hexSHA256(signed)
	job := "/v1/jobs/" + testJob
	switch route {
	case "/v1/capabilities":
		writeJSON(w, map[string]any{"api_version": "v1", "signer": map[string]any{"key_id": "signer-1", "public_key": base64.StdEncoding.EncodeToString(f.signerKey.Public().(ed25519.PublicKey))}})
	case job:
		writeJSON(w, map[string]any{"id": testJob, "state": "succeeded", "kind": "ios_archive", "repo": testRepo, "sha": testCommit, "requested": map[string]any{"repo": testRepo, "sha": testCommit, "kind": "ios_archive", "release": map[string]any{"build_name": testVersion, "build_number": testBuild}}})
	case job + "/signing":
		writeJSON(w, map[string]any{"job_id": testJob, "state": "succeeded", "signing": map[string]any{"status": "signed", "artifacts": []map[string]any{
			{"id": ipaID, "name": "App.ipa", "media_type": "application/octet-stream", "size_bytes": size, "sha256": ipaID, "url": job + "/artifacts/" + ipaID},
			{"id": receiptID, "name": "signer-receipt.json", "media_type": "application/json", "size_bytes": len(signed), "sha256": receiptID, "url": job + "/artifacts/" + receiptID},
		}}})
	case job + "/receipt":
		w.Write(f.jobReceipt)
	case job + "/artifacts/" + ipaID:
		w.Write(ipa)
	case job + "/artifacts/" + receiptID:
		w.Write(signed)
	default:
		http.Error(w, `{"error":{"code":"not_found","message":"not found"}}`, http.StatusNotFound)
	}
}

func (f *fixture) serveKeyring(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/"+testRole+"/_keyring/sign/appstoreconnect" {
		http.Error(w, "unexpected", http.StatusTeapot)
		return
	}
	if body, _ := io.ReadAll(r.Body); len(body) != 0 {
		http.Error(w, "body", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.keyringCalls++
	token := fmt.Sprintf("jwt-%d", f.keyringCalls)
	f.mu.Unlock()
	expires := f.clock.Now().Add(f.keyringTTL)
	f.ascState.issue(token, expires)
	writeJSON(w, map[string]any{"token": token, "expires_at": expires.Format(time.RFC3339)})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// fakeASC is App Store Connect's Build Upload API and its storage.
type fakeASC struct {
	t  *testing.T
	f  *fixture
	mu sync.Mutex

	tokens       map[string]time.Time
	minRemaining time.Duration
	unauthorized int
	// reject401 answers 401 to the next n ASC requests regardless of token.
	reject401 int
	// step advances the clock after every ASC request.
	step time.Duration

	uploads []*fakeUpload
	files   map[string][]*fakeFile
	nextID  int
	// parts are the bytes received per operation offset.
	parts map[int64][]byte
	// partStatus queues statuses for an operation index before 200.
	partStatus map[int][]int
	partCalls  map[int]int
	// getStatus queues statuses for GET /v1/buildUploads/{id}.
	getStatus []int
	// final is the state processing ends in; processingPolls reads stay
	// PROCESSING first.
	final           string
	finalErrors     []StateDetail
	processingPolls int
	opsPerFile      int

	log    []string
	bodies map[string][]string
}

type fakeUpload struct {
	id, version, build, platform, state string
	created                             time.Time
	errors                              []StateDetail
	polls                               int
}

type fakeFile struct {
	id, state string
	size      int64
	ops       []map[string]any
	checksum  map[string]any
}

func newFakeASC(t *testing.T, f *fixture) *fakeASC {
	return &fakeASC{t: t, f: f, tokens: map[string]time.Time{}, minRemaining: time.Duration(1 << 62), files: map[string][]*fakeFile{}, parts: map[int64][]byte{}, partStatus: map[int][]int{}, partCalls: map[int]int{}, final: stateComplete, processingPolls: 1, opsPerFile: 3, bodies: map[string][]string{}}
}

func (a *fakeASC) issue(token string, expires time.Time) {
	a.mu.Lock()
	a.tokens[token] = expires
	a.mu.Unlock()
}

func (a *fakeASC) id(prefix string) string {
	a.nextID++
	return fmt.Sprintf("%s-%d", prefix, a.nextID)
}

func (a *fakeASC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if index, ok := strings.CutPrefix(r.URL.Path, "/storage/part/"); ok {
		a.servePart(w, r, index)
		return
	}
	defer a.f.clock.advance(a.step)
	a.log = append(a.log, r.Method+" "+r.URL.Path)
	expires, ok := a.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	remaining := expires.Sub(a.f.clock.Now())
	if !ok || remaining <= 0 || a.reject401 > 0 {
		if a.reject401 > 0 {
			a.reject401--
		}
		a.unauthorized++
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errors":[{"status":"401","code":"NOT_AUTHORIZED","title":"Authentication credentials are missing or invalid.","detail":"Provide a properly configured and signed bearer token."}]}`))
		return
	}
	a.minRemaining = min(a.minRemaining, remaining)
	var body map[string]any
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			a.bodies[r.Method+" "+r.URL.Path] = append(a.bodies[r.Method+" "+r.URL.Path], string(raw))
			if err := json.Unmarshal(raw, &body); err != nil || r.Header.Get("Content-Type") != "application/json" {
				a.error(w, 400, "PARAMETER_ERROR.INVALID", "bad body")
				return
			}
		}
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 3 && parts[1] == "apps":
		if parts[2] != testAppID || r.URL.Query().Get("fields[apps]") != "bundleId" {
			a.error(w, 404, "NOT_FOUND", "no app")
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{"type": "apps", "id": testAppID, "attributes": map[string]any{"bundleId": testBundleID}}})
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "apps" && parts[3] == "buildUploads":
		q := r.URL.Query()
		if q.Get("filter[cfBundleShortVersionString]") != testVersion || q.Get("filter[cfBundleVersion]") != testBuild || q.Get("filter[platform]") != "IOS" {
			a.error(w, 400, "PARAMETER_ERROR.INVALID", "filters")
			return
		}
		var data []any
		for _, u := range a.uploads {
			if u.version == q.Get("filter[cfBundleShortVersionString]") && u.build == q.Get("filter[cfBundleVersion]") {
				data = append(data, u.resource())
			}
		}
		writeJSON(w, map[string]any{"data": data, "links": map[string]any{"self": r.URL.String()}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/buildUploads":
		data, _ := body["data"].(map[string]any)
		attrs, _ := data["attributes"].(map[string]any)
		app, _ := dig(data, "relationships", "app", "data").(map[string]any)
		if data["type"] != "buildUploads" || attrs["cfBundleShortVersionString"] != testVersion || attrs["cfBundleVersion"] != testBuild || attrs["platform"] != "IOS" || app["type"] != "apps" || app["id"] != testAppID {
			a.error(w, 422, "ENTITY_ERROR", "bad build upload")
			return
		}
		u := &fakeUpload{id: a.id("upload"), version: testVersion, build: testBuild, platform: "IOS", state: stateAwaitingUpload, created: a.f.clock.Now()}
		a.uploads = append(a.uploads, u)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"data": u.resource()})
	case r.Method == http.MethodGet && len(parts) == 3 && parts[1] == "buildUploads":
		if len(a.getStatus) > 0 {
			status := a.getStatus[0]
			a.getStatus = a.getStatus[1:]
			a.error(w, status, "UNEXPECTED_ERROR", "try again")
			return
		}
		u := a.upload(parts[2])
		if u == nil {
			a.error(w, 404, "NOT_FOUND", "no upload")
			return
		}
		if files := a.files[u.id]; u.state == stateAwaitingUpload && len(files) > 0 && files[0].state == fileUploadComplete {
			u.state = stateProcessing
		}
		if u.state == stateProcessing {
			u.polls++
			if u.polls > a.processingPolls {
				u.state, u.errors = a.final, a.finalErrors
			}
		}
		writeJSON(w, map[string]any{"data": u.resource()})
	case r.Method == http.MethodGet && len(parts) == 4 && parts[1] == "buildUploads" && parts[3] == "buildUploadFiles":
		var data []any
		for _, file := range a.files[parts[2]] {
			data = append(data, file.resource())
		}
		writeJSON(w, map[string]any{"data": data, "links": map[string]any{"self": r.URL.String()}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/buildUploadFiles":
		data, _ := body["data"].(map[string]any)
		attrs, _ := data["attributes"].(map[string]any)
		parent, _ := dig(data, "relationships", "buildUpload", "data").(map[string]any)
		size, _ := attrs["fileSize"].(float64)
		u, _ := parent["id"].(string)
		if data["type"] != "buildUploadFiles" || attrs["fileName"] != "App.ipa" || attrs["uti"] != "com.apple.ipa" || attrs["assetType"] != "ASSET" || int64(size) != int64(len(a.f.ipa)) || parent["type"] != "buildUploads" || a.upload(u) == nil {
			a.error(w, 422, "ENTITY_ERROR", "bad file")
			return
		}
		file := a.reserve(u, int64(size))
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"data": file.resource()})
	case r.Method == http.MethodPatch && len(parts) == 3 && parts[1] == "buildUploadFiles":
		file, u := a.file(parts[2])
		data, _ := body["data"].(map[string]any)
		attrs, _ := data["attributes"].(map[string]any)
		sum, _ := dig(attrs, "sourceFileChecksums", "file").(map[string]any)
		if file == nil || data["type"] != "buildUploadFiles" || data["id"] != file.id || attrs["uploaded"] != true {
			a.error(w, 422, "ENTITY_ERROR", "bad commit")
			return
		}
		if file.state != stateAwaitingUpload {
			a.error(w, 409, "STATE_ERROR", "already committed")
			return
		}
		md5sum := md5.Sum(a.f.ipa)
		if sum["algorithm"] != "MD5" || sum["hash"] != hex.EncodeToString(md5sum[:]) {
			a.error(w, 409, "ENTITY_ERROR.CHECKSUM", "checksum")
			return
		}
		var offsets []int64
		for _, op := range file.ops {
			offsets = append(offsets, op["offset"].(int64))
		}
		slices.Sort(offsets)
		var got []byte
		for _, offset := range offsets {
			got = append(got, a.parts[offset]...)
		}
		if !bytes.Equal(got, a.f.ipa) {
			a.error(w, 409, "ENTITY_ERROR.INCOMPLETE", "parts differ")
			return
		}
		file.state, file.checksum, u.state = fileUploadComplete, sum, stateProcessing
		writeJSON(w, map[string]any{"data": file.resource()})
	default:
		a.error(w, 404, "NOT_FOUND", "route")
	}
}

// servePart is a pre-signed storage URL: no JWT, exactly the operation's
// headers and byte range.
func (a *fakeASC) servePart(w http.ResponseWriter, r *http.Request, index string) {
	i, _ := strconv.Atoi(index)
	a.partCalls[i]++
	body, _ := io.ReadAll(r.Body)
	if queue := a.partStatus[i]; len(queue) > 0 {
		a.partStatus[i] = queue[1:]
		w.WriteHeader(queue[0])
		return
	}
	var op map[string]any
	for _, files := range a.files {
		for _, file := range files {
			for _, candidate := range file.ops {
				if candidate["url"] == "http://"+r.Host+r.URL.Path+"?"+r.URL.RawQuery {
					op = candidate
				}
			}
		}
	}
	if op == nil || r.Method != op["method"] || r.Header.Get("Authorization") != "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	for _, h := range op["requestHeaders"].([]map[string]any) {
		if r.Header.Get(h["name"].(string)) != h["value"] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}
	offset, length := op["offset"].(int64), op["length"].(int64)
	if int64(len(body)) != length || r.ContentLength != length || !bytes.Equal(body, a.f.ipa[offset:offset+length]) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	a.parts[offset] = body
	w.Header().Set("ETag", `"`+hexSHA256(body)[:16]+`"`)
}

// reserve creates a file with opsPerFile operations, listed out of order.
func (a *fakeASC) reserve(uploadID string, size int64) *fakeFile {
	file := &fakeFile{id: a.id("file"), state: stateAwaitingUpload, size: size}
	chunk := (size + int64(a.opsPerFile) - 1) / int64(a.opsPerFile)
	for i, offset := 0, int64(0); offset < size; i, offset = i+1, offset+chunk {
		length := min(chunk, size-offset)
		file.ops = append(file.ops, map[string]any{
			"method": "PUT", "url": fmt.Sprintf("%s/storage/part/%d?X-Signature=s%d&partNumber=%d", a.f.asc.URL, i, i, i+1),
			"offset": offset, "length": length, "partNumber": i + 1,
			"requestHeaders": []map[string]any{{"name": "Content-Type", "value": "application/octet-stream"}, {"name": "x-apple-part", "value": strconv.Itoa(i + 1)}},
		})
	}
	slices.Reverse(file.ops)
	a.files[uploadID] = append(a.files[uploadID], file)
	return file
}

func (a *fakeASC) upload(id string) *fakeUpload {
	for _, u := range a.uploads {
		if u.id == id {
			return u
		}
	}
	return nil
}

func (a *fakeASC) file(id string) (*fakeFile, *fakeUpload) {
	for uploadID, files := range a.files {
		for _, file := range files {
			if file.id == id {
				return file, a.upload(uploadID)
			}
		}
	}
	return nil, nil
}

func (a *fakeASC) error(w http.ResponseWriter, status int, code, detail string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{"status": strconv.Itoa(status), "code": code, "title": code, "detail": detail}}})
}

func (u *fakeUpload) resource() map[string]any {
	state := map[string]any{"state": u.state, "errors": u.errors, "warnings": []any{}, "infos": []any{}}
	return map[string]any{"type": "buildUploads", "id": u.id, "attributes": map[string]any{
		"cfBundleShortVersionString": u.version, "cfBundleVersion": u.build, "platform": u.platform,
		"createdDate": u.created.Format(time.RFC3339), "state": state,
	}}
}

func (f *fakeFile) resource() map[string]any {
	attrs := map[string]any{"fileName": "App.ipa", "fileSize": f.size, "uti": "com.apple.ipa", "assetType": "ASSET",
		"assetDeliveryState": map[string]any{"state": f.state, "errors": []any{}}, "uploadOperations": f.ops}
	if f.checksum != nil {
		attrs["sourceFileChecksums"] = map[string]any{"file": f.checksum}
	}
	return map[string]any{"type": "buildUploadFiles", "id": f.id, "attributes": attrs}
}

func dig(v any, path ...string) any {
	for _, key := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[key]
	}
	return v
}

// buildIPA zips Payload/<app>/Info.plist and an executable, uncompressed.
func buildIPA(t *testing.T, app string, infoPlist []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	executable := make([]byte, 6000)
	rand.Read(executable)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"Payload/", nil}, {"Payload/" + app + "/", nil}, {"Payload/" + app + "/Example", executable}, {"Payload/" + app + "/Info.plist", infoPlist}} {
		w, err := archive.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(entry.body)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func xmlInfoPlist(id, short, version string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>Example</string>
	<key>CFBundleIdentifier</key>
	<string>` + id + `</string>
	<key>CFBundleShortVersionString</key>
	<string>` + short + `</string>
	<key>UIDeviceFamily</key>
	<array><integer>1</integer><integer>2</integer></array>
	<key>LSRequiresIPhoneOS</key>
	<true/>
	<key>CFBundleVersion</key>
	<string>` + version + `</string>
</dict>
</plist>
`)
}

// binaryPlist encodes a dictionary of strings (UTF-16 when not ASCII) and
// one integer as bplist00, keys and values in the given order.
func binaryPlist(pairs ...string) []byte {
	var objects [][]byte
	marker := func(kind byte, n int) []byte {
		if n < 15 {
			return []byte{kind<<4 | byte(n)}
		}
		return []byte{kind<<4 | 0x0f, 0x11, byte(n >> 8), byte(n)}
	}
	str := func(s string) []byte {
		ascii := true
		for _, r := range s {
			if r > 0x7f {
				ascii = false
			}
		}
		if ascii {
			return append(marker(0x5, len(s)), s...)
		}
		units := utf16.Encode([]rune(s))
		out := marker(0x6, len(units))
		for _, u := range units {
			out = binary.BigEndian.AppendUint16(out, u)
		}
		return out
	}
	n := len(pairs)/2 + 1
	dict := marker(0xd, n)
	for i := range n {
		dict = append(dict, byte(1+i))
	}
	for i := range n {
		dict = append(dict, byte(1+n+i))
	}
	objects = append(objects, dict)
	for i := 0; i < len(pairs); i += 2 {
		objects = append(objects, str(pairs[i]))
	}
	objects = append(objects, str("UIDeviceFamilyCount"))
	for i := 1; i < len(pairs); i += 2 {
		objects = append(objects, str(pairs[i]))
	}
	objects = append(objects, []byte{0x10, 2})
	out := []byte("bplist00")
	var offsets []int
	for _, o := range objects {
		offsets = append(offsets, len(out))
		out = append(out, o...)
	}
	table := len(out)
	for _, o := range offsets {
		out = binary.BigEndian.AppendUint16(out, uint16(o))
	}
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 2, 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[16:], 0)
	binary.BigEndian.PutUint64(trailer[24:], uint64(table))
	return append(out, trailer...)
}
