package testflight

import (
	"bytes"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func validFixture(t *testing.T) *fixture {
	return newFixture(t, xmlInfoPlist(testBundleID, testVersion, testBuild))
}

func TestUploadRunsEveryOperationAndCommits(t *testing.T) {
	f := validFixture(t)
	ev, err := f.run()
	if err != nil {
		t.Fatal(err)
	}
	a := f.ascState
	want := []string{
		"GET /v1/apps/" + testAppID,
		"GET /v1/apps/" + testAppID + "/buildUploads",
		"POST /v1/buildUploads",
		"GET /v1/buildUploads/upload-1/buildUploadFiles",
		"POST /v1/buildUploadFiles",
		"PATCH /v1/buildUploadFiles/file-2",
		"GET /v1/buildUploads/upload-1",
		"GET /v1/buildUploads/upload-1",
	}
	if !slices.Equal(a.log, want) {
		t.Fatalf("requests:\n%s\nwant:\n%s", strings.Join(a.log, "\n"), strings.Join(want, "\n"))
	}
	if len(a.parts) != 3 || a.partCalls[0] != 1 || a.partCalls[1] != 1 || a.partCalls[2] != 1 {
		t.Fatalf("parts %d, calls %v", len(a.parts), a.partCalls)
	}
	if f.keyringCalls != 1 || a.unauthorized != 0 {
		t.Fatalf("keyring calls %d, 401s %d", f.keyringCalls, a.unauthorized)
	}
	md5sum := md5.Sum(f.ipa)
	if got := a.bodies["PATCH /v1/buildUploadFiles/file-2"]; len(got) != 1 || got[0] != `{"data":{"attributes":{"sourceFileChecksums":{"file":{"hash":"`+hex.EncodeToString(md5sum[:])+`","algorithm":"MD5"}},"uploaded":true},"id":"file-2","type":"buildUploadFiles"}}` {
		t.Fatalf("commit body %v", got)
	}
	if got := a.bodies["POST /v1/buildUploads"]; len(got) != 1 || got[0] != `{"data":{"attributes":{"cfBundleShortVersionString":"2.0.1","cfBundleVersion":"17","platform":"IOS"},"relationships":{"app":{"data":{"id":"`+testAppID+`","type":"apps"}}},"type":"buildUploads"}}` {
		t.Fatalf("create body %v", got)
	}
	if ev.JobID != testJob || ev.AppID != testAppID || ev.BundleID != testBundleID || ev.BuildName != testVersion || ev.BuildNumber != testBuild || ev.BuildUploadID != "upload-1" || ev.Resumed || ev.FinalState != "COMPLETE" || ev.Error != "" {
		t.Fatalf("evidence %+v", ev)
	}
	if ev.IPASHA256 != hexSHA256(f.ipa) || ev.IPASize != int64(len(f.ipa)) || ev.SignerReceiptSHA256 != hexSHA256(f.signerReceipt()) || ev.StartedAt.IsZero() || ev.FinishedAt.Before(ev.StartedAt) {
		t.Fatalf("evidence digests %+v", ev)
	}
	encoded, _ := json.Marshal(ev)
	for _, key := range []string{"job_id", "signer_receipt_sha256", "ipa_sha256", "ipa_size", "app_id", "build_name", "build_number", "build_upload_id", "final_state", "started_at", "finished_at"} {
		if !bytes.Contains(encoded, []byte(`"`+key+`":`)) {
			t.Fatalf("evidence JSON lacks %s: %s", key, encoded)
		}
	}
}

func TestUploadReadsBinaryInfoPlist(t *testing.T) {
	f := newFixture(t, binaryPlist("CFBundleIdentifier", testBundleID, "CFBundleShortVersionString", testVersion, "CFBundleVersion", testBuild))
	if ev, err := f.run(); err != nil || ev.FinalState != "COMPLETE" {
		t.Fatalf("%+v %v", ev, err)
	}
}

func TestTokenRefreshedWithinAMinuteOfExpiry(t *testing.T) {
	f := validFixture(t)
	f.keyringTTL = 2 * time.Minute
	f.ascState.step = 30 * time.Second
	if _, err := f.run(); err != nil {
		t.Fatal(err)
	}
	if f.keyringCalls < 3 || f.ascState.unauthorized != 0 || f.ascState.minRemaining <= refreshBefore {
		t.Fatalf("keyring calls %d, 401s %d, least remaining %s", f.keyringCalls, f.ascState.unauthorized, f.ascState.minRemaining)
	}
}

func TestUnauthorizedRefreshesTokenOnce(t *testing.T) {
	f := validFixture(t)
	f.ascState.reject401 = 1
	if _, err := f.run(); err != nil {
		t.Fatal(err)
	}
	if f.keyringCalls != 2 || f.ascState.unauthorized != 1 {
		t.Fatalf("keyring calls %d, 401s %d", f.keyringCalls, f.ascState.unauthorized)
	}

	f = validFixture(t)
	f.ascState.reject401 = 2
	_, err := f.run()
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "NOT_AUTHORIZED") {
		t.Fatalf("persistent 401: %v", err)
	}
	if f.keyringCalls != 2 || !slices.Equal(f.ascState.log, []string{"GET /v1/apps/" + testAppID, "GET /v1/apps/" + testAppID}) {
		t.Fatalf("keyring calls %d, requests %v", f.keyringCalls, f.ascState.log)
	}
	if strings.Contains(err.Error(), "jwt-") {
		t.Fatalf("error leaks a token: %v", err)
	}
}

func TestServerErrorsAreRetried(t *testing.T) {
	f := validFixture(t)
	f.ascState.partStatus[1] = []int{500, 502}
	f.ascState.getStatus = []int{503}
	ev, err := f.run()
	if err != nil || ev.FinalState != "COMPLETE" {
		t.Fatalf("%+v %v", ev, err)
	}
	if f.ascState.partCalls[1] != 3 || f.ascState.partCalls[0] != 1 {
		t.Fatalf("part calls %v", f.ascState.partCalls)
	}

	f = validFixture(t)
	f.ascState.partStatus[2] = []int{500, 500, 500}
	if _, err := f.run(); err == nil || !strings.Contains(err.Error(), "HTTP 500") || slices.Contains(f.ascState.log, "PATCH /v1/buildUploadFiles/file-2") {
		t.Fatalf("exhausted retries: %v %v", err, f.ascState.log)
	}
	if f.ascState.partCalls[2] != 3 {
		t.Fatalf("part calls %v", f.ascState.partCalls)
	}
}

func TestClientErrorsAbort(t *testing.T) {
	f := validFixture(t)
	f.ascState.partStatus[0] = []int{403}
	_, err := f.run()
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || f.ascState.partCalls[0] != 1 || slices.Contains(f.ascState.log, "PATCH /v1/buildUploadFiles/file-2") {
		t.Fatalf("403: %v %v %v", err, f.ascState.partCalls, f.ascState.log)
	}
	if strings.Contains(err.Error(), "X-Signature") {
		t.Fatalf("error leaks the pre-signed URL: %v", err)
	}

	f = validFixture(t)
	f.ascState.getStatus = []int{400}
	ev, err := f.run()
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || ev.BuildUploadID != "upload-1" || ev.FinalState != "AWAITING_UPLOAD" {
		t.Fatalf("400: %+v %v", ev, err)
	}
	if polls := slices.DeleteFunc(slices.Clone(f.ascState.log), func(s string) bool { return s != "GET /v1/buildUploads/upload-1" }); len(polls) != 1 {
		t.Fatalf("400 was retried: %v", f.ascState.log)
	}
}

func TestFailedStateIsReported(t *testing.T) {
	f := validFixture(t)
	f.ascState.final = "FAILED"
	f.ascState.finalErrors = []StateDetail{{Code: "90062", Description: "The value for key CFBundleShortVersionString must be higher"}}
	ev, err := f.run()
	if err == nil || !strings.Contains(err.Error(), "FAILED; 90062") {
		t.Fatalf("FAILED: %v", err)
	}
	if ev.FinalState != "FAILED" || len(ev.StateErrors) != 1 || ev.StateErrors[0].Code != "90062" || ev.Error == "" || ev.BuildUploadID != "upload-1" {
		t.Fatalf("evidence %+v", ev)
	}
}

func TestExistingUploadIsResumed(t *testing.T) {
	// Awaiting upload with its file reserved: upload and commit only.
	f := validFixture(t)
	a := f.ascState
	a.uploads = append(a.uploads, &fakeUpload{id: "upload-7", version: testVersion, build: testBuild, platform: "IOS", state: stateAwaitingUpload, created: f.clock.Now()})
	a.nextID = 7
	a.reserve("upload-7", int64(len(f.ipa)))
	ev, err := f.run()
	if err != nil || !ev.Resumed || ev.BuildUploadID != "upload-7" || ev.FinalState != "COMPLETE" {
		t.Fatalf("%+v %v", ev, err)
	}
	if slices.Contains(a.log, "POST /v1/buildUploads") || slices.Contains(a.log, "POST /v1/buildUploadFiles") || !slices.Contains(a.log, "PATCH /v1/buildUploadFiles/file-8") || len(a.parts) != 3 {
		t.Fatalf("requests %v", a.log)
	}

	// Already committed and processing: poll only.
	f = validFixture(t)
	a = f.ascState
	md5sum := md5.Sum(f.ipa)
	a.uploads = append(a.uploads, &fakeUpload{id: "upload-3", version: testVersion, build: testBuild, platform: "IOS", state: stateProcessing, created: f.clock.Now()})
	a.files["upload-3"] = []*fakeFile{{id: "file-4", state: fileUploadComplete, size: int64(len(f.ipa)), checksum: map[string]any{"hash": hex.EncodeToString(md5sum[:]), "algorithm": "MD5"}}}
	ev, err = f.run()
	if err != nil || !ev.Resumed || ev.BuildUploadID != "upload-3" || ev.FinalState != "COMPLETE" || len(a.partCalls) != 0 {
		t.Fatalf("%+v %v %v", ev, err, a.log)
	}
	if slices.ContainsFunc(a.log, func(s string) bool { return !strings.HasPrefix(s, "GET ") }) {
		t.Fatalf("processing upload was modified: %v", a.log)
	}

	// Processing, but for a different ipa: refuse.
	f = validFixture(t)
	a = f.ascState
	a.uploads = append(a.uploads, &fakeUpload{id: "upload-3", version: testVersion, build: testBuild, platform: "IOS", state: stateProcessing, created: f.clock.Now()})
	a.files["upload-3"] = []*fakeFile{{id: "file-4", state: fileUploadComplete, size: int64(len(f.ipa)), checksum: map[string]any{"hash": strings.Repeat("0", 32), "algorithm": "MD5"}}}
	if _, err := f.run(); err == nil || !strings.Contains(err.Error(), "not this ipa's") {
		t.Fatalf("different ipa: %v", err)
	}

	// An earlier FAILED upload is reported, not duplicated.
	f = validFixture(t)
	a = f.ascState
	a.uploads = append(a.uploads, &fakeUpload{id: "upload-5", version: testVersion, build: testBuild, platform: "IOS", state: stateFailed, created: f.clock.Now(), errors: []StateDetail{{Code: "90189", Description: "Redundant Binary Upload"}}})
	ev, err = f.run()
	if err == nil || ev.FinalState != "FAILED" || ev.BuildUploadID != "upload-5" || slices.Contains(a.log, "POST /v1/buildUploads") {
		t.Fatalf("failed upload: %+v %v %v", ev, err, a.log)
	}
}

func TestRefusesUnverifiedIPA(t *testing.T) {
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, test := range map[string]struct {
		mutate func(*fixture)
		want   string
	}{
		"bad signer signature":    {func(f *fixture) { f.receiptKey = otherKey }, "does not verify"},
		"receipt for another job": {func(f *fixture) { f.payload.JobID = "job_other" }, "names job job_other"},
		"other job receipt":       {func(f *fixture) { f.jobReceipt = []byte(`{"other":true}`) }, "does not bind this job's receipt"},
		"other commit":            {func(f *fixture) { f.payload.Commit = strings.Repeat("d", 40) }, "repository or commit"},
		"ipa digest mismatch": {func(f *fixture) {
			f.served = bytes.Clone(f.ipa)
			f.served[len(f.served)/2] ^= 1
		}, "differs from the signer receipt"},
		"ipa longer than receipt": {func(f *fixture) { f.served = append(bytes.Clone(f.ipa), 0) }, "exceeds"},
		"size mismatch":           {func(f *fixture) { f.listedSize = int64(len(f.ipa)) + 1 }, "digest or size differs"},
		"info plist version": {func(f *fixture) {
			f.ipa = buildIPA(t, "Example.app", xmlInfoPlist(testBundleID, testVersion, "18"))
			f.payload.IPA.SHA256, f.payload.IPA.SizeBytes = hexSHA256(f.ipa), int64(len(f.ipa))
		}, "ipa Info.plist names"},
		"info plist bundle": {func(f *fixture) {
			f.ipa = buildIPA(t, "Example.app", xmlInfoPlist("com.example.other", testVersion, testBuild))
			f.payload.IPA.SHA256, f.payload.IPA.SizeBytes = hexSHA256(f.ipa), int64(len(f.ipa))
		}, "ipa Info.plist names"},
		"other app in ipa": {func(f *fixture) {
			f.ipa = buildIPA(t, "Other.app", xmlInfoPlist(testBundleID, testVersion, testBuild))
			f.payload.IPA.SHA256, f.payload.IPA.SizeBytes = hexSHA256(f.ipa), int64(len(f.ipa))
		}, "outside Payload/Example.app/"},
	} {
		t.Run(name, func(t *testing.T) {
			f := validFixture(t)
			test.mutate(f)
			_, err := f.run()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want %q", err, test.want)
			}
			if len(f.ascState.log) != 0 || f.keyringCalls != 0 {
				t.Fatalf("App Store Connect contacted: %v, keyring %d", f.ascState.log, f.keyringCalls)
			}
		})
	}
}

func TestRefusesOtherApp(t *testing.T) {
	f := validFixture(t)
	o := f.options()
	o.AppID = "1234"
	if _, err := Run(t.Context(), o); err == nil || !strings.Contains(err.Error(), "HTTP 404") || slices.Contains(f.ascState.log, "POST /v1/buildUploads") {
		t.Fatalf("other app: %v %v", err, f.ascState.log)
	}
}

func TestPlistStrings(t *testing.T) {
	keys := []string{"CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion"}
	long := strings.Repeat("v", 40)
	for name, raw := range map[string][]byte{
		"xml":    xmlInfoPlist("com.example.app", "1.2.3", long),
		"binary": binaryPlist("CFBundleIdentifier", "com.example.app", "CFBundleShortVersionString", "1.2.3", "CFBundleVersion", long),
	} {
		got, err := plistStrings(raw, keys)
		if err != nil || got["CFBundleIdentifier"] != "com.example.app" || got["CFBundleShortVersionString"] != "1.2.3" || got["CFBundleVersion"] != long {
			t.Fatalf("%s: %v %v", name, got, err)
		}
	}
	got, err := plistStrings(binaryPlist("CFBundleIdentifier", "com.exämple.app"), keys)
	if err != nil || got["CFBundleIdentifier"] != "com.exämple.app" {
		t.Fatalf("utf-16: %v %v", got, err)
	}
	raw := binaryPlist("CFBundleIdentifier", "com.example.app", "CFBundleVersion", "1")
	for n := range len(raw) {
		plistStrings(raw[:n], keys) // must not panic
		corrupt := bytes.Clone(raw)
		corrupt[n] ^= 0xff
		plistStrings(corrupt, keys)
	}
	for _, bad := range []string{`<plist><array/></plist>`, `<plist><dict><key>CFBundleVersion</key>`, `not xml`} {
		if _, err := plistStrings([]byte(bad), keys); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
