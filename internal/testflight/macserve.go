package testflight

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/signer"
)

var (
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rootAppPattern = regexp.MustCompile(`^Products/Applications/[^/]+\.app$`)
)

// signedIPA is a downloaded App.ipa that matched its verified signer receipt.
type signedIPA struct {
	receipt       signer.ReceiptPayload
	receiptSHA256 string
	bundleID      string
	file          *os.File
	size          int64
	sha256, md5   string
}

type signingArtifact struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// fetchSignedIPA reads the macserve signer key, the job and its signing
// record; verifies the signer receipt (Ed25519 under that key, this job,
// this job's receipt, its repository, commit and release); downloads App.ipa
// by its content ID into dir, requiring the receipt's size and SHA-256; and
// requires the ipa's root app Info.plist to carry the receipt's bundle ID,
// version and build.
//
// Versions are checked against the signed receipt first: the worker parsed
// every bundle's Info.plist into the signing manifest and refused any
// version other than the job's release, and the signer receipt binds that
// manifest and the ipa digest. Reading the ipa's own Info.plist (XML or
// binary) is an independent second check that needs no macOS tools.
func fetchSignedIPA(ctx context.Context, api *apiClient, jobID, dir string, logf func(string, ...any)) (*signedIPA, error) {
	var capabilities struct {
		Signer *struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"signer"`
	}
	if err := api.getJSON(ctx, "/v1/capabilities", 1<<20, &capabilities); err != nil {
		return nil, err
	}
	if capabilities.Signer == nil {
		return nil, errors.New("macserve publishes no signer key: signing is not configured")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(capabilities.Signer.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || capabilities.Signer.KeyID == "" {
		return nil, errors.New("macserve publishes an invalid signer key")
	}
	var job struct {
		ID        string `json:"id"`
		State     string `json:"state"`
		Kind      string `json:"kind"`
		Repo      string `json:"repo"`
		SHA       string `json:"sha"`
		Requested struct {
			Release *struct {
				BuildName   string `json:"build_name"`
				BuildNumber string `json:"build_number"`
			} `json:"release"`
		} `json:"requested"`
	}
	if err := api.getJSON(ctx, "/v1/jobs/"+jobID, 1<<20, &job); err != nil {
		return nil, err
	}
	if job.ID != jobID || job.Kind != "ios_archive" || job.State != "succeeded" || job.Requested.Release == nil {
		return nil, fmt.Errorf("job %s is not a succeeded ios_archive job (kind %q, state %q)", jobID, job.Kind, job.State)
	}
	var signing struct {
		JobID   string `json:"job_id"`
		Signing struct {
			Status    string            `json:"status"`
			Reason    string            `json:"reason"`
			Artifacts []signingArtifact `json:"artifacts"`
		} `json:"signing"`
	}
	if err := api.getJSON(ctx, "/v1/jobs/"+jobID+"/signing", 1<<20, &signing); err != nil {
		return nil, err
	}
	if signing.JobID != jobID || signing.Signing.Status != "signed" {
		return nil, fmt.Errorf("job %s is not signed (signing status %q %s); POST /v1/jobs/%s/sign first", jobID, signing.Signing.Status, signing.Signing.Reason, jobID)
	}
	ipaArtifact, err := oneArtifact(signing.Signing.Artifacts, signer.IPAArtifact)
	if err != nil {
		return nil, err
	}
	receiptArtifact, err := oneArtifact(signing.Signing.Artifacts, signer.ReceiptArtifact)
	if err != nil {
		return nil, err
	}

	// Signer receipt: exact listed bytes, then Ed25519 under the published key.
	var raw bytes.Buffer
	if _, err := api.download(ctx, artifactPath(jobID, receiptArtifact), signer.MaxReceiptBytes, func() (io.Writer, error) { raw.Reset(); return &raw, nil }); err != nil {
		return nil, err
	}
	receiptSHA := hexSHA256(raw.Bytes())
	if receiptSHA != receiptArtifact.SHA256 || int64(raw.Len()) != receiptArtifact.SizeBytes {
		return nil, errors.New("signer receipt bytes differ from the signing record's digest")
	}
	payload, err := signer.VerifyReceipt(raw.Bytes(), map[string]ed25519.PublicKey{capabilities.Signer.KeyID: key})
	if err != nil {
		return nil, fmt.Errorf("signer receipt does not verify under macserve's signer key %s: %w", capabilities.Signer.KeyID, err)
	}
	release := job.Requested.Release
	switch {
	case payload.JobID != jobID:
		return nil, fmt.Errorf("signer receipt names job %s, not %s", payload.JobID, jobID)
	case payload.IPA.SHA256 != ipaArtifact.SHA256 || payload.IPA.SizeBytes != ipaArtifact.SizeBytes:
		return nil, errors.New("signer receipt's ipa digest or size differs from the signing record's App.ipa")
	case payload.Repository.Name != job.Repo || payload.Commit != job.SHA:
		return nil, errors.New("signer receipt's repository or commit differs from the job")
	case payload.BuildName != release.BuildName || payload.BuildNumber != release.BuildNumber:
		return nil, fmt.Errorf("signer receipt's version %s (%s) differs from the job's release %s (%s)", payload.BuildName, payload.BuildNumber, release.BuildName, release.BuildNumber)
	}
	var jobReceipt bytes.Buffer
	if _, err := api.download(ctx, "/v1/jobs/"+jobID+"/receipt", receipt.MaxReceiptBytes, func() (io.Writer, error) { jobReceipt.Reset(); return &jobReceipt, nil }); err != nil {
		return nil, err
	}
	if hexSHA256(jobReceipt.Bytes()) != payload.JobReceiptSHA256 {
		return nil, errors.New("signer receipt does not bind this job's receipt")
	}
	root := ""
	bundleID := ""
	for _, b := range payload.Bundles {
		if rootAppPattern.MatchString(b.Path) {
			if root != "" {
				return nil, errors.New("signer receipt lists more than one application")
			}
			root, bundleID = b.Path, b.BundleID
		}
	}
	if root == "" || bundleID == "" {
		return nil, errors.New("signer receipt lists no root application")
	}

	// App.ipa by its content ID: exactly the receipt's size and SHA-256.
	file, err := os.OpenFile(filepath.Join(dir, signer.IPAArtifact), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	var sha, sum hash.Hash
	logf("downloading %s (%d bytes)", signer.IPAArtifact, payload.IPA.SizeBytes)
	size, err := api.download(ctx, artifactPath(jobID, ipaArtifact), payload.IPA.SizeBytes, func() (io.Writer, error) {
		sha, sum = sha256.New(), md5.New()
		if err := file.Truncate(0); err != nil {
			return nil, err
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return io.MultiWriter(file, sha, sum), nil
	})
	if err == nil && (size != payload.IPA.SizeBytes || hex.EncodeToString(sha.Sum(nil)) != payload.IPA.SHA256) {
		err = fmt.Errorf("downloaded ipa (%d bytes, sha256 %s) differs from the signer receipt (%d bytes, sha256 %s)", size, hex.EncodeToString(sha.Sum(nil)), payload.IPA.SizeBytes, payload.IPA.SHA256)
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	info, err := readIPAInfo(file, size, path.Base(root))
	if err == nil && (info.id != bundleID || info.shortVersion != payload.BuildName || info.version != payload.BuildNumber) {
		err = fmt.Errorf("ipa Info.plist names %s %s (%s), the signer receipt %s %s (%s)", info.id, info.shortVersion, info.version, bundleID, payload.BuildName, payload.BuildNumber)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return &signedIPA{receipt: payload, receiptSHA256: receiptSHA, bundleID: bundleID, file: file, size: size, sha256: payload.IPA.SHA256, md5: hex.EncodeToString(sum.Sum(nil))}, nil
}

// oneArtifact returns the single listed artifact called name; its content
// ID is its SHA-256.
func oneArtifact(artifacts []signingArtifact, name string) (signingArtifact, error) {
	var found []signingArtifact
	for _, a := range artifacts {
		if a.Name == name {
			found = append(found, a)
		}
	}
	if len(found) != 1 {
		return signingArtifact{}, fmt.Errorf("signing record lists %d %s artifacts", len(found), name)
	}
	a := found[0]
	if !sha256Pattern.MatchString(a.SHA256) || a.ID != a.SHA256 || a.SizeBytes <= 0 {
		return signingArtifact{}, fmt.Errorf("signing record's %s is not content-addressed", name)
	}
	return a, nil
}

func artifactPath(jobID string, a signingArtifact) string {
	return "/v1/jobs/" + jobID + "/artifacts/" + a.ID
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// apiClient reads the macserve API. The base URL authenticates the agent
// (the keyring relay adds its token); nothing App Store Connect related is
// ever sent to it.
type apiClient struct {
	base  *url.URL
	http  *http.Client
	retry retryPolicy
}

func (a *apiClient) getJSON(ctx context.Context, route string, limit int64, out any) error {
	var body bytes.Buffer
	if _, err := a.download(ctx, route, limit, func() (io.Writer, error) { body.Reset(); return &body, nil }); err != nil {
		return err
	}
	if err := json.Unmarshal(body.Bytes(), out); err != nil {
		return fmt.Errorf("macserve GET %s: invalid JSON: %w", route, err)
	}
	return nil
}

// download GETs route into the writer start returns for each attempt (so a
// retried attempt restarts cleanly), refusing bodies over limit bytes.
// Network errors and 5xx responses are retried; other statuses fail.
func (a *apiClient) download(ctx context.Context, route string, limit int64, start func() (io.Writer, error)) (int64, error) {
	target := a.base.JoinPath(route).String()
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return 0, err
		}
		resp, err := a.http.Do(req)
		retryable := err != nil
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				w, err := start()
				if err != nil {
					resp.Body.Close()
					return 0, err
				}
				n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
				resp.Body.Close()
				if err == nil && n > limit {
					return 0, fmt.Errorf("macserve GET %s: response exceeds %d bytes", route, limit)
				}
				if err == nil {
					return n, nil
				}
				retryable = true
			} else {
				message := macserveError(resp)
				if resp.StatusCode < 500 {
					return 0, fmt.Errorf("macserve GET %s: HTTP %d%s", route, resp.StatusCode, message)
				}
				err = fmt.Errorf("HTTP %d%s", resp.StatusCode, message)
				retryable = true
			}
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if !retryable || attempt >= a.retry.attempts {
			return 0, fmt.Errorf("macserve GET %s: %w", route, err)
		}
		if err := a.retry.wait(ctx, attempt, 0); err != nil {
			return 0, err
		}
	}
}

// macserveError renders the API's error envelope, bounded.
func macserveError(resp *http.Response) string {
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) == nil && envelope.Error.Code != "" {
		return ": " + clean(envelope.Error.Code+": "+envelope.Error.Message)
	}
	return ""
}

// clean keeps remote text on one bounded printable line.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 512 {
		s = s[:512] + "…"
	}
	return s
}
