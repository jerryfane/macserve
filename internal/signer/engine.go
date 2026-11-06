// Package signer signs a succeeded ios_archive job's sealed unsigned archive
// into an App Store ipa, outside any job, as the dedicated signer account.
// The signing key is used only through /usr/bin/codesign; every input is
// checked against the job's Ed25519-signed receipt before archive bytes are
// opened.
package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

const (
	maxManifestBytes = 4 << 20
	embeddedProfile  = "embedded.mobileprovision"
)

var (
	jobIDPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	rootAppPattern = regexp.MustCompile(`^Products/Applications/[^/]+\.app$`)
)

// Options configures an Engine.
type Options struct {
	Config      Config
	Policy      Policy
	Tools       Tools
	PrivateKey  ed25519.PrivateKey
	ReceiptKeys map[string]ed25519.PublicKey
	// KeychainSecret unlocks Config.Keychain before every signing.
	KeychainSecret string
	Now            func() time.Time
	// CheckProfileFile checks an admin profile file before it is read
	// (production: root-owned, protected ancestors); nil skips it.
	CheckProfileFile func(path string) error
}

// Engine performs signings, one at a time.
type Engine struct {
	mu      sync.Mutex
	options Options
}

// Signed is a completed signing. IPA is the signed ipa, open at offset 0;
// Close removes the signing's private work directory.
type Signed struct {
	Receipt   []byte
	Payload   ReceiptPayload
	IPA       *os.File
	IPASHA256 string
	IPASize   int64
	work      string
}

// Close releases the ipa and the signing's work directory.
func (s *Signed) Close() error {
	return errors.Join(s.IPA.Close(), os.RemoveAll(s.work))
}

// NewEngine validates options.
func NewEngine(options Options) (*Engine, error) {
	if options.Tools == nil || len(options.PrivateKey) != ed25519.PrivateKeySize || len(options.ReceiptKeys) == 0 {
		return nil, errors.New("signer: tools, signer key and receipt keys are required")
	}
	if err := options.Policy.Validate(); err != nil {
		return nil, err
	}
	if !keychainSecretPattern.MatchString(options.KeychainSecret) {
		return nil, errors.New("signer: keychain secret must be 32-128 ASCII letters and digits")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Engine{options: options}, nil
}

// PublicKey is the signer receipt verification key.
func (e *Engine) PublicKey() ed25519.PublicKey {
	return e.options.PrivateKey.Public().(ed25519.PublicKey)
}

// Ready unlocks the keychain and requires the configured identity, with its
// private key, to be a valid code-signing identity in it.
func (e *Engine) Ready(ctx context.Context) error {
	c, tools := e.options.Config, e.options.Tools
	if err := tools.UnlockKeychain(ctx, c.Keychain, e.options.KeychainSecret); err != nil {
		return fmt.Errorf("unlock signer keychain: %w", err)
	}
	identities, err := tools.Identities(ctx, c.Keychain)
	if err != nil {
		return fmt.Errorf("list signer identities: %w", err)
	}
	if !slices.Contains(identities, e.options.Policy.Identity()) {
		return fmt.Errorf("signer keychain has no valid code-signing identity %s", e.options.Policy.Identity())
	}
	return nil
}

// RequestPaths are the inbox paths a request for jobID must name.
func RequestPaths(inbox, jobID string) (archive, manifest string) {
	dir := filepath.Join(inbox, jobID)
	return filepath.Join(dir, profiles.ArchiveArtifact), filepath.Join(dir, profiles.SigningManifestArtifact)
}

// signable is one code node of the manifest in signing order.
type signable struct {
	path   string
	bundle *worker.SignableBundle
	phase  int
}

// signingOrder lists the manifest's dylibs and bundles inside-out: loose
// dylibs, then frameworks, then app extensions and nested apps, then the
// root app; within a phase deeper paths first, then by path. Every node
// therefore follows each node below it.
func signingOrder(m worker.SigningManifest) []signable {
	var nodes []signable
	for _, dylib := range m.Dylibs {
		nodes = append(nodes, signable{path: dylib, phase: 0})
	}
	for i := range m.Bundles {
		b := &m.Bundles[i]
		phase := 2
		switch {
		case b.PackageType == "FMWK":
			phase = 1
		case rootAppPattern.MatchString(b.Path):
			phase = 3
		}
		nodes = append(nodes, signable{path: b.Path, bundle: b, phase: phase})
	}
	slices.SortStableFunc(nodes, func(a, b signable) int {
		if a.phase != b.phase {
			return a.phase - b.phase
		}
		if da, db := strings.Count(a.path, "/"), strings.Count(b.path, "/"); da != db {
			return db - da
		}
		return strings.Compare(a.path, b.path)
	})
	return nodes
}

// bundlePlan is one app or app extension's verified profile and the
// entitlements plist to sign it with.
type bundlePlan struct {
	profile      Profile
	entitlements map[string]any
	plist        []byte
	plistSHA256  string
}

// Sign verifies req and signs its archive. A *RefusalError reports inputs
// the signer will not sign; other errors are signer or tool failures.
func (e *Engine) Sign(ctx context.Context, req Request) (*Signed, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, tools := e.options.Config, e.options.Tools
	if !jobIDPattern.MatchString(req.JobID) {
		return nil, refusal("job id")
	}
	archivePath, manifestPath := RequestPaths(c.Inbox, req.JobID)
	if req.ArchivePath != archivePath || req.ManifestPath != manifestPath {
		return nil, refusal("archive and manifest must be %s and %s", archivePath, manifestPath)
	}
	// The receipt: signature, then complete succeeded ios_archive evidence
	// with GitHub App default-branch provenance, for this job.
	payload, err := receipt.Verify(req.Receipt, e.options.ReceiptKeys)
	if err != nil {
		return nil, refusal("job receipt signature does not verify with a pinned key")
	}
	if err := receipt.ValidateRelease(payload); err != nil {
		return nil, refusal("job receipt: %v", err)
	}
	if payload.JobID != req.JobID {
		return nil, refusal("job receipt is for job %s", payload.JobID)
	}
	// The manifest the receipt binds.
	manifestRaw, err := readInput(manifestPath, maxManifestBytes)
	if err != nil {
		return nil, refusal("signing manifest: %v", err)
	}
	manifestSum := sha256.Sum256(manifestRaw)
	manifestSHA := hex.EncodeToString(manifestSum[:])
	if manifestSHA != payload.SigningManifestSHA256 {
		return nil, refusal("signing manifest SHA-256 %s is not the receipt's %s", manifestSHA, payload.SigningManifestSHA256)
	}
	m, err := worker.ParseSigningManifest(manifestRaw, *payload.Release)
	if err != nil {
		return nil, refusal("%v", err)
	}
	if m.Archive.Name != profiles.ArchiveArtifact || m.Archive.Root != profiles.ArchivePath {
		return nil, refusal("signing manifest archive identity")
	}
	teamID, err := e.policyTeam(m)
	if err != nil {
		return nil, err
	}
	identity := e.options.Policy.Identity()

	work, err := e.workDir(req.JobID)
	if err != nil {
		return nil, err
	}
	signed := false
	defer func() {
		if !signed {
			os.RemoveAll(work)
		}
	}()
	// The archive: size and SHA-256 of a private copy, then extraction
	// from that copy only.
	archiveCopy, err := copyArchive(ctx, archivePath, filepath.Join(work, "archive.tar"), m.Archive)
	if err != nil {
		return nil, err
	}
	defer archiveCopy.Close()
	treeDir := filepath.Join(work, "tree")
	if err := os.Mkdir(treeDir, 0o700); err != nil {
		return nil, err
	}
	tree, err := os.OpenRoot(treeDir)
	if err != nil {
		return nil, err
	}
	defer tree.Close()
	if err := extractArchive(ctx, archiveCopy, tree, m); err != nil {
		return nil, err
	}
	archiveCopy.Close()
	os.Remove(filepath.Join(work, "archive.tar"))
	if err := refuseEmbeddedProfiles(tree, m.Archive.Root); err != nil {
		return nil, err
	}
	// Identity, profiles and entitlements before any signature.
	if err := tools.UnlockKeychain(ctx, c.Keychain, e.options.KeychainSecret); err != nil {
		return nil, fmt.Errorf("unlock signer keychain: %w", err)
	}
	identities, err := tools.Identities(ctx, c.Keychain)
	if err != nil {
		return nil, fmt.Errorf("list signer identities: %w", err)
	}
	if !slices.Contains(identities, identity) {
		return nil, refusal("signer keychain has no valid identity %s", identity)
	}
	plans := map[string]bundlePlan{}
	for _, b := range m.Bundles {
		if b.PackageType == "FMWK" {
			continue
		}
		plan, err := e.planBundle(ctx, work, b, identity, len(plans))
		if err != nil {
			return nil, err
		}
		plans[b.Path] = plan
	}
	// Embed each verified profile, then sign inside-out.
	for bundlePath, plan := range plans {
		if err := writeNew(tree, path.Join(m.Archive.Root, bundlePath, embeddedProfile), plan.profile.Raw, 0o644); err != nil {
			return nil, err
		}
	}
	order := signingOrder(m)
	for _, node := range order {
		spec := SignSpec{Path: filepath.Join(treeDir, m.Archive.Root, node.path), Identity: identity, Keychain: c.Keychain}
		if plan, ok := plans[node.path]; ok {
			spec.Entitlements = filepath.Join(work, "entitlements", plan.plistSHA256+".plist")
		}
		if err := tools.Sign(ctx, spec); err != nil {
			return nil, fmt.Errorf("codesign %s: %w", node.path, err)
		}
		if err := tools.Verify(ctx, spec.Path); err != nil {
			return nil, fmt.Errorf("codesign --verify %s: %w", node.path, err)
		}
	}
	// Package and re-parse.
	root := ""
	for _, b := range m.Bundles {
		if rootAppPattern.MatchString(b.Path) {
			root = b.Path
		}
	}
	ipaPath := filepath.Join(work, IPAArtifact)
	ipaSHA, ipaSize, err := packageIPA(ctx, tree, path.Join(m.Archive.Root, root), ipaPath)
	if err != nil {
		return nil, err
	}
	if err := e.verifyIPA(ctx, work, ipaPath, ipaSize, m, root, plans); err != nil {
		return nil, err
	}
	// Receipt.
	result := ReceiptPayload{
		Schema: ReceiptSchema, JobID: req.JobID, JobReceiptSHA256: sum(req.Receipt),
		Repository: RepositoryRef{ID: payload.Repository.ID, Name: payload.Repository.Name}, Commit: payload.Source.Commit,
		BuildName: payload.Release.BuildName, BuildNumber: payload.Release.BuildNumber,
		Archive:               DigestRef{Name: m.Archive.Name, SHA256: m.Archive.SHA256, SizeBytes: m.Archive.SizeBytes},
		SigningManifestSHA256: manifestSHA, IdentitySHA1: identity, TeamID: teamID,
		IPA:      DigestRef{Name: IPAArtifact, SHA256: ipaSHA, SizeBytes: ipaSize},
		Bundles:  make([]SignedBundle, 0, len(m.Bundles)),
		Dylibs:   append([]string{}, m.Dylibs...),
		SignedAt: e.options.Now().UTC().Truncate(time.Second),
		Signer:   SignerReference{KeyID: c.KeyID},
	}
	for _, b := range m.Bundles {
		entry := SignedBundle{Path: b.Path, BundleID: b.BundleID}
		if plan, ok := plans[b.Path]; ok {
			entry.ProfileUUID, entry.ProfileSHA256, entry.EntitlementsSHA256 = plan.profile.UUID, plan.profile.SHA256, plan.plistSHA256
		}
		result.Bundles = append(result.Bundles, entry)
	}
	envelope, err := sealReceipt(result, e.options.PrivateKey)
	if err != nil {
		return nil, err
	}
	ipa, err := os.OpenFile(ipaPath, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, err
	}
	signed = true
	return &Signed{Receipt: envelope, Payload: result, IPA: ipa, IPASHA256: ipaSHA, IPASize: ipaSize, work: work}, nil
}

// policyTeam requires a policy entry for every app and app extension, all
// of one team, and returns that team.
func (e *Engine) policyTeam(m worker.SigningManifest) (string, error) {
	team := ""
	for _, b := range m.Bundles {
		if b.PackageType == "FMWK" {
			continue
		}
		app, ok := e.options.Policy.Apps[b.BundleID]
		if !ok {
			return "", refusal("bundle %s (%s) is not allowed by the signing policy", b.Path, b.BundleID)
		}
		if team != "" && app.TeamID != team {
			return "", refusal("bundles span teams %s and %s", team, app.TeamID)
		}
		team = app.TeamID
	}
	if team == "" {
		return "", refusal("signing manifest has no app")
	}
	return team, nil
}

// planBundle loads, decodes and validates b's admin profile from a private
// copy of its exact bytes, then builds and writes its entitlements plist.
func (e *Engine) planBundle(ctx context.Context, work string, b worker.SignableBundle, identity string, index int) (bundlePlan, error) {
	app := e.options.Policy.Apps[b.BundleID]
	if check := e.options.CheckProfileFile; check != nil {
		if err := check(app.ProfilePath); err != nil {
			return bundlePlan{}, fmt.Errorf("profile %s: %w", app.ProfilePath, err)
		}
	}
	raw, err := readInput(app.ProfilePath, maxProfileBytes)
	if err != nil {
		return bundlePlan{}, fmt.Errorf("profile %s: %w", app.ProfilePath, err)
	}
	copyPath := filepath.Join(work, "profiles", strconv.Itoa(index)+".mobileprovision")
	if err := os.WriteFile(copyPath, raw, 0o600); err != nil {
		return bundlePlan{}, err
	}
	decoded, err := e.options.Tools.DecodeProfile(ctx, copyPath)
	if err != nil {
		return bundlePlan{}, fmt.Errorf("decode profile %s: %w", app.ProfilePath, err)
	}
	profile, err := parseProfile(raw, decoded, b.BundleID, app.TeamID, identity, e.options.Now())
	if err != nil {
		return bundlePlan{}, refusal("%v", err)
	}
	entitlements, err := finalEntitlements(b.Entitlements, profile, app.RequiredEntitlements)
	if err != nil {
		return bundlePlan{}, refusal("%v", err)
	}
	plist, err := encodePlist(entitlements)
	if err != nil {
		return bundlePlan{}, refusal("entitlements for %s: %v", b.BundleID, err)
	}
	digest := sum(plist)
	if err := os.WriteFile(filepath.Join(work, "entitlements", digest+".plist"), plist, 0o600); err != nil && !errors.Is(err, fs.ErrExist) {
		return bundlePlan{}, err
	}
	return bundlePlan{profile: profile, entitlements: entitlements, plist: plist, plistSHA256: digest}, nil
}

// verifyIPA re-extracts the packaged ipa and checks every app and app
// extension embeds its exact profile and carries exactly its planned
// entitlements, and every node verifies strictly.
func (e *Engine) verifyIPA(ctx context.Context, work, ipaPath string, ipaSize int64, m worker.SigningManifest, rootApp string, plans map[string]bundlePlan) error {
	tools := e.options.Tools
	ipa, err := os.Open(ipaPath)
	if err != nil {
		return err
	}
	defer ipa.Close()
	verifyDir := filepath.Join(work, "verify")
	if err := os.Mkdir(verifyDir, 0o700); err != nil {
		return err
	}
	verify, err := os.OpenRoot(verifyDir)
	if err != nil {
		return err
	}
	defer verify.Close()
	app, err := extractIPA(ctx, ipa, ipaSize, verify)
	if err != nil {
		return err
	}
	if app != path.Join("Payload", path.Base(rootApp)) {
		return refusal("signed ipa app %s is not the archive's", app)
	}
	located := func(node string) string {
		return path.Join(app, strings.TrimPrefix(node, rootApp))
	}
	for _, node := range signingOrder(m) {
		if err := tools.Verify(ctx, filepath.Join(verifyDir, located(node.path))); err != nil {
			return fmt.Errorf("signed ipa: codesign --verify %s: %w", node.path, err)
		}
		plan, ok := plans[node.path]
		if !ok {
			continue
		}
		embedded, err := readRootFile(verify, path.Join(located(node.path), embeddedProfile), maxProfileBytes)
		if err != nil || !bytes.Equal(embedded, plan.profile.Raw) {
			return refusal("signed ipa: %s does not embed its verified profile", node.path)
		}
		raw, err := tools.Entitlements(ctx, filepath.Join(verifyDir, located(node.path)))
		if err != nil {
			return fmt.Errorf("signed ipa: entitlements of %s: %w", node.path, err)
		}
		signed, err := decodePlist(raw)
		if err != nil || !reflect.DeepEqual(signed, plan.entitlements) {
			return refusal("signed ipa: %s entitlements differ from the planned entitlements", node.path)
		}
	}
	return nil
}

func (e *Engine) workDir(jobID string) (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	base := filepath.Join(e.options.Config.StateDir, "work")
	if err := os.Mkdir(base, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	work := filepath.Join(base, jobID+"-"+hex.EncodeToString(random[:]))
	if err := os.Mkdir(work, 0o700); err != nil {
		return "", err
	}
	for _, sub := range []string{"profiles", "entitlements"} {
		if err := os.Mkdir(filepath.Join(work, sub), 0o700); err != nil {
			os.RemoveAll(work)
			return "", err
		}
	}
	return work, nil
}

// copyArchive copies the inbox archive, a regular file of exactly the
// manifest's size, into a private file while hashing it, requires the
// manifest's SHA-256, and returns the copy open at offset 0.
func copyArchive(ctx context.Context, source, target string, want worker.SealedArchive) (*os.File, error) {
	in, err := os.OpenFile(source, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, refusal("archive: %v", err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != want.SizeBytes {
		return nil, refusal("archive is not a regular file of the manifest's %d bytes", want.SizeBytes)
	}
	out, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	copied, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(&contextReader{ctx, in}, want.SizeBytes+1))
	if err == nil && (copied != want.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != want.SHA256) {
		err = refusal("archive SHA-256 or size differs from the signing manifest")
	}
	if err == nil {
		_, err = out.Seek(0, io.SeekStart)
	}
	if err != nil {
		out.Close()
		return nil, err
	}
	return out, nil
}

// refuseEmbeddedProfiles refuses an archive that already carries an
// embedded.mobileprovision anywhere.
func refuseEmbeddedProfiles(tree *os.Root, root string) error {
	return fs.WalkDir(tree.FS(), root, func(current string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.EqualFold(d.Name(), embeddedProfile) {
			return refusal("archive already contains %s", strconv.Quote(current))
		}
		return nil
	})
}

func writeNew(root *os.Root, name string, data []byte, mode fs.FileMode) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Chmod(mode)
	}
	return errors.Join(err, file.Close())
}

// readInput reads a regular file without following a final symlink.
func readInput(name string, max int64) ([]byte, error) {
	file, err := os.OpenFile(name, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readRegular(file, max)
}

func readRootFile(root *os.Root, name string, max int64) ([]byte, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readRegular(file, max)
}

func readRegular(file *os.File, max int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", file.Name(), max)
	}
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", file.Name(), max)
	}
	return data, nil
}

// packageIPA writes the deterministic ipa of app to target and returns its
// SHA-256 and size.
func packageIPA(ctx context.Context, tree *os.Root, app, target string) (string, int64, error) {
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	counter := &countingWriter{w: io.MultiWriter(out, hash)}
	err = writeIPA(ctx, tree, app, counter)
	if err == nil {
		err = out.Sync()
	}
	if err = errors.Join(err, out.Close()); err != nil {
		return "", 0, err
	}
	if counter.n > MaxIPABytes {
		return "", 0, refusal("signed ipa exceeds %d bytes", int64(MaxIPABytes))
	}
	return hex.EncodeToString(hash.Sum(nil)), counter.n, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func sum(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
