package workerclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
)

// Checks are the host checks of the lease authority files: RootConfig
// checks a root-owned protected configuration file and ReadPrivateKey reads
// a root-only key. Zero fields are the hostguard checks; only tests, which
// cannot create root-owned files, supply others.
type Checks struct {
	RootConfig     func(string) error
	ReadPrivateKey func(string) ([]byte, error)
}

func (c Checks) withDefaults() Checks {
	if c.RootConfig == nil {
		c.RootConfig = hostguard.RootConfig
	}
	if c.ReadPrivateKey == nil {
		c.ReadPrivateKey = hostguard.ReadPrivateKey
	}
	return c
}

// ErrLeaseRefused reports a lease the root registry does not admit.
var ErrLeaseRefused = errors.New("lease refused by the root profile registry")

// loadSealKey reads the root-only worker seal key.
func loadSealKey(checks Checks, path string) (ed25519.PrivateKey, error) {
	raw, err := checks.ReadPrivateKey(path)
	if err != nil {
		return nil, fmt.Errorf("worker seal key: %w", err)
	}
	key, err := receipt.ParsePrivateKey(raw)
	clear(raw)
	if err != nil {
		return nil, fmt.Errorf("worker seal key: %w", err)
	}
	return key, nil
}

// resolveLease re-admits a leased job against the root-owned registry,
// never the controller's snapshot: the profile or template the request
// names must resolve, from today's registry, to exactly the leased snapshot,
// request and digests, and the registry's profile set must equal the
// qualified one. This is the controller's own admission, so every job it
// admits from the same registry (template snapshots included) resolves
// identically; a replay returns the job its first admission stored.
func (c *Client) resolveLease(job model.Job) (*buildseal.Resolution, error) {
	if err := c.checks.RootConfig(c.config.ProfilesFile); err != nil {
		return nil, fmt.Errorf("%w: profiles: %v", ErrLeaseRefused, err)
	}
	registry, err := profiles.Load(c.config.ProfilesFile)
	if err != nil {
		return nil, fmt.Errorf("%w: profiles: %v", ErrLeaseRefused, err)
	}
	admission, err := registry.Resolve(job.Request)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLeaseRefused, err)
	}
	request, err := json.Marshal(admission.Request)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(request)
	if !reflect.DeepEqual(job.Profile, admission.Profile) || !reflect.DeepEqual(job.Request, admission.Request) || job.ProfileDigest != admission.ProfileDigest || job.RequestDigest != hex.EncodeToString(digest[:]) {
		return nil, fmt.Errorf("%w: leased profile, repository, request or digest differs", ErrLeaseRefused)
	}
	qualified, err := qualifiedProfiles(c.checks, c.config.QualificationFile)
	if err != nil {
		return nil, fmt.Errorf("%w: qualification: %v", ErrLeaseRefused, err)
	}
	if !maps.Equal(qualified, registry.Digests()) {
		return nil, fmt.Errorf("%w: qualified profile set differs from the registry", ErrLeaseRefused)
	}
	p := admission.Profile
	resolution := &buildseal.Resolution{ProfileID: p.ID, ProfileVersion: p.Version, ProfileDigest: admission.ProfileDigest, Xcode: p.Xcode, DeveloperDir: p.DeveloperDir}
	if p.Template != nil && p.Template.Flutter != nil {
		pin := *p.Template.Flutter
		resolution.Flutter = &pin
	}
	return resolution, nil
}

// qualifiedProfiles reads the profile digests the root-owned qualification
// record approved.
func qualifiedProfiles(checks Checks, path string) (map[string]string, error) {
	if err := checks.RootConfig(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("qualification record exceeds 1 MiB")
	}
	var record struct {
		Profiles map[string]string `json:"profiles"`
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&record); err != nil {
		return nil, err
	}
	if record.Profiles == nil {
		return nil, errors.New("qualification record has no profiles")
	}
	return record.Profiles, nil
}

// seal signs the build seal of a final result.
func (c *Client) seal(saved pending) (buildseal.Envelope, error) {
	s, err := buildseal.New(saved.Lease.Job, saved.Resolution, saved.SourceTree, saved.Result, time.Now())
	if err != nil {
		return buildseal.Envelope{}, err
	}
	return buildseal.Sign(c.sealKey, c.config.SealKeyID, s)
}
